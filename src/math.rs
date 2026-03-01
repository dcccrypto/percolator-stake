//! Pure LP math — extracted for Kani formal verification.
//!
//! No Solana/Pubkey dependencies. Just arithmetic.
//! Kani can verify these functions exhaustively.

/// Calculate LP tokens for a deposit.
///
/// # Arguments
/// * `total_lp_supply` - Current total LP tokens in circulation
/// * `total_pool_value` - Current total pool value (deposited - withdrawn)
/// * `deposit_amount` - Amount of collateral being deposited
///
/// # Returns
/// * `Some(lp_tokens)` - LP tokens to mint (rounds DOWN — pool-favoring)
/// * `None` - Arithmetic overflow
///
/// # Invariant
/// First depositor (supply == 0): gets 1:1 LP tokens.
/// Subsequent: `lp = amount * supply / pool_value` (pro-rata, rounded down).
pub fn calc_lp_for_deposit(
    total_lp_supply: u64,
    total_pool_value: u64,
    deposit_amount: u64,
) -> Option<u64> {
    if total_lp_supply == 0 && total_pool_value == 0 {
        // True first depositor — 1:1
        Some(deposit_amount)
    } else if total_lp_supply == 0 {
        // CRITICAL: LP supply is 0 but pool has orphaned value (e.g., returned insurance
        // after all LP holders withdrew). Allowing 1:1 deposits here would let the
        // depositor withdraw the entire orphaned value. Block deposits.
        None
    } else if total_pool_value == 0 {
        // LP tokens exist but pool value is 0 (fully flushed to insurance).
        // Existing holders have a claim on future insurance returns.
        // Allowing deposits would dilute that claim. Block deposits.
        None
    } else {
        // Pro-rata via u128 to prevent overflow
        let lp = (deposit_amount as u128)
            .checked_mul(total_lp_supply as u128)?
            .checked_div(total_pool_value as u128)?;
        if lp > u64::MAX as u128 {
            None
        } else {
            Some(lp as u64)
        }
    }
}

/// Calculate collateral for an LP token burn.
///
/// # Arguments
/// * `total_lp_supply` - Current total LP tokens
/// * `total_pool_value` - Current pool value
/// * `lp_amount` - LP tokens being burned
///
/// # Returns
/// * `Some(collateral)` - Collateral to return (rounds DOWN — pool-favoring)
/// * `None` - Division by zero or overflow
///
/// # Invariant
/// `collateral = lp_amount * pool_value / lp_supply` (rounded down).
/// Full burn returns ≤ pool_value (never more).
pub fn calc_collateral_for_withdraw(
    total_lp_supply: u64,
    total_pool_value: u64,
    lp_amount: u64,
) -> Option<u64> {
    if total_lp_supply == 0 {
        return None;
    }
    let collateral = (lp_amount as u128)
        .checked_mul(total_pool_value as u128)?
        .checked_div(total_lp_supply as u128)?;
    if collateral > u64::MAX as u128 {
        None
    } else {
        Some(collateral as u64)
    }
}

/// Calculate pool value from accounting state.
///
/// # Returns
/// * `Some(value)` if deposited + fees >= withdrawn
/// * `None` if accounting is broken (withdrawn > deposited + fees)
pub fn pool_value(total_deposited: u64, total_withdrawn: u64) -> Option<u64> {
    total_deposited.checked_sub(total_withdrawn)
}

/// Calculate pool value including accrued trading fees (PERC-272).
///
/// # Returns
/// * `Some(value)` if deposited + fees >= withdrawn
/// * `None` if accounting overflow or underflow
pub fn pool_value_with_fees(
    total_deposited: u64,
    total_withdrawn: u64,
    total_fees_earned: u64,
) -> Option<u64> {
    total_deposited
        .checked_sub(total_withdrawn)?
        .checked_add(total_fees_earned)
}

// ═══════════════════════════════════════════════════════════════
// PERC-303: Senior/Junior LP Tranche Math
// ═══════════════════════════════════════════════════════════════

/// Calculate LP tokens for a junior tranche deposit.
///
/// Junior tranche has its own sub-pool: junior_balance / junior_total_lp.
/// First junior depositor gets 1:1, subsequent get pro-rata within junior pool.
///
/// # Returns
/// * `Some(lp_tokens)` to mint
/// * `None` on overflow or blocked state (orphaned value)
pub fn calc_junior_lp_for_deposit(
    junior_total_lp: u64,
    junior_balance: u64,
    deposit_amount: u64,
) -> Option<u64> {
    calc_lp_for_deposit(junior_total_lp, junior_balance, deposit_amount)
}

/// Calculate collateral for a junior LP token burn.
///
/// Junior withdrawals are valued against the junior sub-pool only.
/// If junior_balance has been reduced by losses, junior LPs take the hit.
///
/// # Returns
/// * `Some(collateral)` to return (rounds down)
/// * `None` on overflow
pub fn calc_junior_collateral_for_withdraw(
    junior_total_lp: u64,
    junior_balance: u64,
    lp_amount: u64,
) -> Option<u64> {
    calc_collateral_for_withdraw(junior_total_lp, junior_balance, lp_amount)
}

/// Calculate collateral for a senior LP token burn.
///
/// Senior withdrawals are valued against the senior sub-pool only.
/// senior_balance = total_pool_value - junior_balance.
/// senior_total_lp = total_lp_supply - junior_total_lp.
///
/// Senior LPs only lose if junior_balance is fully wiped (== 0).
///
/// # Returns
/// * `Some(collateral)` to return (rounds down)
/// * `None` on overflow or zero senior supply
pub fn calc_senior_collateral_for_withdraw(
    senior_total_lp: u64,
    senior_balance: u64,
    lp_amount: u64,
) -> Option<u64> {
    calc_collateral_for_withdraw(senior_total_lp, senior_balance, lp_amount)
}

/// Distribute a loss across tranches. Junior absorbs first.
///
/// # Returns
/// (junior_loss, senior_loss)
/// Invariant: junior_loss + senior_loss == loss_amount (unless capped at total).
pub fn distribute_loss(
    junior_balance: u64,
    senior_balance: u64,
    loss_amount: u64,
) -> (u64, u64) {
    let total = junior_balance.saturating_add(senior_balance);
    let capped_loss = loss_amount.min(total);

    if capped_loss <= junior_balance {
        // Junior absorbs all
        (capped_loss, 0)
    } else {
        // Junior wiped, remainder hits senior
        let senior_loss = capped_loss.saturating_sub(junior_balance);
        (junior_balance, senior_loss)
    }
}

/// Distribute fee income across tranches using junior multiplier.
///
/// Junior gets: fee * (junior_share * junior_mult_bps / 10_000) / weighted_total
/// Senior gets: remainder
///
/// # Arguments
/// * `junior_balance` - Junior tranche balance
/// * `senior_balance` - Senior tranche balance
/// * `junior_fee_mult_bps` - Junior fee multiplier (20000 = 2x)
/// * `total_fee` - Total fee to distribute
///
/// # Returns
/// (junior_fee, senior_fee) — guaranteed to sum to <= total_fee
pub fn distribute_fees(
    junior_balance: u64,
    senior_balance: u64,
    junior_fee_mult_bps: u16,
    total_fee: u64,
) -> (u64, u64) {
    if total_fee == 0 {
        return (0, 0);
    }
    let total_balance = junior_balance as u128 + senior_balance as u128;
    if total_balance == 0 {
        return (0, 0);
    }

    // Weighted shares: junior weight = junior_balance * mult, senior weight = senior_balance * 10_000
    let junior_weight = (junior_balance as u128) * (junior_fee_mult_bps as u128);
    let senior_weight = (senior_balance as u128) * 10_000u128;
    let total_weight = junior_weight + senior_weight;

    if total_weight == 0 {
        return (0, 0);
    }

    let junior_fee = ((total_fee as u128) * junior_weight / total_weight) as u64;
    let senior_fee = total_fee.saturating_sub(junior_fee); // remainder to senior

    (junior_fee, senior_fee)
}

/// Check senior never loses while junior is positive.
///
/// Given initial senior balance and post-loss senior balance,
/// returns true if senior is protected (no loss while junior > 0).
pub fn senior_protected(
    junior_balance: u64,
    _senior_balance: u64,
    loss_amount: u64,
) -> bool {
    // If loss <= junior_balance, senior takes zero loss
    loss_amount <= junior_balance
}

/// Calculate available flush amount.
///
/// `available = deposited - withdrawn - already_flushed`
/// Uses saturating arithmetic (can't go negative).
pub fn flush_available(total_deposited: u64, total_withdrawn: u64, total_flushed: u64) -> u64 {
    total_deposited
        .saturating_sub(total_withdrawn)
        .saturating_sub(total_flushed)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Basic Behavior ──

    #[test]
    fn test_first_depositor() {
        assert_eq!(calc_lp_for_deposit(0, 0, 1_000_000), Some(1_000_000));
    }

    #[test]
    fn test_pro_rata() {
        assert_eq!(
            calc_lp_for_deposit(1_000_000, 1_000_000, 500_000),
            Some(500_000)
        );
    }

    #[test]
    fn test_withdraw_proportional() {
        assert_eq!(
            calc_collateral_for_withdraw(2_000_000, 2_000_000, 1_000_000),
            Some(1_000_000)
        );
    }

    #[test]
    fn test_rounding_down() {
        assert_eq!(calc_lp_for_deposit(999_999, 1_000_000, 1), Some(0));
    }

    #[test]
    fn test_zero_supply_withdraw_none() {
        assert_eq!(calc_collateral_for_withdraw(0, 100, 10), None);
    }

    // ── Conservation ──

    #[test]
    fn test_roundtrip_no_profit() {
        // Deposit 1000 into pool with 5000 supply / 10000 value
        let lp = calc_lp_for_deposit(5_000, 10_000, 1_000).unwrap();
        assert_eq!(lp, 500); // 1000 * 5000 / 10000

        // Withdraw those LP tokens from updated pool
        let back = calc_collateral_for_withdraw(5_500, 11_000, 500).unwrap();
        assert_eq!(back, 1_000); // exact roundtrip at 2:1 ratio
    }

    #[test]
    fn test_roundtrip_with_rounding_loss() {
        // Deposit 7 into pool with 3 supply / 10 value → lp = 7*3/10 = 2
        let lp = calc_lp_for_deposit(3, 10, 7).unwrap();
        assert_eq!(lp, 2);

        // Withdraw 2 LP from pool (5 supply, 17 value) → col = 2*17/5 = 6
        let back = calc_collateral_for_withdraw(5, 17, 2).unwrap();
        assert_eq!(back, 6);
        assert!(back <= 7); // Can't profit
    }

    #[test]
    fn test_two_depositors_conservation() {
        // A deposits 100 (first depositor, 1:1)
        let a_lp = calc_lp_for_deposit(0, 0, 100).unwrap();
        assert_eq!(a_lp, 100);

        // B deposits 50
        let b_lp = calc_lp_for_deposit(100, 100, 50).unwrap();
        assert_eq!(b_lp, 50);

        // A withdraws
        let a_back = calc_collateral_for_withdraw(150, 150, 100).unwrap();
        assert_eq!(a_back, 100);

        // B withdraws from remaining
        let b_back = calc_collateral_for_withdraw(50, 50, 50).unwrap();
        assert_eq!(b_back, 50);

        assert!(a_back + b_back <= 100 + 50);
    }

    // ── Dilution Protection ──

    #[test]
    fn test_no_dilution_attack() {
        // A deposits 1000 (1:1)
        let a_lp = calc_lp_for_deposit(0, 0, 1000).unwrap();

        // A's value before B
        let a_value_before = calc_collateral_for_withdraw(a_lp, 1000, a_lp).unwrap();
        assert_eq!(a_value_before, 1000);

        // B deposits 1 (tiny amount)
        let b_lp = calc_lp_for_deposit(1000, 1000, 1).unwrap();
        assert_eq!(b_lp, 1); // floor(1*1000/1000) = 1

        // A's value after B deposits
        let a_value_after = calc_collateral_for_withdraw(1001, 1001, 1000).unwrap();
        assert!(a_value_after >= a_value_before); // A not diluted
    }

    // ── Edge Cases ──

    #[test]
    fn test_zero_deposit_zero_lp() {
        assert_eq!(calc_lp_for_deposit(100, 200, 0), Some(0));
    }

    #[test]
    fn test_zero_burn_zero_col() {
        assert_eq!(calc_collateral_for_withdraw(100, 200, 0), Some(0));
    }

    #[test]
    fn test_deposit_into_zero_value_pool_blocked() {
        // Supply > 0 but value = 0 → blocked (C9 fix: protects existing holders'
        // claim on future insurance returns from dilution)
        assert_eq!(calc_lp_for_deposit(100, 0, 50), None);
    }

    #[test]
    fn test_deposit_orphaned_value_blocked() {
        // Supply = 0 but value > 0 → blocked (C9 fix: prevents theft of
        // orphaned insurance returns by first new depositor)
        assert_eq!(calc_lp_for_deposit(0, 500, 1), None);
    }

    #[test]
    fn test_large_values_no_overflow() {
        let max = u64::MAX / 2;
        // Should handle via u128 intermediates
        assert!(calc_lp_for_deposit(max, max, max).is_some());
        assert!(calc_collateral_for_withdraw(max, max, max).is_some());
    }

    #[test]
    fn test_u64_max_deposit() {
        // All three are u64::MAX → pro-rata path (supply > 0, value > 0)
        // u64::MAX as u128 * u64::MAX as u128 = (2^64-1)^2 = 2^128 - 2^65 + 1
        // u128::MAX = 2^128 - 1, so it fits. Result = u64::MAX.
        let result = calc_lp_for_deposit(u64::MAX, u64::MAX, u64::MAX);
        assert_eq!(result, Some(u64::MAX));
    }

    // ── Pool Value ──

    #[test]
    fn test_pool_value_normal() {
        assert_eq!(pool_value(1000, 300), Some(700));
    }

    #[test]
    fn test_pool_value_overdrawn() {
        assert_eq!(pool_value(100, 200), None);
    }

    #[test]
    fn test_pool_value_exact() {
        assert_eq!(pool_value(100, 100), Some(0));
    }

    // ── Flush ──

    #[test]
    fn test_flush_available_normal() {
        assert_eq!(flush_available(1000, 200, 300), 500);
    }

    #[test]
    fn test_flush_available_overdrawn() {
        // withdrawn > deposited → saturates to 0
        assert_eq!(flush_available(100, 200, 0), 0);
    }

    #[test]
    fn test_flush_available_fully_flushed() {
        assert_eq!(flush_available(1000, 200, 800), 0);
    }

    #[test]
    fn test_flush_available_over_flushed() {
        // More flushed than available → saturates to 0
        assert_eq!(flush_available(1000, 200, 900), 0);
    }

    // ── Rounding Direction ──

    #[test]
    fn test_lp_rounds_down_not_up() {
        // deposit=7, supply=3, pool_value=10 → 7*3/10 = 2.1 → should be 2
        let lp = calc_lp_for_deposit(3, 10, 7).unwrap();
        assert_eq!(lp, 2);
        // Verify: lp * pv <= dep * supply (pool-favoring)
        assert!((lp as u128) * 10 <= (7u128) * 3);
    }

    #[test]
    fn test_withdrawal_rounds_down_not_up() {
        // lp=3, supply=7, pool_value=10 → 3*10/7 = 4.28 → should be 4
        let col = calc_collateral_for_withdraw(7, 10, 3).unwrap();
        assert_eq!(col, 4);
        // Verify: col * supply <= lp * pv (pool-favoring)
        assert!((col as u128) * 7 <= (3u128) * 10);
    }

    // ── C9 Attack Scenarios ──

    #[test]
    fn test_c9_orphaned_insurance_theft_blocked() {
        // Scenario: All LP holders withdrew, then insurance returned to vault.
        // pool_value > 0, LP_supply = 0. Attacker deposits 1 token.
        // OLD behavior: attacker gets 1 LP (1:1), then withdraws entire pool_value.
        // NEW behavior: None — deposits blocked when orphaned value exists.
        assert_eq!(calc_lp_for_deposit(0, 10_000_000, 1), None);
    }

    #[test]
    fn test_c9_dilution_attack_blocked() {
        // Scenario: Pool fully flushed (value=0), LP holders still have tokens.
        // New depositor at 1:1 would dilute existing holders' insurance claims.
        // Blocked: pool_value == 0 with supply > 0.
        assert_eq!(calc_lp_for_deposit(1000, 0, 500), None);
    }

    #[test]
    fn test_c9_true_first_depositor_works() {
        // True first deposit: both supply and value are 0. 1:1 ratio.
        assert_eq!(calc_lp_for_deposit(0, 0, 1000), Some(1000));
    }

    #[test]
    fn test_c9_normal_pro_rata_unaffected() {
        // Normal state: supply > 0, value > 0. Pro-rata works as before.
        assert_eq!(calc_lp_for_deposit(1000, 2000, 500), Some(250));
    }

    // ── Monotonicity ──

    #[test]
    fn test_larger_deposit_more_lp() {
        let small = calc_lp_for_deposit(100, 200, 10).unwrap();
        let large = calc_lp_for_deposit(100, 200, 20).unwrap();
        assert!(large >= small);
    }

    #[test]
    fn test_larger_burn_more_collateral() {
        let small = calc_collateral_for_withdraw(100, 200, 10).unwrap();
        let large = calc_collateral_for_withdraw(100, 200, 20).unwrap();
        assert!(large >= small);
    }

    // ── PERC-272: Fee-inclusive Pool Value ──

    #[test]
    fn test_pool_value_with_fees() {
        assert_eq!(pool_value_with_fees(1000, 200, 100), Some(900));
    }

    #[test]
    fn test_pool_value_with_fees_zero() {
        assert_eq!(pool_value_with_fees(1000, 1000, 0), Some(0));
    }

    #[test]
    fn test_pool_value_with_fees_overflow() {
        assert_eq!(pool_value_with_fees(100, 200, 50), None);
    }

    // ── PERC-303: Tranche Tests ──

    #[test]
    fn test_junior_first_deposit_1_to_1() {
        assert_eq!(calc_junior_lp_for_deposit(0, 0, 1000), Some(1000));
    }

    #[test]
    fn test_junior_pro_rata() {
        assert_eq!(calc_junior_lp_for_deposit(1000, 2000, 500), Some(250));
    }

    #[test]
    fn test_junior_withdraw_proportional() {
        assert_eq!(calc_junior_collateral_for_withdraw(1000, 2000, 500), Some(1000));
    }

    #[test]
    fn test_junior_withdraw_after_loss() {
        // Junior balance reduced from 1000 to 500 by losses
        // 1000 LP tokens, 500 balance → each LP worth 0.5
        assert_eq!(calc_junior_collateral_for_withdraw(1000, 500, 1000), Some(500));
    }

    #[test]
    fn test_senior_withdraw_full_protection() {
        // Senior balance untouched (1000), junior absorbed all losses
        assert_eq!(calc_senior_collateral_for_withdraw(500, 1000, 500), Some(1000));
    }

    #[test]
    fn test_distribute_loss_junior_absorbs_all() {
        let (j, s) = distribute_loss(1000, 5000, 800);
        assert_eq!(j, 800);
        assert_eq!(s, 0);
    }

    #[test]
    fn test_distribute_loss_junior_wiped() {
        let (j, s) = distribute_loss(1000, 5000, 1500);
        assert_eq!(j, 1000);
        assert_eq!(s, 500);
    }

    #[test]
    fn test_distribute_loss_total_wipe() {
        let (j, s) = distribute_loss(1000, 5000, 10000);
        assert_eq!(j, 1000);
        assert_eq!(s, 5000);
    }

    #[test]
    fn test_distribute_loss_zero() {
        let (j, s) = distribute_loss(1000, 5000, 0);
        assert_eq!(j, 0);
        assert_eq!(s, 0);
    }

    #[test]
    fn test_distribute_fees_2x_multiplier() {
        // Junior: 1000 balance, 2x mult → weight = 1000 * 20000 = 20_000_000
        // Senior: 4000 balance, 1x base → weight = 4000 * 10000 = 40_000_000
        // Total weight = 60_000_000
        // Fee = 600 → junior gets 600 * 20M/60M = 200, senior gets 400
        let (jf, sf) = distribute_fees(1000, 4000, 20000, 600);
        assert_eq!(jf, 200);
        assert_eq!(sf, 400);
    }

    #[test]
    fn test_distribute_fees_no_junior() {
        let (jf, sf) = distribute_fees(0, 5000, 20000, 1000);
        assert_eq!(jf, 0);
        assert_eq!(sf, 1000);
    }

    #[test]
    fn test_distribute_fees_no_senior() {
        let (jf, sf) = distribute_fees(5000, 0, 20000, 1000);
        assert_eq!(jf, 1000);
        assert_eq!(sf, 0);
    }

    #[test]
    fn test_distribute_fees_zero_fee() {
        let (jf, sf) = distribute_fees(1000, 4000, 20000, 0);
        assert_eq!(jf, 0);
        assert_eq!(sf, 0);
    }

    #[test]
    fn test_senior_protected_when_junior_covers() {
        assert!(senior_protected(1000, 5000, 800));
    }

    #[test]
    fn test_senior_not_protected_when_loss_exceeds_junior() {
        assert!(!senior_protected(1000, 5000, 1500));
    }

    #[test]
    fn test_fee_appreciation_increases_share_price() {
        let lp_before = calc_collateral_for_withdraw(1000, 1000, 100).unwrap();
        assert_eq!(lp_before, 100);
        let lp_after = calc_collateral_for_withdraw(1000, 1200, 100).unwrap();
        assert_eq!(lp_after, 120);
    }
}

// ═══════════════════════════════════════════════════════════════
// Kani Formal Verification
// ═══════════════════════════════════════════════════════════════
//
// Production-type (u64/u128) proofs live in kani-proofs/ crate with
// u32/u64 mirrors for CBMC tractability. See kani-proofs/src/lib.rs.
//
// Keeping this note here so nobody adds u64 Kani proofs that timeout.

// (PERC-272 tests moved to mod tests above)
