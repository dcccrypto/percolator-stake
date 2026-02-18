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
/// * `Some(value)` if deposited >= withdrawn
/// * `None` if accounting is broken (withdrawn > deposited)
pub fn pool_value(total_deposited: u64, total_withdrawn: u64) -> Option<u64> {
    total_deposited.checked_sub(total_withdrawn)
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
        assert_eq!(calc_lp_for_deposit(1_000_000, 1_000_000, 500_000), Some(500_000));
    }

    #[test]
    fn test_withdraw_proportional() {
        assert_eq!(calc_collateral_for_withdraw(2_000_000, 2_000_000, 1_000_000), Some(1_000_000));
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
}

// ═══════════════════════════════════════════════════════════════
// Kani Formal Verification
// ═══════════════════════════════════════════════════════════════
//
// Production-type (u64/u128) proofs live in kani-proofs/ crate with
// u32/u64 mirrors for CBMC tractability. See kani-proofs/src/lib.rs.
//
// Keeping this note here so nobody adds u64 Kani proofs that timeout.
