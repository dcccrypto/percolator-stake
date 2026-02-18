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
    if total_lp_supply == 0 || total_pool_value == 0 {
        // First depositor — 1:1
        Some(deposit_amount)
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
}

// ═══════════════════════════════════════════════════════════════
// Kani Formal Verification Proofs
// ═══════════════════════════════════════════════════════════════
//
// Proves: conservation, arithmetic safety, monotonicity, bounds.
// Run all:  cargo kani --function proof_
// Run one:  cargo kani --harness proof_first_depositor_exact

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // ── 1. Conservation ──

    /// Deposit then withdraw returns ≤ deposited (no inflation).
    #[kani::proof]
    fn proof_deposit_withdraw_no_inflation() {
        let supply: u64 = kani::any();
        let pv: u64 = kani::any();
        let deposit: u64 = kani::any();

        kani::assume(deposit > 0 && supply > 0 && pv > 0);
        kani::assume(deposit <= 1_000_000_000);
        kani::assume(supply <= 1_000_000_000);
        kani::assume(pv <= 1_000_000_000);

        let lp = match calc_lp_for_deposit(supply, pv, deposit) {
            Some(lp) if lp > 0 => lp,
            _ => return,
        };

        let new_supply = match supply.checked_add(lp) {
            Some(v) => v, None => return,
        };
        let new_pv = match pv.checked_add(deposit) {
            Some(v) => v, None => return,
        };

        let back = match calc_collateral_for_withdraw(new_supply, new_pv, lp) {
            Some(v) => v, None => return,
        };

        assert!(back <= deposit);
    }

    /// First depositor: exact 1:1 roundtrip.
    #[kani::proof]
    fn proof_first_depositor_exact() {
        let amount: u64 = kani::any();
        kani::assume(amount > 0);

        let lp = calc_lp_for_deposit(0, 0, amount).unwrap();
        assert_eq!(lp, amount);

        let back = calc_collateral_for_withdraw(lp, amount, lp).unwrap();
        assert_eq!(back, amount);
    }

    /// Two depositors, both withdraw → total_out ≤ total_in.
    #[kani::proof]
    fn proof_two_depositors_conservation() {
        let a: u64 = kani::any();
        let b: u64 = kani::any();
        kani::assume(a > 0 && a <= 100_000_000);
        kani::assume(b > 0 && b <= 100_000_000);

        let a_lp = calc_lp_for_deposit(0, 0, a).unwrap();
        let b_lp = match calc_lp_for_deposit(a_lp, a, b) {
            Some(lp) if lp > 0 => lp, _ => return,
        };
        let s2 = a_lp + b_lp;
        let pv2 = a + b;

        let a_back = match calc_collateral_for_withdraw(s2, pv2, a_lp) {
            Some(v) => v, None => return,
        };
        let b_back = match calc_collateral_for_withdraw(s2 - a_lp, pv2 - a_back, b_lp) {
            Some(v) => v, None => return,
        };

        assert!(a_back + b_back <= a + b);
    }

    // ── 2. Arithmetic Safety ──

    /// calc_lp_for_deposit never panics.
    #[kani::proof]
    fn proof_lp_deposit_no_panic() {
        let s: u64 = kani::any();
        let pv: u64 = kani::any();
        let a: u64 = kani::any();
        let _ = calc_lp_for_deposit(s, pv, a);
    }

    /// calc_collateral_for_withdraw never panics.
    #[kani::proof]
    fn proof_collateral_withdraw_no_panic() {
        let s: u64 = kani::any();
        let pv: u64 = kani::any();
        let lp: u64 = kani::any();
        let _ = calc_collateral_for_withdraw(s, pv, lp);
    }

    /// pool_value never panics.
    #[kani::proof]
    fn proof_pool_value_no_panic() {
        let d: u64 = kani::any();
        let w: u64 = kani::any();
        let _ = pool_value(d, w);
    }

    /// flush_available never panics.
    #[kani::proof]
    fn proof_flush_available_no_panic() {
        let d: u64 = kani::any();
        let w: u64 = kani::any();
        let f: u64 = kani::any();
        let _ = flush_available(d, w, f);
    }

    // ── 3. Fairness / Monotonicity ──

    /// Equal deposits → equal LP (deterministic).
    #[kani::proof]
    fn proof_equal_deposits_equal_lp() {
        let s: u64 = kani::any();
        let pv: u64 = kani::any();
        let a: u64 = kani::any();
        assert_eq!(calc_lp_for_deposit(s, pv, a), calc_lp_for_deposit(s, pv, a));
    }

    /// Larger deposit → ≥ LP (monotone).
    #[kani::proof]
    fn proof_larger_deposit_more_lp() {
        let s: u64 = kani::any();
        let pv: u64 = kani::any();
        let sm: u64 = kani::any();
        let lg: u64 = kani::any();

        kani::assume(s > 0 && pv > 0 && sm > 0 && lg > sm && lg <= 1_000_000_000);

        match (calc_lp_for_deposit(s, pv, sm), calc_lp_for_deposit(s, pv, lg)) {
            (Some(ls), Some(ll)) => assert!(ll >= ls),
            _ => {}
        }
    }

    /// Larger LP burn → ≥ collateral (monotone).
    #[kani::proof]
    fn proof_larger_burn_more_collateral() {
        let s: u64 = kani::any();
        let pv: u64 = kani::any();
        let sm: u64 = kani::any();
        let lg: u64 = kani::any();

        kani::assume(s > 0 && pv > 0 && sm > 0 && lg > sm && lg <= s);

        match (calc_collateral_for_withdraw(s, pv, sm), calc_collateral_for_withdraw(s, pv, lg)) {
            (Some(cs), Some(cl)) => assert!(cl >= cs),
            _ => {}
        }
    }

    // ── 4. Bounds ──

    /// Full LP burn ≤ pool value.
    #[kani::proof]
    fn proof_full_burn_bounded() {
        let s: u64 = kani::any();
        let pv: u64 = kani::any();
        kani::assume(s > 0);

        if let Some(col) = calc_collateral_for_withdraw(s, pv, s) {
            assert!(col <= pv);
        }
    }

    /// flush_available ≤ deposited.
    #[kani::proof]
    fn proof_flush_bounded() {
        let d: u64 = kani::any();
        let w: u64 = kani::any();
        let f: u64 = kani::any();
        assert!(flush_available(d, w, f) <= d);
    }

    /// After max flush → available = 0.
    #[kani::proof]
    fn proof_flush_max_then_zero() {
        let d: u64 = kani::any();
        let w: u64 = kani::any();
        let f: u64 = kani::any();
        kani::assume(w <= d);
        kani::assume(f <= d.saturating_sub(w));

        let avail = flush_available(d, w, f);
        assert_eq!(flush_available(d, w, f + avail), 0);
    }

    /// pool_value: None iff withdrawn > deposited.
    #[kani::proof]
    fn proof_pool_value_correctness() {
        let d: u64 = kani::any();
        let w: u64 = kani::any();
        let r = pool_value(d, w);
        if w > d { assert!(r.is_none()); }
        else { assert_eq!(r, Some(d - w)); }
    }

    // ── 5. Rounding Direction ──

    /// LP minting rounds DOWN: lp * pv ≤ deposit * supply.
    #[kani::proof]
    fn proof_lp_rounds_down() {
        let s: u64 = kani::any();
        let pv: u64 = kani::any();
        let dep: u64 = kani::any();

        kani::assume(s > 0 && pv > 0 && dep > 0);
        kani::assume(s <= 1_000_000_000 && pv <= 1_000_000_000 && dep <= 1_000_000_000);

        if let Some(lp) = calc_lp_for_deposit(s, pv, dep) {
            assert!((lp as u128) * (pv as u128) <= (dep as u128) * (s as u128));
        }
    }

    /// Withdrawal rounds DOWN: col * supply ≤ lp * pv.
    #[kani::proof]
    fn proof_withdrawal_rounds_down() {
        let s: u64 = kani::any();
        let pv: u64 = kani::any();
        let lp: u64 = kani::any();

        kani::assume(s > 0 && pv > 0 && lp > 0 && lp <= s);
        kani::assume(s <= 1_000_000_000 && pv <= 1_000_000_000);

        if let Some(col) = calc_collateral_for_withdraw(s, pv, lp) {
            assert!((col as u128) * (s as u128) <= (lp as u128) * (pv as u128));
        }
    }
}
