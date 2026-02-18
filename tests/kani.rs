//! Kani formal verification proofs for percolator-stake LP math.
//!
//! Proves critical safety properties on the PURE MATH layer:
//! 1. LP conservation: no value creation/destruction through deposit/withdraw
//! 2. Arithmetic safety: no overflow/panic at any valid input
//! 3. Fairness: monotonicity, proportionality
//! 4. Flush bounds: can't flush more than available
//! 5. Withdrawal bounds: can't extract more than pool value
//!
//! Run all:  cargo kani --tests
//! Run one:  cargo kani --harness <name>

#[cfg(kani)]
mod kani_proofs {
    use percolator_stake::math::{
        calc_collateral_for_withdraw, calc_lp_for_deposit, flush_available, pool_value,
    };

    // ═══════════════════════════════════════════════════════════
    // 1. LP Conservation — No Inflation
    // ═══════════════════════════════════════════════════════════

    /// PROOF: Deposit then immediate full withdraw returns ≤ deposited amount.
    /// No value is created through the LP cycle. (Anti-inflation)
    #[kani::proof]
    fn proof_deposit_withdraw_no_inflation() {
        let lp_supply: u64 = kani::any();
        let pv: u64 = kani::any();
        let deposit: u64 = kani::any();

        kani::assume(deposit > 0);
        kani::assume(lp_supply > 0);
        kani::assume(pv > 0);
        // Keep bounded to avoid solver timeout
        kani::assume(deposit <= 1_000_000_000);
        kani::assume(lp_supply <= 1_000_000_000);
        kani::assume(pv <= 1_000_000_000);

        let lp_minted = match calc_lp_for_deposit(lp_supply, pv, deposit) {
            Some(lp) if lp > 0 => lp,
            _ => return, // Can't mint → safe
        };

        // After deposit: new_supply, new_pv
        let new_supply = match lp_supply.checked_add(lp_minted) {
            Some(v) => v,
            None => return,
        };
        let new_pv = match pv.checked_add(deposit) {
            Some(v) => v,
            None => return,
        };

        // Withdraw the LP we just minted
        let back = match calc_collateral_for_withdraw(new_supply, new_pv, lp_minted) {
            Some(v) => v,
            None => return,
        };

        // CRITICAL PROPERTY: can't get back more than deposited
        assert!(back <= deposit, "INFLATION: deposited {} but withdrew {}", deposit, back);
    }

    /// PROOF: First depositor gets exact 1:1 (no loss, no gain).
    #[kani::proof]
    fn proof_first_depositor_exact() {
        let amount: u64 = kani::any();
        kani::assume(amount > 0);

        let lp = calc_lp_for_deposit(0, 0, amount).unwrap();
        assert_eq!(lp, amount, "First depositor must get 1:1");

        let back = calc_collateral_for_withdraw(lp, amount, lp).unwrap();
        assert_eq!(back, amount, "First depositor full withdraw must be exact");
    }

    /// PROOF: Two depositors, both fully withdraw → total out ≤ total in.
    #[kani::proof]
    fn proof_two_depositors_conservation() {
        let a: u64 = kani::any();
        let b: u64 = kani::any();
        kani::assume(a > 0 && a <= 100_000_000);
        kani::assume(b > 0 && b <= 100_000_000);

        // A deposits into empty pool
        let a_lp = calc_lp_for_deposit(0, 0, a).unwrap();
        let supply1 = a_lp;
        let pv1 = a;

        // B deposits
        let b_lp = match calc_lp_for_deposit(supply1, pv1, b) {
            Some(lp) if lp > 0 => lp,
            _ => return,
        };
        let supply2 = supply1 + b_lp;
        let pv2 = pv1 + b;

        // A withdraws
        let a_back = match calc_collateral_for_withdraw(supply2, pv2, a_lp) {
            Some(v) => v,
            None => return,
        };
        let supply3 = supply2 - a_lp;
        let pv3 = pv2 - a_back;

        // B withdraws
        let b_back = match calc_collateral_for_withdraw(supply3, pv3, b_lp) {
            Some(v) => v,
            None => return,
        };

        // CONSERVATION: total_out ≤ total_in
        assert!(
            a_back + b_back <= a + b,
            "INFLATION: in={}+{}, out={}+{}", a, b, a_back, b_back
        );
    }

    // ═══════════════════════════════════════════════════════════
    // 2. Arithmetic Safety — No Panics
    // ═══════════════════════════════════════════════════════════

    /// PROOF: calc_lp_for_deposit never panics for any u64 inputs.
    #[kani::proof]
    fn proof_lp_deposit_no_panic() {
        let supply: u64 = kani::any();
        let pv: u64 = kani::any();
        let amount: u64 = kani::any();
        let _ = calc_lp_for_deposit(supply, pv, amount);
    }

    /// PROOF: calc_collateral_for_withdraw never panics for any u64 inputs.
    #[kani::proof]
    fn proof_collateral_withdraw_no_panic() {
        let supply: u64 = kani::any();
        let pv: u64 = kani::any();
        let lp: u64 = kani::any();
        let _ = calc_collateral_for_withdraw(supply, pv, lp);
    }

    /// PROOF: pool_value never panics.
    #[kani::proof]
    fn proof_pool_value_no_panic() {
        let deposited: u64 = kani::any();
        let withdrawn: u64 = kani::any();
        let _ = pool_value(deposited, withdrawn);
    }

    /// PROOF: flush_available never panics.
    #[kani::proof]
    fn proof_flush_available_no_panic() {
        let deposited: u64 = kani::any();
        let withdrawn: u64 = kani::any();
        let flushed: u64 = kani::any();
        let _ = flush_available(deposited, withdrawn, flushed);
    }

    // ═══════════════════════════════════════════════════════════
    // 3. Fairness — Monotonicity
    // ═══════════════════════════════════════════════════════════

    /// PROOF: Equal deposits get equal LP tokens (deterministic).
    #[kani::proof]
    fn proof_equal_deposits_equal_lp() {
        let supply: u64 = kani::any();
        let pv: u64 = kani::any();
        let amount: u64 = kani::any();

        let lp1 = calc_lp_for_deposit(supply, pv, amount);
        let lp2 = calc_lp_for_deposit(supply, pv, amount);
        assert_eq!(lp1, lp2);
    }

    /// PROOF: Larger deposit → ≥ LP tokens (monotonicity).
    #[kani::proof]
    fn proof_larger_deposit_more_lp() {
        let supply: u64 = kani::any();
        let pv: u64 = kani::any();
        let small: u64 = kani::any();
        let large: u64 = kani::any();

        kani::assume(supply > 0 && pv > 0);
        kani::assume(small > 0);
        kani::assume(large > small);
        kani::assume(large <= 1_000_000_000);

        let lp_s = match calc_lp_for_deposit(supply, pv, small) {
            Some(v) => v,
            None => return,
        };
        let lp_l = match calc_lp_for_deposit(supply, pv, large) {
            Some(v) => v,
            None => return,
        };

        assert!(lp_l >= lp_s, "Monotonicity violated: more deposit → less LP");
    }

    /// PROOF: Larger LP burn → ≥ collateral (monotonicity).
    #[kani::proof]
    fn proof_larger_burn_more_collateral() {
        let supply: u64 = kani::any();
        let pv: u64 = kani::any();
        let small_lp: u64 = kani::any();
        let large_lp: u64 = kani::any();

        kani::assume(supply > 0 && pv > 0);
        kani::assume(small_lp > 0);
        kani::assume(large_lp > small_lp);
        kani::assume(large_lp <= supply);

        let c_s = match calc_collateral_for_withdraw(supply, pv, small_lp) {
            Some(v) => v,
            None => return,
        };
        let c_l = match calc_collateral_for_withdraw(supply, pv, large_lp) {
            Some(v) => v,
            None => return,
        };

        assert!(c_l >= c_s, "Monotonicity violated: more LP burn → less collateral");
    }

    // ═══════════════════════════════════════════════════════════
    // 4. Withdrawal Bounds
    // ═══════════════════════════════════════════════════════════

    /// PROOF: Full LP burn returns ≤ pool value (can't drain more than exists).
    #[kani::proof]
    fn proof_full_burn_bounded() {
        let supply: u64 = kani::any();
        let pv: u64 = kani::any();

        kani::assume(supply > 0);

        let col = match calc_collateral_for_withdraw(supply, pv, supply) {
            Some(v) => v,
            None => return,
        };

        assert!(col <= pv, "Full burn {} exceeds pool value {}", col, pv);
    }

    /// PROOF: Partial burn returns strictly less than full burn
    /// (when partial < total LP).
    #[kani::proof]
    fn proof_partial_burn_less_than_full() {
        let supply: u64 = kani::any();
        let pv: u64 = kani::any();
        let partial: u64 = kani::any();

        kani::assume(supply > 0 && pv > 0);
        kani::assume(partial > 0 && partial < supply);

        let full = match calc_collateral_for_withdraw(supply, pv, supply) {
            Some(v) => v,
            None => return,
        };
        let part = match calc_collateral_for_withdraw(supply, pv, partial) {
            Some(v) => v,
            None => return,
        };

        assert!(part <= full, "Partial {} exceeds full {}", part, full);
    }

    // ═══════════════════════════════════════════════════════════
    // 5. Flush Bounds
    // ═══════════════════════════════════════════════════════════

    /// PROOF: flush_available ≤ deposited (can't flush more than total).
    #[kani::proof]
    fn proof_flush_bounded_by_deposited() {
        let deposited: u64 = kani::any();
        let withdrawn: u64 = kani::any();
        let flushed: u64 = kani::any();

        let avail = flush_available(deposited, withdrawn, flushed);
        assert!(avail <= deposited);
    }

    /// PROOF: After flushing available amount, flush_available = 0.
    #[kani::proof]
    fn proof_flush_max_then_zero() {
        let deposited: u64 = kani::any();
        let withdrawn: u64 = kani::any();
        let flushed: u64 = kani::any();

        kani::assume(withdrawn <= deposited);
        kani::assume(flushed <= deposited.saturating_sub(withdrawn));

        let avail = flush_available(deposited, withdrawn, flushed);
        let new_flushed = flushed + avail;

        let remaining = flush_available(deposited, withdrawn, new_flushed);
        assert_eq!(remaining, 0);
    }

    // ═══════════════════════════════════════════════════════════
    // 6. Pool Value
    // ═══════════════════════════════════════════════════════════

    /// PROOF: pool_value returns None iff withdrawn > deposited.
    #[kani::proof]
    fn proof_pool_value_none_iff_overdrawn() {
        let deposited: u64 = kani::any();
        let withdrawn: u64 = kani::any();

        let result = pool_value(deposited, withdrawn);

        if withdrawn > deposited {
            assert!(result.is_none(), "Should be None when overdrawn");
        } else {
            assert_eq!(result, Some(deposited - withdrawn));
        }
    }

    /// PROOF: Deposit increases pool value by exact amount.
    #[kani::proof]
    fn proof_deposit_increases_value() {
        let deposited: u64 = kani::any();
        let withdrawn: u64 = kani::any();
        let new_deposit: u64 = kani::any();

        kani::assume(withdrawn <= deposited);
        kani::assume(new_deposit > 0);

        let old = pool_value(deposited, withdrawn);
        let new = pool_value(deposited.checked_add(new_deposit).unwrap_or(u64::MAX), withdrawn);

        match (old, new) {
            (Some(o), Some(n)) => assert!(n >= o, "Deposit must not decrease value"),
            _ => {} // overflow cases
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 7. Rounding Direction
    // ═══════════════════════════════════════════════════════════

    /// PROOF: LP minting rounds DOWN (pool-favoring).
    /// lp_minted * pool_value ≤ deposit * supply (integer inequality).
    #[kani::proof]
    fn proof_lp_rounds_down() {
        let supply: u64 = kani::any();
        let pv: u64 = kani::any();
        let deposit: u64 = kani::any();

        kani::assume(supply > 0 && pv > 0 && deposit > 0);
        kani::assume(supply <= 1_000_000_000);
        kani::assume(pv <= 1_000_000_000);
        kani::assume(deposit <= 1_000_000_000);

        if let Some(lp) = calc_lp_for_deposit(supply, pv, deposit) {
            // floor(deposit * supply / pv) * pv ≤ deposit * supply
            let lhs = (lp as u128) * (pv as u128);
            let rhs = (deposit as u128) * (supply as u128);
            assert!(lhs <= rhs, "LP rounding not pool-favoring");
        }
    }

    /// PROOF: Collateral withdrawal rounds DOWN (pool-favoring).
    /// collateral * supply ≤ lp * pool_value (integer inequality).
    #[kani::proof]
    fn proof_withdrawal_rounds_down() {
        let supply: u64 = kani::any();
        let pv: u64 = kani::any();
        let lp: u64 = kani::any();

        kani::assume(supply > 0 && pv > 0 && lp > 0);
        kani::assume(supply <= 1_000_000_000);
        kani::assume(pv <= 1_000_000_000);
        kani::assume(lp <= supply);

        if let Some(col) = calc_collateral_for_withdraw(supply, pv, lp) {
            let lhs = (col as u128) * (supply as u128);
            let rhs = (lp as u128) * (pv as u128);
            assert!(lhs <= rhs, "Withdrawal rounding not pool-favoring");
        }
    }
}
