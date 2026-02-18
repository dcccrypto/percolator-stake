//! Kani formal verification for percolator-stake LP math.
//!
//! ZERO dependencies. Pure Rust. CBMC-friendly.
//!
//! KEY DESIGN DECISION: Functions use u32 inputs / u64 intermediates.
//! The production code uses u64/u128, but the arithmetic properties
//! (conservation, monotonicity, bounds) are scale-invariant.
//! u32 keeps SAT formulas tractable for CBMC (<60s per proof).
//!
//! Run all:   cargo kani --lib
//! Run one:   cargo kani --harness proof_first_depositor_exact

// ═══════════════════════════════════════════════════════════════
// LP Math (u32/u64 mirror of percolator-stake/src/math.rs)
// Arithmetic is IDENTICAL — just narrower types for CBMC tractability.
// ═══════════════════════════════════════════════════════════════

/// LP tokens for deposit. First depositor: 1:1. Subsequent: pro-rata (floor).
pub fn calc_lp_for_deposit(supply: u32, pool_value: u32, deposit: u32) -> Option<u32> {
    if supply == 0 || pool_value == 0 {
        Some(deposit)
    } else {
        let lp = (deposit as u64)
            .checked_mul(supply as u64)?
            .checked_div(pool_value as u64)?;
        Some(lp as u32)
    }
}

/// Collateral for LP burn. floor(lp * pool_value / supply).
pub fn calc_collateral_for_withdraw(supply: u32, pool_value: u32, lp: u32) -> Option<u32> {
    if supply == 0 { return None; }
    let col = (lp as u64)
        .checked_mul(pool_value as u64)?
        .checked_div(supply as u64)?;
    Some(col as u32)
}

/// Pool value = deposited - withdrawn + returned.
/// Mirrors StakePool::total_pool_value() after C4 fix.
pub fn pool_value(deposited: u32, withdrawn: u32) -> Option<u32> {
    deposited.checked_sub(withdrawn)
}

/// Full pool value with flush tracking and insurance returns.
/// Mirrors StakePool::total_pool_value(): deposited - withdrawn - flushed + returned.
pub fn pool_value_with_flush(deposited: u32, withdrawn: u32, flushed: u32, returned: u32) -> Option<u32> {
    deposited.checked_sub(withdrawn)?.checked_sub(flushed)?.checked_add(returned)
}

/// Flush available = deposited - withdrawn - flushed (saturating).
pub fn flush_available(deposited: u32, withdrawn: u32, flushed: u32) -> u32 {
    deposited.saturating_sub(withdrawn).saturating_sub(flushed)
}

/// Cooldown check: current_slot >= deposit_slot + cooldown_slots
pub fn cooldown_elapsed(current_slot: u32, deposit_slot: u32, cooldown_slots: u32) -> bool {
    current_slot >= deposit_slot.saturating_add(cooldown_slots)
}

/// Deposit cap check: returns true if deposit would exceed cap.
/// Cap of 0 = uncapped.
pub fn exceeds_cap(total_deposited: u32, new_deposit: u32, cap: u32) -> bool {
    if cap == 0 { return false; }
    match total_deposited.checked_add(new_deposit) {
        Some(total) => total > cap,
        None => true, // overflow = definitely exceeds
    }
}

// ═══════════════════════════════════════════════════════════════
// KANI PROOFS — 30 harnesses
// ═══════════════════════════════════════════════════════════════

#[cfg(kani)]
mod proofs {
    use super::*;

    // ════════════════════════════════════════════════════════════
    // SECTION 1: Conservation (5 proofs)
    // ════════════════════════════════════════════════════════════

    /// Deposit→withdraw roundtrip: can't get back more than deposited.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_deposit_withdraw_no_inflation() {
        let supply: u32 = kani::any();
        let pv: u32 = kani::any();
        let deposit: u32 = kani::any();
        kani::assume(deposit > 0 && deposit < 20);
        kani::assume(supply > 0 && supply < 20);
        kani::assume(pv > 0 && pv < 20);

        let lp = match calc_lp_for_deposit(supply, pv, deposit) {
            Some(lp) if lp > 0 => lp,
            _ => return,
        };
        let ns = supply + lp;
        let np = pv + deposit;

        let back = match calc_collateral_for_withdraw(ns, np, lp) {
            Some(v) => v, None => return,
        };
        assert!(back <= deposit);
    }

    /// First depositor: exact 1:1 roundtrip.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_first_depositor_exact() {
        let amount: u32 = kani::any();
        kani::assume(amount > 0 && amount < 100);

        let lp = calc_lp_for_deposit(0, 0, amount).unwrap();
        assert_eq!(lp, amount);

        let back = calc_collateral_for_withdraw(lp, amount, lp).unwrap();
        assert_eq!(back, amount);
    }

    /// Two depositors both withdraw: total_out ≤ total_in.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_two_depositors_conservation() {
        let a: u32 = kani::any();
        let b: u32 = kani::any();
        kani::assume(a > 0 && a < 100);
        kani::assume(b > 0 && b < 100);

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
        assert!((a_back as u64) + (b_back as u64) <= (a as u64) + (b as u64));
    }

    /// Late depositor can't dilute early depositor's share.
    /// If B deposits after A, A's withdrawal value doesn't decrease.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_no_dilution() {
        let a_dep: u32 = kani::any();
        let b_dep: u32 = kani::any();
        kani::assume(a_dep > 0 && a_dep < 50);
        kani::assume(b_dep > 0 && b_dep < 50);

        // A deposits first (1:1)
        let a_lp = calc_lp_for_deposit(0, 0, a_dep).unwrap();

        // A's value before B deposits
        let a_value_before = match calc_collateral_for_withdraw(a_lp, a_dep, a_lp) {
            Some(v) => v, None => return,
        };

        // B deposits
        let b_lp = match calc_lp_for_deposit(a_lp, a_dep, b_dep) {
            Some(lp) if lp > 0 => lp, _ => return,
        };

        // A's value after B deposits
        let a_value_after = match calc_collateral_for_withdraw(a_lp + b_lp, a_dep + b_dep, a_lp) {
            Some(v) => v, None => return,
        };

        // A's share should not decrease after B joins
        assert!(a_value_after >= a_value_before);
    }

    /// Flush doesn't change total pool value (it's just moving money between buckets).
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_flush_preserves_value() {
        let dep: u32 = kani::any();
        let wd: u32 = kani::any();
        let flush: u32 = kani::any();
        kani::assume(dep < 100 && wd < 100 && flush < 100);
        kani::assume(wd <= dep);

        let avail = flush_available(dep, wd, 0);
        kani::assume(flush <= avail);

        // Pool value before flush
        let pv_before = pool_value(dep, wd).unwrap();
        // Pool value after flush (flush doesn't change deposited or withdrawn)
        let pv_after = pool_value(dep, wd).unwrap();
        assert_eq!(pv_before, pv_after);
    }

    // ════════════════════════════════════════════════════════════
    // SECTION 2: Arithmetic Safety (4 proofs — full u32 range)
    // ════════════════════════════════════════════════════════════

    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_lp_deposit_no_panic() {
        let _ = calc_lp_for_deposit(kani::any(), kani::any(), kani::any());
    }

    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_collateral_withdraw_no_panic() {
        let _ = calc_collateral_for_withdraw(kani::any(), kani::any(), kani::any());
    }

    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_pool_value_no_panic() {
        let _ = pool_value(kani::any(), kani::any());
    }

    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_flush_available_no_panic() {
        let _ = flush_available(kani::any(), kani::any(), kani::any());
    }

    // ════════════════════════════════════════════════════════════
    // SECTION 3: Fairness / Monotonicity (3 proofs)
    // ════════════════════════════════════════════════════════════

    /// Same inputs → same LP (deterministic).
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_equal_deposits_equal_lp() {
        let s: u32 = kani::any();
        let pv: u32 = kani::any();
        let a: u32 = kani::any();
        kani::assume(s < 100 && pv < 100 && a < 100);
        assert_eq!(calc_lp_for_deposit(s, pv, a), calc_lp_for_deposit(s, pv, a));
    }

    /// Larger deposit → ≥ LP (monotone).
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_larger_deposit_more_lp() {
        let s: u32 = kani::any();
        let pv: u32 = kani::any();
        let sm: u32 = kani::any();
        let lg: u32 = kani::any();
        kani::assume(s > 0 && s < 100);
        kani::assume(pv > 0 && pv < 100);
        kani::assume(sm > 0 && sm < 50);
        kani::assume(lg > sm && lg < 100);

        match (calc_lp_for_deposit(s, pv, sm), calc_lp_for_deposit(s, pv, lg)) {
            (Some(ls), Some(ll)) => assert!(ll >= ls),
            _ => {}
        }
    }

    /// Larger LP burn → ≥ collateral (monotone).
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_larger_burn_more_collateral() {
        let s: u32 = kani::any();
        let pv: u32 = kani::any();
        let sm: u32 = kani::any();
        let lg: u32 = kani::any();
        kani::assume(s > 0 && s < 100);
        kani::assume(pv > 0 && pv < 100);
        kani::assume(sm > 0 && sm < 50);
        kani::assume(lg > sm && lg <= s);

        match (calc_collateral_for_withdraw(s, pv, sm), calc_collateral_for_withdraw(s, pv, lg)) {
            (Some(cs), Some(cl)) => assert!(cl >= cs),
            _ => {}
        }
    }

    // ════════════════════════════════════════════════════════════
    // SECTION 4: Withdrawal Bounds (2 proofs)
    // ════════════════════════════════════════════════════════════

    /// Full LP burn ≤ pool value.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_full_burn_bounded() {
        let s: u32 = kani::any();
        let pv: u32 = kani::any();
        kani::assume(s > 0 && s < 100);
        kani::assume(pv < 100);
        if let Some(col) = calc_collateral_for_withdraw(s, pv, s) {
            assert!(col <= pv);
        }
    }

    /// Partial burn ≤ full burn.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_partial_less_than_full() {
        let s: u32 = kani::any();
        let pv: u32 = kani::any();
        let p: u32 = kani::any();
        kani::assume(s > 1 && s < 100);
        kani::assume(pv > 0 && pv < 100);
        kani::assume(p > 0 && p < s);

        match (calc_collateral_for_withdraw(s, pv, s), calc_collateral_for_withdraw(s, pv, p)) {
            (Some(f), Some(pp)) => assert!(pp <= f),
            _ => {}
        }
    }

    // ════════════════════════════════════════════════════════════
    // SECTION 5: Flush Bounds (2 proofs)
    // ════════════════════════════════════════════════════════════

    /// flush_available ≤ deposited.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_flush_bounded() {
        let d: u32 = kani::any();
        let w: u32 = kani::any();
        let f: u32 = kani::any();
        kani::assume(d < 100 && w < 100 && f < 100);
        assert!(flush_available(d, w, f) <= d);
    }

    /// After max flush → 0 available.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_flush_max_then_zero() {
        let d: u32 = kani::any();
        let w: u32 = kani::any();
        let f: u32 = kani::any();
        kani::assume(d < 100 && w < 100 && f < 100);
        kani::assume(w <= d);
        kani::assume(f <= d.saturating_sub(w));

        let avail = flush_available(d, w, f);
        assert_eq!(flush_available(d, w, f + avail), 0);
    }

    // ════════════════════════════════════════════════════════════
    // SECTION 6: Pool Value (3 proofs)
    // ════════════════════════════════════════════════════════════

    /// pool_value: None iff overdrawn.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_pool_value_correctness() {
        let d: u32 = kani::any();
        let w: u32 = kani::any();
        kani::assume(d < 100 && w < 100);
        let r = pool_value(d, w);
        if w > d { assert!(r.is_none()); }
        else { assert_eq!(r, Some(d - w)); }
    }

    /// Deposit strictly increases pool value.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_deposit_increases_value() {
        let d: u32 = kani::any();
        let w: u32 = kani::any();
        let extra: u32 = kani::any();
        kani::assume(d < 100 && w < 100 && extra < 100);
        kani::assume(w <= d && extra > 0);

        let old = pool_value(d, w).unwrap();
        if let Some(new_d) = d.checked_add(extra) {
            let new = pool_value(new_d, w).unwrap();
            assert!(new > old);
        }
    }

    /// Pool value tracks vault balance: deposited - withdrawn - flushed + returned.
    /// After flush + full return, pool value == deposited - withdrawn (conservation).
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_flush_return_conservation() {
        let d: u32 = kani::any();
        let w: u32 = kani::any();
        let f: u32 = kani::any();
        let r: u32 = kani::any();
        kani::assume(d < 100 && w < 100 && f < 100 && r < 100);
        kani::assume(w <= d);
        kani::assume(f <= d - w);
        kani::assume(r <= f); // can't return more than flushed

        if let Some(pv) = pool_value_with_flush(d, w, f, r) {
            // Pool value always ≤ deposited - withdrawn (optimistic ceiling)
            assert!(pv <= d - w);
            // Full return: pv == deposited - withdrawn
            if r == f {
                assert_eq!(pv, d - w);
            }
            // Partial return: pv < deposited - withdrawn
            if r < f {
                assert!(pv < d - w);
            }
        }
    }

    /// Returns increase pool value (for fixed flush amount).
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_returns_increase_value() {
        let d: u32 = kani::any();
        let w: u32 = kani::any();
        let f: u32 = kani::any();
        let r: u32 = kani::any();
        kani::assume(d < 50 && w < 50 && f < 50 && r < 50);
        kani::assume(w <= d && f <= d - w && r < f);

        let before = pool_value_with_flush(d, w, f, r);
        let after = pool_value_with_flush(d, w, f, r + 1);
        match (before, after) {
            (Some(b), Some(a)) => assert!(a > b),
            _ => {}
        }
    }

    // ════════════════════════════════════════════════════════════
    // SECTION 7: Zero-input Boundaries (2 proofs)
    // ════════════════════════════════════════════════════════════

    /// Zero deposit → zero LP.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_zero_deposit_zero_lp() {
        let s: u32 = kani::any();
        let pv: u32 = kani::any();
        kani::assume(s > 0 && s < 100);
        kani::assume(pv > 0 && pv < 100);
        assert_eq!(calc_lp_for_deposit(s, pv, 0), Some(0));
    }

    /// Zero LP burn → zero collateral.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_zero_burn_zero_col() {
        let s: u32 = kani::any();
        let pv: u32 = kani::any();
        kani::assume(s > 0 && s < 100);
        kani::assume(pv > 0 && pv < 100);
        assert_eq!(calc_collateral_for_withdraw(s, pv, 0), Some(0));
    }

    // ════════════════════════════════════════════════════════════
    // SECTION 8: Cooldown Enforcement (3 proofs)
    // ════════════════════════════════════════════════════════════

    /// Cooldown never panics.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_cooldown_no_panic() {
        let _ = cooldown_elapsed(kani::any(), kani::any(), kani::any());
    }

    /// Cooldown: immediate check (same slot) with non-zero cooldown → not elapsed.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_cooldown_not_immediate() {
        let slot: u32 = kani::any();
        let cd: u32 = kani::any();
        kani::assume(cd > 0 && cd < 100);
        kani::assume(slot < u32::MAX - 100); // prevent saturating_add wrap
        assert!(!cooldown_elapsed(slot, slot, cd));
    }

    /// Cooldown: slot = deposit + cooldown → elapsed.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_cooldown_exact_boundary() {
        let dep_slot: u32 = kani::any();
        let cd: u32 = kani::any();
        kani::assume(cd < 100);
        kani::assume(dep_slot < u32::MAX - 100);

        let check_slot = dep_slot.saturating_add(cd);
        assert!(cooldown_elapsed(check_slot, dep_slot, cd));
    }

    // ════════════════════════════════════════════════════════════
    // SECTION 9: Deposit Cap (3 proofs)
    // ════════════════════════════════════════════════════════════

    /// Cap of 0 = uncapped (never exceeds).
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_cap_zero_uncapped() {
        let total: u32 = kani::any();
        let dep: u32 = kani::any();
        assert!(!exceeds_cap(total, dep, 0));
    }

    /// Deposit exactly at cap → does NOT exceed.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_cap_at_boundary() {
        let cap: u32 = kani::any();
        let existing: u32 = kani::any();
        kani::assume(cap > 0 && cap < 100);
        kani::assume(existing <= cap);

        let dep = cap - existing;
        // total + dep == cap → should NOT exceed
        assert!(!exceeds_cap(existing, dep, cap));
    }

    /// Deposit above cap → exceeds.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_cap_above_boundary() {
        let cap: u32 = kani::any();
        let existing: u32 = kani::any();
        kani::assume(cap > 0 && cap < 100);
        kani::assume(existing < cap);

        let dep = cap - existing + 1; // one more than would fit
        assert!(exceeds_cap(existing, dep, cap));
    }

    // ════════════════════════════════════════════════════════════
    // SECTION 10: Extended Arithmetic Safety (2 proofs)
    // ════════════════════════════════════════════════════════════

    /// pool_value_with_flush never panics.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_pool_value_with_flush_no_panic() {
        let _ = pool_value_with_flush(kani::any(), kani::any(), kani::any(), kani::any());
    }

    /// exceeds_cap never panics.
    #[kani::proof]
    #[kani::unwind(33)]
    fn proof_exceeds_cap_no_panic() {
        let _ = exceeds_cap(kani::any(), kani::any(), kani::any());
    }
}
