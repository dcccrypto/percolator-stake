//! Kani formal verification proofs for percolator-stake LP math.
//!
//! ## DEPRECATION NOTICE (PERC-761 P2)
//! This file is superseded by `kani-proofs/src/lib.rs`, which is the canonical
//! location for all LP-math Kani proofs. `kani-proofs/` uses u32/u64 mirror
//! types for CBMC tractability and now includes INDUCTIVE proofs (§14, PERC-760).
//! New proofs should be added there, not here.
//!
//! This file is retained for CI compatibility until kani-proofs/ covers all
//! harnesses present here. Tracked in PERC-761.
//!
//! Proves critical safety properties on the PURE MATH layer:
//! 1. LP conservation: no value creation/destruction through deposit/withdraw
//! 2. Arithmetic safety: no overflow/panic at any valid input
//! 3. Fairness: monotonicity, proportionality
//! 4. Flush bounds: can't flush more than available
//! 5. Withdrawal bounds: can't extract more than pool value
//!
//! BOUNDS: Proofs involving calc_lp_for_deposit / calc_collateral_for_withdraw
//! are bounded to ≤ 10^9 per symbolic variable. These functions use u128
//! intermediates (u64 * u64 → u128 / u64), and unbounded 64-bit bitvector
//! multiplication causes CBMC SAT-solver timeouts on CI runners.
//! Full-range proofs exist in kani-proofs/ using u32 mirrors for tractability.
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
        assert!(
            back <= deposit,
            "INFLATION: deposited {} but withdrew {}",
            deposit,
            back
        );
    }

    /// PROOF: First depositor gets exact 1:1 (no loss, no gain).
    #[kani::proof]
    fn proof_first_depositor_exact() {
        let amount: u64 = kani::any();
        kani::assume(amount > 0);
        kani::assume(amount <= 1_000_000_000); // bound: withdraw path uses u128 mult

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
            "INFLATION: in={}+{}, out={}+{}",
            a,
            b,
            a_back,
            b_back
        );
    }

    // ═══════════════════════════════════════════════════════════
    // 2. Arithmetic Safety — No Panics
    // ═══════════════════════════════════════════════════════════

    /// PROOF: calc_lp_for_deposit never panics.
    /// Bounded to 10^9 — u128 intermediates make full-u64 intractable for CBMC.
    /// Full-range panic-freedom proven in kani-proofs/ with u32 mirrors.
    #[kani::proof]
    fn proof_lp_deposit_no_panic() {
        let supply: u64 = kani::any();
        let pv: u64 = kani::any();
        let amount: u64 = kani::any();
        kani::assume(supply <= 1_000_000_000);
        kani::assume(pv <= 1_000_000_000);
        kani::assume(amount <= 1_000_000_000);
        let _ = calc_lp_for_deposit(supply, pv, amount);
    }

    /// PROOF: calc_collateral_for_withdraw never panics.
    /// Bounded to 10^9 — u128 intermediates make full-u64 intractable for CBMC.
    /// Full-range panic-freedom proven in kani-proofs/ with u32 mirrors.
    #[kani::proof]
    fn proof_collateral_withdraw_no_panic() {
        let supply: u64 = kani::any();
        let pv: u64 = kani::any();
        let lp: u64 = kani::any();
        kani::assume(supply <= 1_000_000_000);
        kani::assume(pv <= 1_000_000_000);
        kani::assume(lp <= 1_000_000_000);
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
        kani::assume(supply <= 1_000_000_000);
        kani::assume(pv <= 1_000_000_000);
        kani::assume(amount <= 1_000_000_000);

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
        kani::assume(supply <= 1_000_000_000);
        kani::assume(pv <= 1_000_000_000);
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

        assert!(
            lp_l >= lp_s,
            "Monotonicity violated: more deposit → less LP"
        );
    }

    /// PROOF: Larger LP burn → ≥ collateral (monotonicity).
    #[kani::proof]
    fn proof_larger_burn_more_collateral() {
        let supply: u64 = kani::any();
        let pv: u64 = kani::any();
        let small_lp: u64 = kani::any();
        let large_lp: u64 = kani::any();

        kani::assume(supply > 0 && pv > 0);
        kani::assume(supply <= 1_000_000_000);
        kani::assume(pv <= 1_000_000_000);
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

        assert!(
            c_l >= c_s,
            "Monotonicity violated: more LP burn → less collateral"
        );
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
        kani::assume(supply <= 1_000_000_000);
        kani::assume(pv <= 1_000_000_000);

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
        kani::assume(supply <= 1_000_000_000);
        kani::assume(pv <= 1_000_000_000);
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
        let new = pool_value(
            deposited.checked_add(new_deposit).unwrap_or(u64::MAX),
            withdrawn,
        );

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

    // ═══════════════════════════════════════════════════════════
    // PERC-303: Senior/Junior Tranche Safety
    // ═══════════════════════════════════════════════════════════

    #[kani::proof]
    fn proof_senior_never_loses_while_junior_positive() {
        use percolator_stake::math::distribute_loss;

        let junior_balance: u64 = kani::any();
        let senior_balance: u64 = kani::any();
        let loss_amount: u64 = kani::any();

        kani::assume(junior_balance > 0);
        kani::assume(junior_balance <= 1_000_000_000);
        kani::assume(senior_balance <= 1_000_000_000);
        kani::assume(loss_amount <= junior_balance);

        let (junior_loss, senior_loss) =
            distribute_loss(junior_balance, senior_balance, loss_amount);

        assert_eq!(senior_loss, 0, "Senior lost while junior was positive");
        assert_eq!(junior_loss, loss_amount, "Junior did not absorb full loss");
    }

    #[kani::proof]
    fn proof_loss_distribution_conservative() {
        use percolator_stake::math::distribute_loss;

        let junior_balance: u64 = kani::any();
        let senior_balance: u64 = kani::any();
        let loss_amount: u64 = kani::any();

        kani::assume(junior_balance <= 1_000_000_000);
        kani::assume(senior_balance <= 1_000_000_000);
        kani::assume(loss_amount <= 1_000_000_000);

        let (junior_loss, senior_loss) =
            distribute_loss(junior_balance, senior_balance, loss_amount);

        let total = junior_loss as u128 + senior_loss as u128;
        assert!(total <= loss_amount as u128, "Distributed more than loss");
        assert!(
            junior_loss <= junior_balance,
            "Junior lost more than balance"
        );
        assert!(
            senior_loss <= senior_balance,
            "Senior lost more than balance"
        );
    }

    #[kani::proof]
    fn proof_fee_distribution_conservative() {
        use percolator_stake::math::distribute_fees;

        let junior_balance: u64 = kani::any();
        let senior_balance: u64 = kani::any();
        let junior_fee_mult_bps: u16 = kani::any();
        let total_fee: u64 = kani::any();

        kani::assume(junior_balance <= 1_000_000_000);
        kani::assume(senior_balance <= 1_000_000_000);
        kani::assume(junior_fee_mult_bps >= 10_000 && junior_fee_mult_bps <= 50_000);
        kani::assume(total_fee <= 1_000_000_000);

        let (jf, sf) = distribute_fees(
            junior_balance,
            senior_balance,
            junior_fee_mult_bps,
            total_fee,
        );

        assert!(
            jf as u128 + sf as u128 <= total_fee as u128,
            "Fee distribution exceeds total"
        );
    }

    // ═══════════════════════════════════════════════════════════
    // PERC-313: High-Water Mark Floor
    // ═══════════════════════════════════════════════════════════

    #[kani::proof]
    fn proof_withdrawal_blocked_below_hwm_floor() {
        use percolator_stake::math::{hwm_floor, hwm_withdrawal_allowed};

        let post_tvl: u64 = kani::any();
        let epoch_hwm: u64 = kani::any();
        let floor_bps: u16 = kani::any();

        kani::assume(floor_bps <= 10_000);
        kani::assume(epoch_hwm <= 1_000_000_000);
        kani::assume(post_tvl <= 1_000_000_000);

        let allowed = hwm_withdrawal_allowed(post_tvl, epoch_hwm, floor_bps);

        if let Some(floor_val) = hwm_floor(epoch_hwm, floor_bps) {
            if allowed {
                assert!(
                    post_tvl >= floor_val,
                    "allowed withdrawal but post_tvl < floor"
                );
            } else {
                assert!(
                    post_tvl < floor_val,
                    "blocked withdrawal but post_tvl >= floor"
                );
            }
        } else {
            assert!(!allowed, "overflow floor must block");
        }
    }

    #[kani::proof]
    fn proof_hwm_floor_monotonic_in_tvl() {
        use percolator_stake::math::hwm_floor;

        let tvl_a: u64 = kani::any();
        let tvl_b: u64 = kani::any();
        let bps: u16 = kani::any();

        kani::assume(bps <= 10_000);
        kani::assume(tvl_a <= tvl_b);
        kani::assume(tvl_b <= 1_000_000_000);

        if let (Some(floor_a), Some(floor_b)) = (hwm_floor(tvl_a, bps), hwm_floor(tvl_b, bps)) {
            assert!(
                floor_b >= floor_a,
                "higher TVL must produce higher or equal floor"
            );
        }
    }

    #[kani::proof]
    fn proof_hwm_floor_bounded_by_tvl() {
        use percolator_stake::math::hwm_floor;

        let tvl: u64 = kani::any();
        let bps: u16 = kani::any();

        kani::assume(bps <= 10_000);
        kani::assume(tvl <= 1_000_000_000);

        if let Some(floor) = hwm_floor(tvl, bps) {
            assert!(floor <= tvl, "floor must never exceed HWM TVL");
        }
    }

    // ═══════════════════════════════════════════════════════════
    // PERC-8422: Security Finding Proofs
    // ═══════════════════════════════════════════════════════════

    // ── PR#94 CRITICAL: State Collision Independence ──
    // After the fix (hwm_enabled at byte 10, market_resolved at byte 9),
    // these two flags must be fully independent.

    /// PROOF: Enabling HWM does NOT set market_resolved.
    /// Pre-fix this was the CRITICAL bug: both lived at _reserved[9].
    #[kani::proof]
    fn proof_hwm_enable_does_not_set_market_resolved() {
        use bytemuck::Zeroable;
        use percolator_stake::state::StakePool;

        let mut pool = StakePool::zeroed();
        pool.set_discriminator();

        // Precondition: market is NOT resolved
        assert!(!pool.market_resolved());

        // Action: enable HWM
        pool.set_hwm_enabled(true);

        // Postcondition: market_resolved must still be false
        assert!(
            !pool.market_resolved(),
            "CRITICAL: enabling HWM set market_resolved"
        );
        // And HWM must be true
        assert!(pool.hwm_enabled());

        // Non-vacuity: we actually tested something
        kani::cover!(pool.hwm_enabled() && !pool.market_resolved());
    }

    /// PROOF: Resolving market does NOT enable HWM.
    /// Pre-fix this was the reverse collision.
    #[kani::proof]
    fn proof_market_resolve_does_not_enable_hwm() {
        use bytemuck::Zeroable;
        use percolator_stake::state::StakePool;

        let mut pool = StakePool::zeroed();
        pool.set_discriminator();

        // Precondition: HWM is NOT enabled
        assert!(!pool.hwm_enabled());

        // Action: resolve market
        pool.set_market_resolved(true);

        // Postcondition: hwm_enabled must still be false
        assert!(
            !pool.hwm_enabled(),
            "CRITICAL: resolving market enabled HWM"
        );
        assert!(pool.market_resolved());

        kani::cover!(pool.market_resolved() && !pool.hwm_enabled());
    }

    /// PROOF: Both flags can be set independently — all 4 combinations are reachable.
    #[kani::proof]
    fn proof_hwm_market_resolved_orthogonal() {
        use bytemuck::Zeroable;
        use percolator_stake::state::StakePool;

        let hwm_val: bool = kani::any();
        let resolved_val: bool = kani::any();

        let mut pool = StakePool::zeroed();
        pool.set_discriminator();

        pool.set_hwm_enabled(hwm_val);
        pool.set_market_resolved(resolved_val);

        // Read-back must match what was written
        assert_eq!(pool.hwm_enabled(), hwm_val, "HWM read-back mismatch");
        assert_eq!(
            pool.market_resolved(),
            resolved_val,
            "market_resolved read-back mismatch"
        );

        // All 4 combinations reachable
        kani::cover!(!pool.hwm_enabled() && !pool.market_resolved());
        kani::cover!(!pool.hwm_enabled() && pool.market_resolved());
        kani::cover!(pool.hwm_enabled() && !pool.market_resolved());
        kani::cover!(pool.hwm_enabled() && pool.market_resolved());
    }

    /// PROOF: HWM config writes don't clobber tranche fields.
    #[kani::proof]
    fn proof_hwm_does_not_clobber_tranche() {
        use bytemuck::Zeroable;
        use percolator_stake::state::StakePool;

        let junior_balance: u64 = kani::any();
        let junior_total_lp: u64 = kani::any();
        let tranche_enabled: bool = kani::any();

        kani::assume(junior_balance <= 1_000_000_000);
        kani::assume(junior_total_lp <= 1_000_000_000);

        let mut pool = StakePool::zeroed();
        pool.set_discriminator();

        // Set tranche state first
        pool.set_tranche_enabled(tranche_enabled);
        pool.set_junior_balance(junior_balance);
        pool.set_junior_total_lp(junior_total_lp);

        // Now mutate HWM fields
        pool.set_hwm_enabled(true);
        pool.set_hwm_floor_bps(7500);
        pool.set_epoch_high_water_tvl(999_999);
        pool.set_hwm_last_epoch(42);

        // Tranche state must be unchanged
        assert_eq!(
            pool.tranche_enabled(),
            tranche_enabled,
            "tranche_enabled clobbered by HWM"
        );
        assert_eq!(
            pool.junior_balance(),
            junior_balance,
            "junior_balance clobbered by HWM"
        );
        assert_eq!(
            pool.junior_total_lp(),
            junior_total_lp,
            "junior_total_lp clobbered by HWM"
        );
    }

    // ── PR#83 HIGH: distribute_fees Overflow Safety ──

    /// PROOF: distribute_fees never panics at full u64 range.
    /// Pre-fix, the u128 product (total_fee * junior_weight) could reach 2^144,
    /// silently wrapping. The checked_mul + shift fallback must prevent this.
    #[kani::proof]
    fn proof_distribute_fees_no_panic_full_range() {
        use percolator_stake::math::distribute_fees;

        let junior_balance: u64 = kani::any();
        let senior_balance: u64 = kani::any();
        let junior_fee_mult_bps: u16 = kani::any();
        let total_fee: u64 = kani::any();

        // Only constrain to valid BPS range — balances and fees are fully symbolic
        kani::assume(junior_fee_mult_bps >= 10_000 && junior_fee_mult_bps <= 50_000);

        let _ = distribute_fees(
            junior_balance,
            senior_balance,
            junior_fee_mult_bps,
            total_fee,
        );
        // If we reach here without panic, the proof passes.
    }

    /// PROOF: distribute_fees is conservative at full u64 range.
    /// junior_fee + senior_fee <= total_fee for ALL inputs (no overflow inflation).
    #[kani::proof]
    fn proof_distribute_fees_conservative_full_range() {
        use percolator_stake::math::distribute_fees;

        let junior_balance: u64 = kani::any();
        let senior_balance: u64 = kani::any();
        let junior_fee_mult_bps: u16 = kani::any();
        let total_fee: u64 = kani::any();

        kani::assume(junior_fee_mult_bps >= 10_000 && junior_fee_mult_bps <= 50_000);

        let (jf, sf) = distribute_fees(
            junior_balance,
            senior_balance,
            junior_fee_mult_bps,
            total_fee,
        );

        assert!(
            jf as u128 + sf as u128 <= total_fee as u128,
            "OVERFLOW INFLATION: fees exceed total"
        );

        // Non-vacuity: at least one non-trivial split occurred
        kani::cover!(jf > 0 && sf > 0);
    }

    /// PROOF: distribute_fees at extreme inputs (max u64 balances + max fee)
    /// does not silently wrap and remains conservative.
    #[kani::proof]
    fn proof_distribute_fees_extreme_inputs() {
        use percolator_stake::math::distribute_fees;

        // Worst case: both balances at u64::MAX, fee at u64::MAX, mult at 50_000
        // junior_weight = u64::MAX * 50_000 ≈ 2^80
        // product = u64::MAX * 2^80 ≈ 2^144 — must not silently wrap
        let (jf, sf) = distribute_fees(u64::MAX, u64::MAX, 50_000, u64::MAX);

        assert!(
            jf as u128 + sf as u128 <= u64::MAX as u128,
            "extreme inputs: overflow inflation"
        );

        // At equal balances with 5x multiplier, junior should get more than senior
        // (junior_weight = MAX * 50_000 vs senior_weight = MAX * 10_000)
        // Ratio should be 50_000 : 10_000 = 5:1
        kani::cover!(jf > sf);
    }
}
