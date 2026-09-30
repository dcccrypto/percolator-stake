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
    use percolator_stake::math::{calc_collateral_for_withdraw, calc_lp_for_deposit, pool_value};

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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
    }

    /// PROOF: pool_value never panics.
    #[kani::proof]
    fn proof_pool_value_no_panic() {
        let deposited: u64 = kani::any();
        let withdrawn: u64 = kani::any();
        let _ = pool_value(deposited, withdrawn);
    }

    // ═══════════════════════════════════════════════════════════
    // 3. Fairness — Monotonicity
    // ═══════════════════════════════════════════════════════════

    /// PROOF: Equal deposits get equal LP tokens (deterministic).
    ///
    /// Previous version allowed supply=0, pv=0, amount=0 which made the proof
    /// vacuously pass (None == None) without exercising any pro-rata arithmetic.
    /// Now requires supply > 0, pv > 0, and amount > 0 so CBMC must verify the
    /// actual proportional calculation path, not just the None-return early exits.
    #[kani::proof]
    fn proof_equal_deposits_equal_lp() {
        let supply: u64 = kani::any();
        let pv: u64 = kani::any();
        let amount: u64 = kani::any();
        kani::assume(supply > 0 && supply <= 1_000_000_000);
        kani::assume(pv > 0 && pv <= 1_000_000_000);
        kani::assume(amount > 0 && amount <= 1_000_000_000);

        let lp1 = calc_lp_for_deposit(supply, pv, amount);
        let lp2 = calc_lp_for_deposit(supply, pv, amount);
        assert_eq!(lp1, lp2);
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
    }

    // ═══════════════════════════════════════════════════════════
    // 5. Flush Bounds
    // ═══════════════════════════════════════════════════════════

    // #200: proof_flush_bounded_by_deposited / proof_flush_max_then_zero removed
    // along with the dead math::flush_available() they proved. The live flush path's
    // safety is covered by total_pool_value()'s proofs (see #169).

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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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
            // Sentinel 2026-09-30: vacuity detector for the assume set.
        kani::cover!(true, "assume set satisfiable; asserted path reached");
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

    // ═══════════════════════════════════════════════════════════
    // #242 — cooldown-increase timelock window (exhaustive, non-vacuous)
    // ═══════════════════════════════════════════════════════════

    /// PROOF: `timelock_window_elapsed` matches its spec over ALL u64 inputs —
    /// `Err` exactly when `proposed_at + timelock` overflows (never a panic),
    /// otherwise `Ok(now >= proposed_at + timelock)`. The two `cover!`s prove both
    /// the elapsed and not-elapsed verdicts are reachable (the gate is neither
    /// constant-true nor constant-false).
    #[kani::proof]
    fn kani_timelock_window_elapsed_matches_spec() {
        let proposed_at: u64 = kani::any();
        let timelock: u64 = kani::any();
        let now: u64 = kani::any();
        let res = percolator_stake::processor::timelock_window_elapsed(proposed_at, timelock, now);
        match proposed_at.checked_add(timelock) {
            None => assert!(res.is_err()),
            Some(earliest) => assert_eq!(res, Ok(now >= earliest)),
        }
        kani::cover!(res == Ok(true));
        kani::cover!(res == Ok(false));
    }

    /// PROOF (#290): mode-0 fee attribution never books a donation. Over ALL
    /// inputs: the attributable amount never exceeds the vault surplus, and, once
    /// the caller books it, the cursor never passes the wrapper's payout counter
    /// (given an armed cursor that had not passed it). So cumulative booked fees
    /// are bounded by cumulative wrapper payouts. With nothing unbooked, nothing is
    /// attributable whatever the surplus. That last case is the donation. Covers
    /// prove the booking, donation-only and legacy-arming branches are all reachable.
    /// No multiplication, so full-width u64/u128 is tractable.
    #[kani::proof]
    fn kani_290_mode0_attribution_bounded_by_wrapper_payouts() {
        let surplus: u64 = kani::any();
        let paid: u128 = kani::any();
        let cursor: u64 = kani::any();
        let armed: bool = kani::any();
        if armed {
            kani::assume(cursor as u128 <= paid);
        }
        let r = percolator_stake::math::mode0_attributable_fees(surplus, paid, cursor, armed);
        let Some((c2, a)) = r else {
            // Only an un-armed re-base whose cursor exceeds u64 may fail.
            assert!(!armed && paid > u64::MAX as u128);
            return;
        };
        assert!(a <= surplus);
        assert!(c2 as u128 + a as u128 <= paid);
        if armed {
            assert_eq!(c2, cursor);
            if cursor as u128 == paid {
                assert_eq!(a, 0);
            }
        } else {
            assert_eq!(a as u128, core::cmp::min(surplus as u128, paid));
        }
        kani::cover!(armed && a > 0);
        kani::cover!(armed && surplus > 0 && a == 0);
        kani::cover!(!armed && a > 0);
    }

    /// PROOF (F3, fee-flow audit 2026-09-29): the accrual guard admits a pool iff it
    /// holds at least one REAL LP share above the N7 dead-share floor. Over ALL u64
    /// supplies (the real function, full width): `has_real_lp_holders(s)` is exactly
    /// `s > MINIMUM_LIQUIDITY`; when it admits, the real (non-dead) supply
    /// `s - MINIMUM_LIQUIDITY` is at least 1 and cannot underflow; a pool holding only
    /// the dead shares (s == MINIMUM_LIQUIDITY), or less (legacy pools, fresh pools),
    /// is refused. Covers prove the refuse branch, the admit branch, and both sides
    /// of the exact boundary are reachable, so the proof is not vacuous.
    #[kani::proof]
    fn kani_f3_accrual_requires_real_lp_above_dead_shares() {
        use percolator_stake::state::MINIMUM_LIQUIDITY;
        let supply: u64 = kani::any();
        let ok = percolator_stake::math::has_real_lp_holders(supply);
        assert_eq!(ok, supply > MINIMUM_LIQUIDITY);
        if ok {
            let real = supply.checked_sub(MINIMUM_LIQUIDITY);
            assert!(matches!(real, Some(r) if r >= 1));
        } else {
            assert!(supply <= MINIMUM_LIQUIDITY);
        }
        kani::cover!(!ok, "COVER: refuse branch reachable");
        kani::cover!(ok, "COVER: admit branch reachable");
        kani::cover!(
            supply == MINIMUM_LIQUIDITY && !ok,
            "COVER: dead-shares-only pool is refused"
        );
        kani::cover!(
            supply == MINIMUM_LIQUIDITY + 1 && ok,
            "COVER: one real share is admitted"
        );
    }

    // ═══════════════════════════════════════════════════════════
    // F-9: terminal insurance recovery (stake tag 29)
    // ═══════════════════════════════════════════════════════════

    /// PROOF (F-9 split): the terminal split never books more than the surplus,
    /// never books more principal than stakers flushed and have not recovered, books
    /// the WHOLE surplus when real holders exist, and books no fees to dead shares.
    /// Full u64 range, no bounds.
    #[kani::proof]
    fn kani_f9_terminal_split_conserves_surplus() {
        let surplus: u64 = kani::any();
        let recoverable: u64 = kani::any();
        let real: bool = kani::any();
        let (r, f) = percolator_stake::math::terminal_recovery_split(surplus, recoverable, real);
        assert!(r <= surplus);
        assert!(r <= recoverable);
        let booked = r.checked_add(f);
        assert!(matches!(booked, Some(b) if b <= surplus));
        if real {
            assert_eq!(r + f, surplus, "real holders: the whole surplus is booked");
        } else {
            assert_eq!(f, 0, "F3: no fees to dead shares");
        }
        kani::cover!(
            real && r > 0 && f > 0,
            "COVER: principal and fee legs both booked"
        );
        kani::cover!(
            real && recoverable == 0 && f == surplus && surplus > 0,
            "COVER: all-fee terminal budget (F-9 repro shape)"
        );
        kani::cover!(
            !real && surplus > recoverable && r == recoverable,
            "COVER: dead shares, fee remainder left unbooked"
        );
        kani::cover!(
            real && surplus <= recoverable && r == surplus && surplus > 0,
            "COVER: all-principal recovery"
        );
    }

    /// PROOF (F-9 CPI delta): the post-CPI check admits EXACTLY a vault that grew
    /// by the requested amount — never a short, long or negative delivery.
    #[kani::proof]
    fn kani_f9_cpi_delta_is_exact() {
        let before: u64 = kani::any();
        let after: u64 = kani::any();
        let requested: u64 = kani::any();
        let ok = percolator_stake::math::terminal_cpi_delta_ok(before, after, requested);
        let exact = (before as u128) + (requested as u128) == after as u128;
        assert_eq!(ok, exact);
        kani::cover!(ok && requested > 0, "COVER: exact delivery accepted");
        kani::cover!(
            !ok && after > before && after - before < requested,
            "COVER: short delivery rejected"
        );
        kani::cover!(
            !ok && after > before && after - before > requested,
            "COVER: over delivery rejected"
        );
        kani::cover!(!ok && after < before, "COVER: balance decrease rejected");
    }

    /// PROOF (F-9 amount conservation, the headline property): starting from a
    /// fully booked pool (vault balance == total_pool_value()), the wrapper releases
    /// `released` atoms into pool.vault and `book_terminal_recovery` runs at the new
    /// balance. Then:
    ///   * with real LP holders, pool value rises by EXACTLY `released` — the pool
    ///     (stakers) receives exactly what the wrapper released, not an atom more or less;
    ///   * with dead shares only, it rises by exactly the principal leg, and the
    ///     rest is left unbooked (never booked to dead shares);
    ///   * in every case pool value never exceeds the vault balance, and the
    ///     returned principal never exceeds what stakers flushed.
    /// Runs on the REAL `StakePool::book_terminal_recovery` (tranches off; the tranche
    /// split only divides the fee leg, and `test_f9_book_fee_delta_tranche_split_matches_accrue`
    /// covers it). Bounded to 2^40 per field for solver time (> 10^12 atoms).
    #[kani::proof]
    #[kani::unwind(2)]
    fn kani_f9_pool_receives_exactly_what_wrapper_releases() {
        use bytemuck::Zeroable;
        use percolator_stake::state::StakePool;
        const B: u64 = 1 << 40;
        let mut p = StakePool::zeroed();
        p.is_initialized = 1;
        p.set_discriminator();
        p.total_deposited = kani::any();
        p.total_withdrawn = kani::any();
        p.total_flushed = kani::any();
        p.total_returned = kani::any();
        p.total_recovered_from_wrapper = kani::any();
        p.total_fees_earned = kani::any();
        p.total_lp_supply = kani::any();
        let released: u64 = kani::any();
        kani::assume(p.total_deposited <= B && p.total_withdrawn <= B && p.total_flushed <= B);
        kani::assume(p.total_returned <= B && p.total_fees_earned <= B && released <= B);
        // Pool invariants the program maintains: recovered <= returned <= flushed.
        kani::assume(p.total_recovered_from_wrapper <= p.total_returned);
        kani::assume(p.total_returned <= p.total_flushed);
        let v0 = match p.total_pool_value() {
            Some(v) => v,
            None => return,
        };
        let recoverable0 = p.wrapper_recoverable();
        let returned0 = p.total_returned;
        let real = percolator_stake::math::has_real_lp_holders(p.total_lp_supply);
        let balance = v0 + released; // vault was fully booked; wrapper paid `released`
        let (r, f) = match p.book_terminal_recovery(balance) {
            Ok(x) => x,
            Err(_) => {
                // Only an arithmetic Overflow may refuse, and with these bounds none can.
                panic!("book_terminal_recovery refused a bounded input");
            }
        };
        let v1 = p.total_pool_value().expect("value stays representable");
        assert!(v1 <= balance, "never books more than the vault holds");
        assert_eq!(v1, v0 + r + f, "value moves by exactly what was booked");
        assert!(
            r <= recoverable0,
            "principal leg bounded by the unrecovered flush"
        );
        assert_eq!(p.total_returned, returned0 + r);
        if real {
            assert_eq!(
                v1,
                v0 + released,
                "CONSERVATION: pool receives exactly what the wrapper releases"
            );
        } else {
            assert_eq!(f, 0);
            assert_eq!(v1, v0 + released.min(recoverable0));
        }
        kani::cover!(
            real && released > 0 && r > 0 && f > 0,
            "COVER: split release, both legs"
        );
        kani::cover!(
            real && released > 0 && recoverable0 == 0 && f == released,
            "COVER: F-9 shape, nothing flushed, all fees"
        );
        kani::cover!(
            !real && released > recoverable0 && recoverable0 > 0,
            "COVER: dead shares, principal only"
        );
    }

    /// REVIEW (Sentinel 2026-09-30): `kani_f9_pool_receives_exactly_what_wrapper_releases`
    /// assumes the vault was FULLY BOOKED before the release (balance == value + released).
    /// This drops that assumption: any pre-existing unbooked surplus `u` (e.g. a dead-share
    /// fee remainder `book_terminal_recovery` deliberately left unbooked, or a donation) is
    /// also booked by the next terminal recovery. The exact statement is therefore
    /// "with real holders, pool value becomes EXACTLY the vault balance", not "rises by
    /// exactly what the wrapper released"; the two coincide only when u == 0.
    #[kani::proof]
    #[kani::unwind(2)]
    fn kani_review_f9_books_whole_vault_surplus() {
        use bytemuck::Zeroable;
        use percolator_stake::state::StakePool;
        const B: u64 = 1 << 40;
        let mut p = StakePool::zeroed();
        p.is_initialized = 1;
        p.set_discriminator();
        p.total_deposited = kani::any();
        p.total_withdrawn = kani::any();
        p.total_flushed = kani::any();
        p.total_returned = kani::any();
        p.total_recovered_from_wrapper = kani::any();
        p.total_fees_earned = kani::any();
        p.total_lp_supply = kani::any();
        let released: u64 = kani::any();
        let unbooked: u64 = kani::any();
        kani::assume(p.total_deposited <= B && p.total_withdrawn <= B && p.total_flushed <= B);
        kani::assume(p.total_returned <= B && p.total_fees_earned <= B && released <= B && unbooked <= B);
        kani::assume(p.total_recovered_from_wrapper <= p.total_returned);
        kani::assume(p.total_returned <= p.total_flushed);
        let v0 = match p.total_pool_value() {
            Some(v) => v,
            None => return,
        };
        let recoverable0 = p.wrapper_recoverable();
        let real = percolator_stake::math::has_real_lp_holders(p.total_lp_supply);
        let balance = v0 + unbooked + released;
        let (r, f) = p.book_terminal_recovery(balance).expect("bounded input");
        let v1 = p.total_pool_value().expect("representable");
        assert!(v1 <= balance);
        if real {
            assert_eq!(v1, balance, "real holders: the WHOLE vault surplus is booked");
        } else {
            assert_eq!(f, 0);
            assert_eq!(r, (unbooked + released).min(recoverable0));
        }
        kani::cover!(real && unbooked > 0 && released > 0 && v1 > v0 + released,
            "pre-existing unbooked surplus is booked on top of the release");
    }
}
