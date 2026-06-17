//! Property-based tests (proptest) for LP math — complements Kani formal proofs.
//!
//! These test with u64 production types across wide ranges.
//! They can't prove exhaustively (unlike Kani), but they test
//! millions of random inputs including production-scale values.

use proptest::prelude::*;

// Tranche tests below call the REAL production functions directly (not local
// mirrors), so they cannot drift from production. See the "Tranche math" section.
use percolator_stake::math::{
    calc_junior_collateral_for_withdraw, calc_junior_lp_for_deposit,
    calc_senior_collateral_for_withdraw, calc_senior_lp_for_deposit, distribute_fees,
    distribute_loss,
};
use percolator_stake::state::StakePool;

// Mirror production functions exactly (from src/math.rs)
fn calc_lp_for_deposit(supply: u64, pool_value: u64, deposit: u64) -> Option<u64> {
    // C9 fix: block deposits when orphaned value or valueless LP exists
    if supply == 0 && pool_value == 0 {
        Some(deposit)
    } else if supply == 0 || pool_value == 0 {
        None
    } else {
        let lp = (deposit as u128)
            .checked_mul(supply as u128)?
            .checked_div(pool_value as u128)?;
        if lp > u64::MAX as u128 {
            None
        } else {
            Some(lp as u64)
        }
    }
}

fn calc_collateral_for_withdraw(supply: u64, pool_value: u64, lp: u64) -> Option<u64> {
    if supply == 0 {
        return None;
    }
    let col = (lp as u128)
        .checked_mul(pool_value as u128)?
        .checked_div(supply as u128)?;
    if col > u64::MAX as u128 {
        None
    } else {
        Some(col as u64)
    }
}

fn flush_available(deposited: u64, withdrawn: u64, flushed: u64) -> u64 {
    deposited.saturating_sub(withdrawn).saturating_sub(flushed)
}

fn pool_value(deposited: u64, withdrawn: u64) -> Option<u64> {
    deposited.checked_sub(withdrawn)
}

fn pool_value_with_returns(deposited: u64, withdrawn: u64, returned: u64) -> Option<u64> {
    deposited.checked_sub(withdrawn)?.checked_add(returned)
}

// ═══════════════════════════════════════════════════════════════
// Property Tests
// ═══════════════════════════════════════════════════════════════

proptest! {
    // ── Conservation ──

    #[test]
    fn prop_deposit_withdraw_no_inflation(
        supply in 1u64..1_000_000_000,
        pv in 1u64..1_000_000_000,
        deposit in 1u64..1_000_000_000,
    ) {
        let lp = match calc_lp_for_deposit(supply, pv, deposit) {
            Some(lp) if lp > 0 => lp,
            _ => return Ok(()),
        };
        let ns = match supply.checked_add(lp) {
            Some(v) => v, None => return Ok(()),
        };
        let np = match pv.checked_add(deposit) {
            Some(v) => v, None => return Ok(()),
        };
        let back = match calc_collateral_for_withdraw(ns, np, lp) {
            Some(v) => v, None => return Ok(()),
        };
        prop_assert!(back <= deposit, "Got back {} > deposited {}", back, deposit);
    }

    #[test]
    fn prop_first_depositor_exact(amount in 1u64..u64::MAX) {
        let lp = calc_lp_for_deposit(0, 0, amount).unwrap();
        prop_assert_eq!(lp, amount);
        let back = calc_collateral_for_withdraw(lp, amount, lp).unwrap();
        prop_assert_eq!(back, amount);
    }

    #[test]
    fn prop_two_depositors_conservation(
        a in 1u64..100_000_000,
        b in 1u64..100_000_000,
    ) {
        let a_lp = calc_lp_for_deposit(0, 0, a).unwrap();
        let b_lp = match calc_lp_for_deposit(a_lp, a, b) {
            Some(lp) if lp > 0 => lp, _ => return Ok(()),
        };
        let s2 = a_lp + b_lp;
        let pv2 = a + b;

        let a_back = match calc_collateral_for_withdraw(s2, pv2, a_lp) {
            Some(v) => v, None => return Ok(()),
        };
        let b_back = match calc_collateral_for_withdraw(s2 - a_lp, pv2 - a_back, b_lp) {
            Some(v) => v, None => return Ok(()),
        };
        prop_assert!(
            a_back + b_back <= a + b,
            "total out {} > total in {}", a_back + b_back, a + b,
        );
    }

    // ── No Dilution ──

    #[test]
    fn prop_no_dilution(
        a_dep in 1u64..100_000_000,
        b_dep in 1u64..100_000_000,
    ) {
        let a_lp = calc_lp_for_deposit(0, 0, a_dep).unwrap();
        let a_before = calc_collateral_for_withdraw(a_lp, a_dep, a_lp).unwrap();

        let b_lp = match calc_lp_for_deposit(a_lp, a_dep, b_dep) {
            Some(lp) if lp > 0 => lp, _ => return Ok(()),
        };

        let a_after = match calc_collateral_for_withdraw(a_lp + b_lp, a_dep + b_dep, a_lp) {
            Some(v) => v, None => return Ok(()),
        };

        prop_assert!(a_after >= a_before, "Dilution: {} < {}", a_after, a_before);
    }

    // ── Monotonicity ──

    #[test]
    fn prop_larger_deposit_more_lp(
        supply in 1u64..1_000_000_000,
        pv in 1u64..1_000_000_000,
        sm in 1u64..500_000_000u64,
    ) {
        // BUG-11: Replace single-arm match with if let to satisfy clippy::match_single_binding.
        let lg = sm + 1;
        if let (Some(ls), Some(ll)) = (calc_lp_for_deposit(supply, pv, sm), calc_lp_for_deposit(supply, pv, lg)) {
            prop_assert!(ll >= ls);
        }
    }

    #[test]
    fn prop_larger_burn_more_collateral(
        supply in 2u64..1_000_000_000,
        pv in 1u64..1_000_000_000,
        sm in 1u64..500_000_000u64,
    ) {
        let lg = sm + 1;
        prop_assume!(lg <= supply);
        // BUG-11: Replace single-arm match with if let to satisfy clippy::match_single_binding.
        if let (Some(cs), Some(cl)) = (calc_collateral_for_withdraw(supply, pv, sm), calc_collateral_for_withdraw(supply, pv, lg)) {
            prop_assert!(cl >= cs);
        }
    }

    // ── Rounding Direction ──

    #[test]
    fn prop_lp_rounds_down(
        supply in 1u64..1_000_000_000,
        pv in 1u64..1_000_000_000,
        deposit in 1u64..1_000_000_000,
    ) {
        if let Some(lp) = calc_lp_for_deposit(supply, pv, deposit) {
            // lp * pv <= deposit * supply (pool-favoring)
            prop_assert!(
                (lp as u128) * (pv as u128) <= (deposit as u128) * (supply as u128),
                "LP rounding up: lp={} pv={} dep={} supply={}", lp, pv, deposit, supply,
            );
        }
    }

    #[test]
    fn prop_withdrawal_rounds_down(
        supply in 1u64..1_000_000_000,
        pv in 1u64..1_000_000_000,
        lp in 1u64..1_000_000_000u64,
    ) {
        prop_assume!(lp <= supply);
        if let Some(col) = calc_collateral_for_withdraw(supply, pv, lp) {
            // col * supply <= lp * pv (pool-favoring)
            prop_assert!(
                (col as u128) * (supply as u128) <= (lp as u128) * (pv as u128),
                "Withdrawal rounding up: col={} s={} lp={} pv={}", col, supply, lp, pv,
            );
        }
    }

    // ── Bounds ──

    #[test]
    fn prop_full_burn_bounded(
        supply in 1u64..u64::MAX,
        pv in 0u64..u64::MAX,
    ) {
        if let Some(col) = calc_collateral_for_withdraw(supply, pv, supply) {
            prop_assert!(col <= pv, "Full burn {} > pv {}", col, pv);
        }
    }

    #[test]
    fn prop_flush_bounded(d: u64, w: u64, f: u64) {
        prop_assert!(flush_available(d, w, f) <= d);
    }

    // ── Pool Value with Returns ──

    #[test]
    fn prop_returns_increase_value(
        dep in 0u64..1_000_000_000,
        wd in 0u64..1_000_000_000u64,
        ret in 1u64..1_000_000_000,
    ) {
        prop_assume!(wd <= dep);
        let base = pool_value(dep, wd).unwrap();
        if let Some(with_ret) = pool_value_with_returns(dep, wd, ret) {
            prop_assert!(with_ret > base);
            prop_assert_eq!(with_ret, base + ret);
        }
    }

    // ── Large Values (production scale) ──

    #[test]
    fn prop_large_deposit_no_panic(
        supply in 0u64..u64::MAX,
        pv in 0u64..u64::MAX,
        deposit in 0u64..u64::MAX,
    ) {
        let _ = calc_lp_for_deposit(supply, pv, deposit);
    }

    #[test]
    fn prop_large_withdraw_no_panic(
        supply in 0u64..u64::MAX,
        pv in 0u64..u64::MAX,
        lp in 0u64..u64::MAX,
    ) {
        let _ = calc_collateral_for_withdraw(supply, pv, lp);
    }
}

// ═══════════════════════════════════════════════════════════════
// Targeted Edge Cases (not random)
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_production_scale_conservation() {
    // Simulate a real pool: 10M USDC total, 1M LP tokens
    let supply = 1_000_000_000_000u64; // 1M LP (6 decimals)
    let pv = 10_000_000_000_000u64; // 10M USDC (6 decimals)

    // User deposits 50K USDC
    let deposit = 50_000_000_000u64;
    let lp = calc_lp_for_deposit(supply, pv, deposit).unwrap();
    assert_eq!(lp, 5_000_000_000); // 5K LP

    // Withdraw immediately
    let back = calc_collateral_for_withdraw(supply + lp, pv + deposit, lp).unwrap();
    assert!(back <= deposit);
    assert_eq!(back, deposit); // exact at clean ratios
}

#[test]
fn test_dust_deposit_gets_zero_lp() {
    // Pool with 1B LP and 1B value — depositing 0 should return 0
    let lp = calc_lp_for_deposit(1_000_000_000, 1_000_000_001, 1).unwrap();
    // 1 * 1B / (1B+1) = 0 (rounds down)
    assert_eq!(lp, 0);
}

#[test]
fn test_whale_deposit_conservation() {
    // Whale deposits the same as entire pool
    let supply = 100u64;
    let pv = 100u64;
    let deposit = 100u64;

    let lp = calc_lp_for_deposit(supply, pv, deposit).unwrap();
    assert_eq!(lp, 100); // 100 * 100 / 100

    let back = calc_collateral_for_withdraw(200, 200, 100).unwrap();
    assert_eq!(back, 100);
}

#[test]
fn test_three_depositors_sequential_conservation() {
    // A=100, B=200, C=50
    let a_lp = calc_lp_for_deposit(0, 0, 100).unwrap();
    assert_eq!(a_lp, 100);

    let b_lp = calc_lp_for_deposit(100, 100, 200).unwrap();
    assert_eq!(b_lp, 200);

    let c_lp = calc_lp_for_deposit(300, 300, 50).unwrap();
    assert_eq!(c_lp, 50);

    // All withdraw in reverse order
    let c_back = calc_collateral_for_withdraw(350, 350, 50).unwrap();
    let b_back = calc_collateral_for_withdraw(300, 300, 200).unwrap();
    let a_back = calc_collateral_for_withdraw(100, 100, 100).unwrap();

    assert_eq!(c_back + b_back + a_back, 350);
    assert!(c_back + b_back + a_back <= 100 + 200 + 50);
}

// ═══════════════════════════════════════════════════════════════
// Tranche math (senior/junior sub-pools, loss & fee distribution,
// tranche valuation). Calls the REAL production functions in
// `percolator_stake::math` and `percolator_stake::state::StakePool` — the
// u64 property-test complement to the §15 Kani proofs.
// ═══════════════════════════════════════════════════════════════

/// Build a mode-0 (insurance LP) tranche pool with the given ledger fields.
fn tranche_pool(deposited: u64, withdrawn: u64, flushed: u64, returned: u64, junior_balance: u64) -> StakePool {
    use bytemuck::Zeroable;
    let mut pool = StakePool::zeroed();
    pool.is_initialized = 1;
    pool.set_discriminator();
    pool.set_tranche_enabled(true);
    pool.total_deposited = deposited;
    pool.total_withdrawn = withdrawn;
    pool.total_flushed = flushed;
    pool.total_returned = returned;
    pool.set_junior_balance(junior_balance);
    pool // pool_mode 0
}

proptest! {
    // ── Loss distribution: junior absorbs first, value conserved ──

    #[test]
    fn prop_distribute_loss_conservation(
        jb in 0u64..1_000_000_000,
        sb in 0u64..1_000_000_000,
        loss in 0u64..2_000_000_000u64,
    ) {
        let (jl, sl) = distribute_loss(jb, sb, loss);
        let capped = loss.min(jb + sb);
        prop_assert_eq!(jl + sl, capped, "loss not conserved");
        prop_assert!(jl <= jb, "junior over-charged");
        prop_assert!(sl <= sb, "senior over-charged");
    }

    #[test]
    fn prop_distribute_loss_junior_first(
        jb in 0u64..1_000_000_000,
        sb in 0u64..1_000_000_000,
        loss in 0u64..1_000_000_000u64,
    ) {
        prop_assume!(loss <= jb);
        let (jl, sl) = distribute_loss(jb, sb, loss);
        prop_assert_eq!(sl, 0, "senior took loss while junior could absorb");
        prop_assert_eq!(jl, loss);
    }

    // ── Fee distribution: conserved, junior captures all when no senior ──

    #[test]
    fn prop_distribute_fees_conservation(
        jb in 0u64..1_000_000_000,
        sb in 0u64..1_000_000_000,
        mult in 1u16..50_000,
        fee in 0u64..1_000_000_000u64,
    ) {
        let (jf, sf) = distribute_fees(jb, sb, mult, fee);
        prop_assert!(jf <= fee);
        prop_assert!(jf + sf <= fee, "fees exceed total");
        if fee > 0 && (jb > 0 || sb > 0) {
            prop_assert_eq!(jf + sf, fee, "fee not fully conserved when distributable");
        }
    }

    #[test]
    fn prop_distribute_fees_no_senior_all_to_junior(
        jb in 1u64..1_000_000_000,
        mult in 1u16..50_000,
        fee in 1u64..1_000_000_000u64,
    ) {
        let (jf, sf) = distribute_fees(jb, 0, mult, fee);
        prop_assert_eq!(jf, fee, "junior should capture all fees when no senior tranche");
        prop_assert_eq!(sf, 0);
    }

    // ── Sub-pool deposit guard (C9) + first-depositor 1:1 ──

    #[test]
    fn prop_subpool_deposit_orphan_blocked(
        bal in 1u64..1_000_000_000,
        dep in 1u64..1_000_000_000u64,
    ) {
        // sub_lp == 0 but sub_balance > 0 => orphaned value => rejected (not 1:1).
        prop_assert!(calc_senior_lp_for_deposit(0, bal, dep).is_none());
        prop_assert!(calc_junior_lp_for_deposit(0, bal, dep).is_none());
    }

    #[test]
    fn prop_subpool_first_deposit_one_to_one(dep in 1u64..1_000_000_000u64) {
        prop_assert_eq!(calc_senior_lp_for_deposit(0, 0, dep), Some(dep));
        prop_assert_eq!(calc_junior_lp_for_deposit(0, 0, dep), Some(dep));
    }

    // ── Sub-pool deposit→withdraw round-trip cannot profit ──

    #[test]
    fn prop_senior_roundtrip_no_profit(
        slp in 1u64..1_000_000_000,
        sbal in 1u64..1_000_000_000,
        dep in 1u64..1_000_000_000u64,
    ) {
        let lp = match calc_senior_lp_for_deposit(slp, sbal, dep) {
            Some(l) if l > 0 => l, _ => return Ok(()),
        };
        let ns = match slp.checked_add(lp) { Some(v) => v, None => return Ok(()) };
        let nb = match sbal.checked_add(dep) { Some(v) => v, None => return Ok(()) };
        let back = match calc_senior_collateral_for_withdraw(ns, nb, lp) {
            Some(v) => v, None => return Ok(()),
        };
        prop_assert!(back <= dep, "senior round-trip profited: {} > {}", back, dep);
    }

    #[test]
    fn prop_junior_roundtrip_no_profit(
        jlp in 1u64..1_000_000_000,
        jbal in 1u64..1_000_000_000,
        dep in 1u64..1_000_000_000u64,
    ) {
        let lp = match calc_junior_lp_for_deposit(jlp, jbal, dep) {
            Some(l) if l > 0 => l, _ => return Ok(()),
        };
        let ns = match jlp.checked_add(lp) { Some(v) => v, None => return Ok(()) };
        let nb = match jbal.checked_add(dep) { Some(v) => v, None => return Ok(()) };
        let back = match calc_junior_collateral_for_withdraw(ns, nb, lp) {
            Some(v) => v, None => return Ok(()),
        };
        prop_assert!(back <= dep, "junior round-trip profited: {} > {}", back, dep);
    }

    // ── Tranche valuation never bricks senior; tranches partition the pool ──

    #[test]
    fn prop_senior_balance_never_underflows(
        deposited in 0u64..1_000_000_000,
        withdrawn_raw in 0u64..1_000_000_000,
        flushed_raw in 0u64..1_000_000_000,
        returned_raw in 0u64..1_000_000_000,
        junior_raw in 0u64..1_000_000_000,
    ) {
        // Derive a VALID pool state by construction (clamp into range) rather than
        // generate-and-reject: uniform-independent generation satisfies all four
        // ordering constraints only rarely and trips proptest's global-reject cap.
        let withdrawn = withdrawn_raw % (deposited + 1);
        let gross_pool = deposited - withdrawn;
        let flushed = flushed_raw % (gross_pool + 1);       // can't flush more than principal
        let returned = returned_raw % (flushed + 1);        // can't return more than flushed
        let junior_balance = junior_raw % (gross_pool + 1); // junior balance ≤ net principal

        let pool = tranche_pool(deposited, withdrawn, flushed, returned, junior_balance);
        let pv = pool.total_pool_value().unwrap();
        let ejb = pool.effective_junior_balance();
        prop_assert!(ejb <= pv, "effective_junior {} > pool_value {}", ejb, pv);

        // senior_balance() = pv - ejb is always Some, and the split is exact.
        let sb = pool.senior_balance().expect("senior_balance must be Some under pool invariants");
        prop_assert_eq!(sb + ejb, pv, "tranches do not partition the pool exactly");
    }
}
