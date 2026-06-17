//! Regression test for the senior LP deposit/withdraw pricing asymmetry.
//!
//! ── The bug (fixed) ──────────────────────────────────────────────────────────
//! With tranches enabled, a SENIOR deposit used to mint LP at the GLOBAL price
//! (`process_deposit` → `StakePool::calc_lp_for_deposit`), while a SENIOR withdraw
//! redeems at the SENIOR SUB-POOL price (`math::calc_senior_collateral_for_withdraw`).
//! After a junior-absorbed loss (`total_flushed > total_returned`) the global price
//! falls below the senior price, so an unprivileged user could mint senior LP cheap
//! (global) and redeem dear (senior), extracting value from existing senior LPs.
//!
//! ── The fix ──────────────────────────────────────────────────────────────────
//! `process_deposit` now prices senior deposits against the senior sub-pool via
//! `math::calc_senior_lp_for_deposit(senior_total_lp(), senior_balance(), amount)`
//! when `tranche_enabled()`, with a `senior_total_lp() == 0` first-depositor 1:1
//! bootstrap. This mirrors the junior deposit path and the senior withdraw path.
//!
//! These tests model deposits/withdrawals on the pool struct exactly as the repo's
//! `tests/integration.rs` does (no runtime), exercising the same functions the
//! processor calls. `global_pricing_was_exploitable` documents the original bug;
//! the other two are the regression guards for the fix.

use bytemuck::Zeroable;
use percolator_stake::math::{calc_senior_collateral_for_withdraw, calc_senior_lp_for_deposit};
use percolator_stake::state::StakePool;

fn initialized_pool() -> StakePool {
    let mut pool = StakePool::zeroed();
    pool.is_initialized = 1;
    pool.bump = 255;
    pool.vault_authority_bump = 254;
    pool.admin_transferred = 1;
    pool.set_discriminator();
    pool
}

/// Old (buggy) senior deposit pricing: GLOBAL pool ratio.
fn senior_deposit_global(pool: &mut StakePool, amount: u64) -> u64 {
    let lp = pool.calc_lp_for_deposit(amount).expect("calc_lp_for_deposit");
    pool.total_deposited += amount;
    pool.total_lp_supply += lp;
    lp
}

/// Fixed senior deposit pricing — mirrors the post-fix `process_deposit` tranche
/// branch: senior sub-pool ratio, with the `senior_total_lp() == 0` 1:1 bootstrap.
fn senior_deposit_fixed(pool: &mut StakePool, amount: u64) -> u64 {
    let senior_lp = pool.senior_total_lp();
    let lp = if senior_lp == 0 {
        amount
    } else {
        let senior_bal = pool.senior_balance().expect("senior_balance");
        calc_senior_lp_for_deposit(senior_lp, senior_bal, amount).expect("calc_senior_lp_for_deposit")
    };
    pool.total_deposited += amount;
    pool.total_lp_supply += lp;
    lp
}

/// Senior withdraw — same as `process_withdraw`'s senior branch.
fn senior_withdraw(pool: &mut StakePool, lp: u64) -> u64 {
    let coll = calc_senior_collateral_for_withdraw(pool.senior_total_lp(), pool.senior_balance().unwrap(), lp)
        .expect("calc_senior_collateral_for_withdraw");
    pool.total_withdrawn += coll;
    pool.total_lp_supply -= lp;
    coll
}

/// Tranche pool: junior 1M + honest senior "Alice" 1M, then a junior-absorbed 800k loss.
fn setup() -> (StakePool, u64) {
    let mut pool = initialized_pool();
    pool.set_tranche_enabled(true);
    pool.set_junior_balance(1_000_000);
    pool.set_junior_total_lp(1_000_000);
    pool.total_deposited += 1_000_000;
    pool.total_lp_supply += 1_000_000;
    let alice_lp = senior_deposit_global(&mut pool, 1_000_000); // first senior: 1:1 regardless
    pool.total_flushed = 800_000;
    // Junior absorbed the loss; the two price bases now diverge (global 0.6 < senior 1.0).
    assert_eq!(pool.effective_junior_balance(), 200_000);
    assert_eq!(pool.senior_balance().unwrap(), 1_000_000);
    (pool, alice_lp)
}

#[test]
fn global_pricing_was_exploitable() {
    // Documents the original vulnerability: with the OLD global-priced senior
    // deposit, an unprivileged user profits at existing seniors' expense.
    let (mut pool, _alice_lp) = setup();
    let eve_dep = 1_000_000u64;
    let eve_lp = senior_deposit_global(&mut pool, eve_dep);
    let eve_back = senior_withdraw(&mut pool, eve_lp);
    assert!(
        eve_back > eve_dep,
        "global pricing must reproduce the exploit (got {eve_back} for {eve_dep})"
    );
}

#[test]
fn senior_subpool_pricing_prevents_extraction() {
    // Regression guard: the FIXED senior sub-pool pricing yields NO profit and
    // leaves the incumbent senior whole.
    let (mut pool, alice_lp) = setup();
    let alice_before =
        calc_senior_collateral_for_withdraw(pool.senior_total_lp(), pool.senior_balance().unwrap(), alice_lp).unwrap();

    let eve_dep = 1_000_000u64;
    let eve_lp = senior_deposit_fixed(&mut pool, eve_dep);
    let eve_back = senior_withdraw(&mut pool, eve_lp);
    assert!(
        eve_back <= eve_dep,
        "FIX: sub-pool-priced senior deposit must not profit (got {eve_back} for {eve_dep})"
    );

    let alice_after =
        calc_senior_collateral_for_withdraw(pool.senior_total_lp(), pool.senior_balance().unwrap(), alice_lp).unwrap();
    assert!(
        alice_after >= alice_before,
        "FIX: incumbent senior must not be diluted ({alice_before} -> {alice_after})"
    );
}

#[test]
fn bootstrap_first_senior_deposit_does_not_brick() {
    // First senior deposit into a junior-only pool (senior_total_lp == 0) must
    // succeed 1:1 rather than hitting the orphaned-value guard and bricking the
    // senior tranche.
    let mut pool = initialized_pool();
    pool.set_tranche_enabled(true);
    pool.set_junior_balance(1_000_000);
    pool.set_junior_total_lp(1_000_000);
    pool.total_deposited += 1_000_000;
    pool.total_lp_supply += 1_000_000;
    assert_eq!(pool.senior_total_lp(), 0);

    let lp = senior_deposit_fixed(&mut pool, 500_000);
    assert_eq!(lp, 500_000, "first senior deposit bootstraps 1:1");
}
