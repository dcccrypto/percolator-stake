//! PoC / regression — JIT trading-fee snipe on the JUNIOR tranche (mode-1 pools).
//!
//! ── The bug ──────────────────────────────────────────────────────────────────
//! In a trading-LP pool (`pool_mode == 1`) with tranches enabled, trading fees land
//! in the vault as an UN-ACCRUED surplus (`current_balance > total_pool_value()`)
//! until the permissionless `AccrueFees` folds them into `total_fees_earned` and
//! credits the junior tranche's (multiplier-weighted) share into `junior_balance`
//! via `distribute_fees`.
//!
//! `process_deposit` (senior/global path) and `process_withdraw` CRYSTALLIZE that
//! surplus (`accrue_fees_inner`) BEFORE pricing — the #136 fix. `process_deposit_junior`
//! does NOT: it prices the junior deposit directly against `effective_junior_balance()`,
//! which excludes the pending surplus. So a junior depositor mints LP at the stale
//! pre-fee price and, after `AccrueFees`, captures a share of fees earned BEFORE they
//! joined — diluting the existing junior LPs. The junior fee multiplier (up to 5x)
//! makes the captured share strictly larger than the senior-path snipe #136 fixed.
//!
//! These tests apply the EXACT functions the program uses
//! (`calc_junior_lp_for_deposit`, `distribute_fees`, `calc_junior_collateral_for_withdraw`)
//! and model `accrue_fees_inner` / `total_pool_value()` on a real `StakePool`,
//! mirroring `tests/poc_jit_fee_snipe.rs`. `junior_jit_fee_snipe_is_profitable_*`
//! documents the bug; `pre_accrue_before_junior_pricing_prevents_snipe` is the fix guard.

use bytemuck::Zeroable;
use percolator_stake::math::{
    calc_junior_collateral_for_withdraw, calc_junior_lp_for_deposit, distribute_fees,
};
use percolator_stake::state::StakePool;

const MULT: u16 = 20_000; // junior_fee_mult_bps = 2x

fn mode1_tranche_pool() -> StakePool {
    let mut p = StakePool::zeroed();
    p.is_initialized = 1;
    p.pool_mode = 1; // trading LP
    p.set_discriminator();
    p.set_tranche_enabled(true);
    p.set_junior_fee_mult_bps(MULT);
    p
}

/// First senior deposit (1:1): only touches the global counters; senior_total_lp
/// and senior_balance are derived (total_lp_supply − junior_total_lp / total_pool_value
/// − effective_junior_balance).
fn add_senior(pool: &mut StakePool, vault: &mut u64, amount: u64) {
    pool.total_deposited += amount;
    pool.total_lp_supply += amount;
    *vault += amount;
}

/// Models `accrue_fees_inner` (mode-1 tranche): fold the vault surplus into
/// `total_fees_earned` and credit the junior share, snapshotting balances BEFORE the add.
fn accrue(pool: &mut StakePool, vault: u64) {
    let pv = pool.total_pool_value().unwrap();
    if vault > pv && pool.total_lp_supply > 0 {
        let fee_delta = vault - pv;
        let snap_j = pool.effective_junior_balance(); // == junior_balance in mode-1 (net_loss=0)
        let snap_s = pool.senior_balance().unwrap();
        let (junior_fee, _senior_fee) =
            distribute_fees(snap_j, snap_s, pool.junior_fee_mult_bps(), fee_delta);
        pool.total_fees_earned += fee_delta;
        pool.set_junior_balance(pool.junior_balance() + junior_fee);
    }
}

/// CURRENT `process_deposit_junior`: price against `effective_junior_balance()` with NO pre-accrue.
fn deposit_junior_current(pool: &mut StakePool, vault: &mut u64, amount: u64) -> u64 {
    let lp = calc_junior_lp_for_deposit(pool.junior_total_lp(), pool.effective_junior_balance(), amount)
        .expect("calc_junior_lp_for_deposit");
    pool.total_deposited += amount;
    pool.total_lp_supply += lp;
    pool.set_junior_total_lp(pool.junior_total_lp() + lp);
    pool.set_junior_balance(pool.junior_balance() + amount);
    *vault += amount;
    lp
}

/// FIXED `process_deposit_junior`: crystallize pending fees (pre-accrue) BEFORE pricing.
fn deposit_junior_fixed(pool: &mut StakePool, vault: &mut u64, amount: u64) -> u64 {
    accrue(pool, *vault); // <-- the fix: mirror the #136 pre-accrue from process_deposit
    let lp = calc_junior_lp_for_deposit(pool.junior_total_lp(), pool.effective_junior_balance(), amount)
        .expect("calc_junior_lp_for_deposit");
    pool.total_deposited += amount;
    pool.total_lp_supply += lp;
    pool.set_junior_total_lp(pool.junior_total_lp() + lp);
    pool.set_junior_balance(pool.junior_balance() + amount);
    *vault += amount;
    lp
}

fn withdraw_junior(pool: &mut StakePool, vault: &mut u64, lp: u64) -> u64 {
    let coll =
        calc_junior_collateral_for_withdraw(pool.junior_total_lp(), pool.effective_junior_balance(), lp)
            .expect("calc_junior_collateral_for_withdraw");
    pool.total_withdrawn += coll;
    pool.total_lp_supply -= lp;
    pool.set_junior_total_lp(pool.junior_total_lp() - lp);
    pool.set_junior_balance(pool.junior_balance() - coll);
    *vault -= coll;
    coll
}

#[test]
fn junior_jit_fee_snipe_is_profitable_with_current_pricing() {
    let mut pool = mode1_tranche_pool();
    let mut vault = 0u64;

    // Senior Alice 1M + honest junior Jane 1M.
    add_senior(&mut pool, &mut vault, 1_000_000);
    let _jane_lp = deposit_junior_current(&mut pool, &mut vault, 1_000_000);

    // Engine pays 1,000,000 trading fees into the vault — un-accrued surplus.
    vault += 1_000_000;

    // Eve front-runs the accrual: DepositJunior at the STALE pre-fee price (current code).
    let eve_dep = 1_000_000u64;
    let eve_lp = deposit_junior_current(&mut pool, &mut vault, eve_dep);

    // Anyone calls AccrueFees (Eve can bundle it in the same tx).
    accrue(&mut pool, vault);

    let eve_back = withdraw_junior(&mut pool, &mut vault, eve_lp);
    assert!(
        eve_back > eve_dep,
        "junior JIT snipe must profit (got {eve_back} for {eve_dep})"
    );
    assert_eq!(eve_back, 1_400_000, "Eve captures +400,000 of fees she did not earn");
}

#[test]
fn pre_accrue_before_junior_pricing_prevents_snipe() {
    // Regression guard for the fix: crystallize pending fees BEFORE pricing a junior
    // deposit (mirroring process_deposit / process_withdraw). The JIT depositor then
    // buys at the post-fee price and gains nothing.
    let mut pool = mode1_tranche_pool();
    let mut vault = 0u64;

    add_senior(&mut pool, &mut vault, 1_000_000);
    let _jane_lp = deposit_junior_fixed(&mut pool, &mut vault, 1_000_000);

    vault += 1_000_000; // fees earned while Jane is the sole junior

    let eve_dep = 1_000_000u64;
    let eve_lp = deposit_junior_fixed(&mut pool, &mut vault, eve_dep); // pre-accrues -> fair price
    accrue(&mut pool, vault);
    let eve_back = withdraw_junior(&mut pool, &mut vault, eve_lp);
    assert!(
        eve_back <= eve_dep,
        "FIX: pre-accrued junior deposit must not profit (got {eve_back} for {eve_dep})"
    );
}
