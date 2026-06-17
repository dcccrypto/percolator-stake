//! PoC / regression — JIT fee-snipe on trading-LP (mode 1) pools.
//!
//! ── The bug ──────────────────────────────────────────────────────────────────
//! Trading fees are paid into the stake vault by the engine and sit there as an
//! UN-ACCRUED surplus (`current_balance > total_pool_value()`) until someone calls
//! the PERMISSIONLESS `AccrueFees`, which folds the whole surplus into
//! `total_fees_earned` (`processor.rs:1688-1690`), lifting LP share price for ALL
//! holders. But `process_deposit` prices new LP against `total_pool_value()`
//! (`calc_lp_for_deposit`) WITHOUT crystallizing the pending surplus first. So a
//! depositor can buy LP at the stale pre-fee price right before accrual (or
//! self-trigger `AccrueFees` in the same tx) and capture a pro-rata share of fees
//! earned BEFORE they joined — diluting the LPs who actually earned them.
//!
//! These tests model the vault token balance (`vault`) alongside the pool ledger
//! and apply the EXACT formulas the program uses: `AccrueFees` =
//! `total_fees_earned += vault - total_pool_value()` (guarded `vault > pv &&
//! supply > 0`); deposit pricing = `calc_lp_for_deposit(total_lp_supply,
//! total_pool_value(), amount)`; withdraw = `calc_collateral_for_withdraw(...)`.

use bytemuck::Zeroable;
use percolator_stake::state::StakePool;

fn mode1_pool() -> StakePool {
    let mut pool = StakePool::zeroed();
    pool.is_initialized = 1;
    pool.bump = 255;
    pool.vault_authority_bump = 254;
    pool.admin_transferred = 1;
    pool.pool_mode = 1; // trading LP pool
    pool.set_discriminator();
    pool
}

/// Models `AccrueFees`: fold the vault surplus into total_fees_earned.
fn accrue(pool: &mut StakePool, vault: u64) {
    let pv = pool.total_pool_value().unwrap();
    if vault > pv && pool.total_lp_supply > 0 {
        pool.total_fees_earned += vault - pv;
    }
}

/// Models the CURRENT `process_deposit`: price against total_pool_value() (no pre-accrue).
fn deposit_current(pool: &mut StakePool, vault: &mut u64, amount: u64) -> u64 {
    let lp = pool.calc_lp_for_deposit(amount).expect("calc_lp_for_deposit");
    pool.total_deposited += amount;
    pool.total_lp_supply += lp;
    *vault += amount;
    lp
}

/// Models a FIXED `process_deposit`: crystallize pending fees BEFORE pricing.
fn deposit_fixed(pool: &mut StakePool, vault: &mut u64, amount: u64) -> u64 {
    accrue(pool, *vault); // <-- the fix: fold pending surplus into share price first
    let lp = pool.calc_lp_for_deposit(amount).expect("calc_lp_for_deposit");
    pool.total_deposited += amount;
    pool.total_lp_supply += lp;
    *vault += amount;
    lp
}

fn withdraw(pool: &mut StakePool, vault: &mut u64, lp: u64) -> u64 {
    let coll = pool.calc_collateral_for_withdraw(lp).expect("calc_collateral_for_withdraw");
    pool.total_withdrawn += coll;
    pool.total_lp_supply -= lp;
    *vault -= coll;
    coll
}

#[test]
fn jit_fee_snipe_is_profitable_with_current_pricing() {
    let mut pool = mode1_pool();
    let mut vault = 0u64;

    // Honest LP Alice is the sole holder while 1,000,000 of fees are earned.
    let alice_lp = deposit_current(&mut pool, &mut vault, 1_000_000);
    vault += 1_000_000; // engine pays in trading fees (un-accrued surplus)

    // Eve front-runs the accrual: deposits at the STALE pre-fee price...
    let eve_dep = 1_000_000u64;
    let eve_lp = deposit_current(&mut pool, &mut vault, eve_dep);
    // ...then anyone calls AccrueFees (Eve can do it in the same tx).
    accrue(&mut pool, vault);
    let eve_back = withdraw(&mut pool, &mut vault, eve_lp);

    assert!(
        eve_back > eve_dep,
        "JIT snipe must profit (got {eve_back} for {eve_dep})"
    );

    // The profit is taken from Alice's earned fees: her fair outcome (sole LP) was
    // 1,000,000 deposit + 1,000,000 fees = 2,000,000; she now gets less.
    let alice_back = withdraw(&mut pool, &mut vault, alice_lp);
    assert!(
        alice_back < 2_000_000,
        "Alice was diluted out of fees she earned (got {alice_back}, fair 2,000,000)"
    );
    assert_eq!(
        (eve_back - eve_dep) + (alice_back - 1_000_000),
        1_000_000,
        "Eve's gain + Alice's gain == total fees (Eve captured part of Alice's earnings)"
    );
}

#[test]
fn crystallizing_fees_before_pricing_prevents_snipe() {
    // Regression guard for the fix direction: accrue pending fees BEFORE pricing a
    // deposit. The JIT depositor then buys at the post-fee price and gains nothing;
    // the honest LP keeps the full fees she earned.
    let mut pool = mode1_pool();
    let mut vault = 0u64;

    let alice_lp = deposit_fixed(&mut pool, &mut vault, 1_000_000);
    vault += 1_000_000; // fees earned while Alice is sole LP

    let eve_dep = 1_000_000u64;
    let eve_lp = deposit_fixed(&mut pool, &mut vault, eve_dep); // pre-accrues -> fair price
    accrue(&mut pool, vault);
    let eve_back = withdraw(&mut pool, &mut vault, eve_lp);
    assert!(
        eve_back <= eve_dep,
        "FIX: JIT depositor must not profit (got {eve_back} for {eve_dep})"
    );

    let alice_back = withdraw(&mut pool, &mut vault, alice_lp);
    assert!(
        alice_back >= 2_000_000,
        "FIX: honest LP keeps the fees she earned (got {alice_back})"
    );
}
