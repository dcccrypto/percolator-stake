//! PoC / regression — mode-1 (trading-LP) `total_pool_value()` underflow brick.
//!
//! `total_pool_value()` computes `total_deposited.checked_sub(total_withdrawn)` FIRST and
//! adds `total_fees_earned` LAST (mode 1). But in a trading pool the withdrawal amount is
//! fee-INCLUSIVE (priced against the fee-inclusive TPV), so `total_withdrawn` accumulates
//! payouts that include fees while `total_deposited` tracks principal only. Once cumulative
//! payouts exceed cumulative principal, `total_deposited.checked_sub(total_withdrawn)`
//! underflows → None → every subsequent `total_pool_value()` returns None and the pool
//! permanently bricks (deposits/withdrawals/accruals all revert via `.ok_or(Overflow)`),
//! trapping remaining LPs' funds. Reachable in normal operation of any profitable trading
//! pool — no attacker.
//!
//! These tests assert the CORRECT (post-fix) solvent values: they FAIL against the pre-fix
//! code (None) and PASS once the arithmetic nets all credits before subtracting debits.

use bytemuck::Zeroable;
use percolator_stake::state::StakePool;

fn trading_pool() -> StakePool {
    let mut p = StakePool::zeroed();
    p.is_initialized = 1;
    p.set_discriminator();
    p.pool_mode = 1; // trading LP
    p
}

#[test]
fn mode1_fee_inclusive_withdraw_does_not_brick_pool() {
    let mut pool = trading_pool();
    // Two LPs deposit 100 each (principal only).
    pool.total_deposited = 200;
    pool.total_lp_supply = 200;
    // Engine trading fees of 300 crystallized via AccrueFees.
    pool.total_fees_earned = 300;
    assert_eq!(pool.total_pool_value(), Some(500), "200 - 0 - 0 + 0 + 300");

    // LP A withdraws 100 of 200 LP at the fee-inclusive price: 100 * 500 / 200 = 250.
    pool.total_withdrawn = 250; // fee-inclusive payout — exceeds total_deposited (200)
    pool.total_lp_supply = 100; // LP B still holds 100 LP

    // Real remaining value = 200 + 300 − 250 = 250. Pre-fix this underflows to None.
    assert_eq!(
        pool.total_pool_value(),
        Some(250),
        "must not underflow when fee-inclusive total_withdrawn (250) > total_deposited (200)"
    );
}

#[test]
fn mode1_tpv_reads_zero_not_none_when_emptied_via_fees() {
    // Single LP deposits 100, earns 100 fees, withdraws everything (200 out).
    let mut pool = trading_pool();
    pool.total_deposited = 100;
    pool.total_lp_supply = 100;
    pool.total_fees_earned = 100;
    assert_eq!(pool.total_pool_value(), Some(200));

    pool.total_withdrawn = 200; // total_withdrawn (200) > total_deposited (100)
    pool.total_lp_supply = 0;

    // Empty, solvent pool must read 0 — not a None brick that blocks future re-use.
    assert_eq!(pool.total_pool_value(), Some(0), "emptied pool reads 0, not None");
}

#[test]
fn mode0_total_pool_value_unchanged_and_insolvency_still_none() {
    // mode-0 (insurance) must be byte-identical: deposited − withdrawn − flushed + returned.
    let mut pool = StakePool::zeroed();
    pool.is_initialized = 1;
    pool.set_discriminator();
    pool.pool_mode = 0;
    pool.total_deposited = 1_000;
    pool.total_withdrawn = 200;
    pool.total_flushed = 300;
    pool.total_returned = 100;
    assert_eq!(pool.total_pool_value(), Some(600), "1000 - 200 - 300 + 100");

    pool.total_flushed = 900; // 1000 - 200 - 900 + 100 = 0
    assert_eq!(pool.total_pool_value(), Some(0));

    // A genuine over-flush (true insolvency / over-withdraw) must STILL return None.
    pool.total_flushed = 1_100; // net negative
    assert_eq!(pool.total_pool_value(), None, "genuine insolvency still surfaces as None");
}
