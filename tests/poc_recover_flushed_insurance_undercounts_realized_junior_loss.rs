//! Regression for #259 — `RecoverFlushedInsurance`'s recovery cap used to be
//! `total_flushed - total_returned`, omitting `realized_junior_loss`. `ReturnInsurance`
//! (the admin path) already included it: when the last junior LP exits during an
//! outstanding loss, `process_withdraw` settles the forfeited portion by adding it to
//! `total_returned` (a bookkeeping-only entry, no wrapper token movement) and records it
//! in `realized_junior_loss` so `total_pool_value()` keeps treating it as dead/unclaimable.
//! `RecoverFlushedInsurance` then under-counted what's physically recoverable from the
//! wrapper by exactly that amount — in the fully-realized case, down to zero — even
//! though the tokens were still sitting in the wrapper's insurance vault.
//!
//! Both paths now share `StakePool::physical_insurance_outstanding()`.

use bytemuck::Zeroable;
use percolator_stake::state::StakePool;

#[test]
fn recover_flushed_insurance_cap_matches_return_insurance_cap() {
    let mut pool = StakePool::zeroed();
    pool.set_discriminator();

    // Model a pool with 1,000 total deposits and 400 flushed to insurance.
    pool.total_deposited = 1_000;
    pool.total_flushed = 400;

    // Model the last-junior-exit bookkeeping: process_withdraw() records the
    // junior-forfeited loss as returned while also recording realized_junior_loss so
    // total_pool_value does not windfall that value to senior. No wrapper token
    // transfer happens in that block — the tokens are still in the wrapper.
    pool.total_returned = 400;
    pool.set_realized_junior_loss(400);

    // Pool value remains loss-adjusted because realized_junior_loss cancels the
    // bookkeeping return.
    assert_eq!(pool.total_pool_value().unwrap(), 600);

    // Before the fix, RecoverFlushedInsurance's cap (total_flushed - total_returned)
    // would have been 0 here, even though 400 tokens are still physically recoverable
    // from the wrapper. Both paths must now agree.
    assert_eq!(pool.physical_insurance_outstanding(), 400);
}

#[test]
fn partial_realized_junior_loss_is_fully_accounted_for() {
    let mut pool = StakePool::zeroed();
    pool.set_discriminator();

    pool.total_deposited = 1_000;
    pool.total_flushed = 600;

    // 250 was booked as a realized junior loss (no token transfer implied).
    pool.total_returned = 250;
    pool.set_realized_junior_loss(250);

    // Outstanding = (600 - 250) + 250 = 600 (the full flushed amount remains
    // physically recoverable; none of it has actually moved back yet).
    assert_eq!(pool.physical_insurance_outstanding(), 600);
}

#[test]
fn no_realized_loss_behaves_like_the_simple_formula() {
    let mut pool = StakePool::zeroed();
    pool.set_discriminator();

    pool.total_deposited = 1_000;
    pool.total_flushed = 600;
    pool.total_returned = 250;
    // realized_junior_loss defaults to 0 (zeroed pool).

    assert_eq!(pool.physical_insurance_outstanding(), 350);
}
