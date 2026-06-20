//! PoC — `hwm_floor_bps == 10_000` (100%) turns the HWM drain-limiter into a permanent
//! withdrawal kill-switch (issue #196).
//!
//! ── Mechanism ────────────────────────────────────────────────────────────────
//! `validate_hwm_floor_bps` accepts any value in `[1, 10_000]` (processor.rs:117 —
//! the guard is `bps == 0 || bps > 10_000`, so 10_000 passes). The withdraw path
//! (processor.rs:982-996) enforces, for an enabled pool:
//!
//!     current_tvl = pool.total_pool_value()
//!     hwm         = pool.refresh_hwm(epoch, current_tvl)   // only RAISES within an epoch;
//!                                                          // RE-ANCHORS to current_tvl on a new epoch
//!     post_tvl    = current_tvl - withdrawal_amount
//!     require  hwm_withdrawal_allowed(post_tvl, hwm, floor_bps)  // == post_tvl >= hwm*bps/10000
//!
//! At `bps == 10_000` the floor equals the full mark. Because `refresh_hwm` guarantees
//! `hwm >= current_tvl`, we have `floor == hwm >= current_tvl`, so ANY positive
//! withdrawal makes `post_tvl < floor` → rejected with `WithdrawalBelowHwmFloor`.
//!
//! Crucially this is NOT escaped by waiting for the next epoch: on a new epoch
//! `refresh_hwm` re-anchors the mark to the (still full) current TVL, so the floor
//! re-pegs to 100% of current TVL and the next withdrawal is blocked again. The only
//! escape is the admin lowering the floor / disabling HWM. The freeze is permanent
//! and pool-wide.
//!
//! Uses the real `StakePool::refresh_hwm` + `math::hwm_withdrawal_allowed` — the exact
//! functions the withdraw instruction calls.

use bytemuck::Zeroable;
use percolator_stake::math::{hwm_floor, hwm_withdrawal_allowed};
use percolator_stake::state::StakePool;

/// A healthy, fully-backed pool (no loss) with HWM enabled at a 100% floor.
fn pool_with_floor(bps: u16) -> StakePool {
    let mut p = StakePool::zeroed();
    p.is_initialized = 1;
    p.set_discriminator();
    p.set_hwm_enabled(true);
    p.set_hwm_floor_bps(bps);
    p.total_deposited = 1_000_000; // total_pool_value() == 1_000_000 (no flush, no fees)
    p
}

/// Replicates the withdraw-path HWM gate (processor.rs:982-996) for a given epoch &
/// withdrawal amount. Returns `true` if the withdrawal would be ALLOWED.
fn withdrawal_allowed(pool: &mut StakePool, epoch: u64, amount: u64) -> bool {
    let current_tvl = pool.total_pool_value().unwrap();
    let hwm = pool.refresh_hwm(epoch, current_tvl);
    let post_tvl = current_tvl - amount;
    hwm_withdrawal_allowed(post_tvl, hwm, pool.hwm_floor_bps())
}

#[test]
fn floor_100pct_blocks_every_positive_withdrawal_on_a_healthy_pool() {
    let mut pool = pool_with_floor(10_000); // 100%

    // Sanity: at 100% the floor equals the full mark.
    let hwm = pool.refresh_hwm(5, 1_000_000);
    assert_eq!(hwm, 1_000_000);
    assert_eq!(hwm_floor(hwm, 10_000), Some(1_000_000), "floor == 100% of the mark");

    // No loss has occurred — the pool is fully solvent (TVL == 1,000,000) — yet EVERY
    // positive withdrawal is rejected, from a dust 1-unit exit up to a full redemption.
    for amount in [1u64, 1_000, 250_000, 999_999, 1_000_000] {
        assert!(
            !withdrawal_allowed(&mut pool, 5, amount),
            "withdraw of {amount} must be blocked at a 100% HWM floor (post_tvl < floor)"
        );
    }
}

#[test]
fn epoch_rollover_does_not_lift_the_freeze() {
    // The issue posits the freeze lasts only "for the remainder of that epoch" and that the
    // next epoch unfreezes it. That is FALSE at exactly 100%: refresh_hwm re-anchors the mark
    // to the (still full) current TVL on the new epoch, so the floor re-pegs to 100% of TVL.
    let mut pool = pool_with_floor(10_000);

    // Epoch 5: frozen.
    assert!(!withdrawal_allowed(&mut pool, 5, 1), "frozen in the peak epoch");

    // Epoch 6 (rollover): refresh_hwm re-anchors mark to current TVL = 1,000,000.
    let hwm_new_epoch = pool.refresh_hwm(6, 1_000_000);
    assert_eq!(hwm_new_epoch, 1_000_000, "mark re-anchors to current TVL on a new epoch");
    assert!(
        !withdrawal_allowed(&mut pool, 6, 1),
        "STILL frozen one epoch later — the freeze is permanent until the admin lowers the floor"
    );

    // And many epochs later — same result.
    assert!(!withdrawal_allowed(&mut pool, 9_999, 1), "still frozen thousands of epochs later");
}

#[test]
fn boundary_9999_allows_a_sliver_so_10000_is_the_discontinuity() {
    // At 9999 bps the floor is 999,900, so a withdrawal of up to 100 units is allowed —
    // the feature still functions as a *rate limiter*. Bumping the cap by a single bp to
    // 10000 removes the last unit of headroom and converts it into a *kill switch*.
    let mut pool99 = pool_with_floor(9_999);
    assert!(withdrawal_allowed(&mut pool99, 5, 100), "9999 bps allows a 100-unit withdrawal");
    assert!(!withdrawal_allowed(&mut pool99, 5, 101), "9999 bps blocks beyond the 0.01% headroom");

    let mut pool100 = pool_with_floor(10_000);
    assert!(!withdrawal_allowed(&mut pool100, 5, 1), "10000 bps blocks even a single unit");
}
