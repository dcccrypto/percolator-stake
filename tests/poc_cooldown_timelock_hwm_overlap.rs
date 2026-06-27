//! Regression for #250/#258 — the #242 cooldown-increase timelock fields
//! (`pending_cooldown_slots`, `cooldown_proposed_at_slot`) used to be packed into
//! `StakePool::_reserved[10..26]`, which the PERC-313 high-water-mark feature already
//! owned in full (`hwm_enabled` at [10], `hwm_floor_bps` at [11..13],
//! `epoch_high_water_tvl` at [16..24], `hwm_last_epoch` at [24..32]). Every write to
//! one feature silently corrupted the other's stored state.
//!
//! The fix promotes both cooldown-timelock fields to real `StakePool` struct fields
//! (CURRENT_VERSION 2 -> 3, STAKE_POOL_SIZE 384 -> 400), so they can no longer alias
//! any `_reserved` byte. These tests mirror the exact corruption sequences from the
//! original bug reports and assert the corruption no longer happens.

use bytemuck::Zeroable;
use percolator_stake::state::StakePool;

#[test]
fn cooldown_timelock_and_hwm_no_longer_share_storage() {
    let mut pool = StakePool::zeroed();
    pool.set_discriminator();

    // Start with HWM enabled and a normal 50% floor.
    pool.set_hwm_enabled(true);
    pool.set_hwm_floor_bps(5_000);
    pool.set_epoch_high_water_tvl(1_000_000);
    pool.set_hwm_last_epoch(10);

    assert!(pool.hwm_enabled());
    assert_eq!(pool.hwm_floor_bps(), 5_000);
    assert_eq!(pool.epoch_high_water_tvl(), 1_000_000);
    assert_eq!(pool.hwm_last_epoch(), 10);

    // Proposing a cooldown increase used to write _reserved[10..18] and
    // _reserved[18..26], which aliased every HWM field except the high bytes of
    // hwm_last_epoch. With real fields, this must leave HWM state untouched.
    pool.set_pending_cooldown_slots(43_200_000);
    pool.set_cooldown_proposed_at_slot(123_456_789);

    assert!(pool.hwm_enabled(), "cooldown proposal must not disturb hwm_enabled");
    assert_eq!(
        pool.hwm_floor_bps(),
        5_000,
        "cooldown proposal must not disturb hwm_floor_bps"
    );
    assert_eq!(
        pool.epoch_high_water_tvl(),
        1_000_000,
        "cooldown proposal must not disturb epoch_high_water_tvl"
    );
    assert_eq!(
        pool.hwm_last_epoch(),
        10,
        "cooldown proposal must not disturb hwm_last_epoch"
    );

    // Now the reverse direction: a later HWM refresh must not corrupt the active
    // cooldown proposal.
    let pending_before = pool.pending_cooldown_slots();
    let proposed_at_before = pool.cooldown_proposed_at_slot();

    pool.refresh_hwm(11, 2_000_000);

    assert_eq!(
        pool.pending_cooldown_slots(),
        pending_before,
        "refresh_hwm must not change pending_cooldown_slots"
    );
    assert_eq!(
        pool.cooldown_proposed_at_slot(),
        proposed_at_before,
        "refresh_hwm must not change cooldown_proposed_at_slot"
    );
}

#[test]
fn enabling_hwm_does_not_mutate_a_pending_cooldown_value() {
    let mut pool = StakePool::zeroed();
    pool.set_discriminator();

    pool.set_pending_cooldown_slots(10_000_000);
    pool.set_cooldown_proposed_at_slot(500_000);

    let pending_before = pool.pending_cooldown_slots();
    let proposed_at_before = pool.cooldown_proposed_at_slot();

    pool.set_hwm_enabled(true);
    pool.set_hwm_floor_bps(9_000);

    assert_eq!(
        pool.pending_cooldown_slots(),
        pending_before,
        "set_hwm_enabled/set_hwm_floor_bps must not overwrite pending_cooldown_slots"
    );
    assert_eq!(
        pool.cooldown_proposed_at_slot(),
        proposed_at_before,
        "set_hwm_enabled/set_hwm_floor_bps must not overwrite cooldown_proposed_at_slot"
    );
}

#[test]
fn hwm_activity_does_not_fabricate_a_phantom_cooldown_proposal() {
    // #250 Direction C: with the old _reserved packing, enabling HWM with a nonzero
    // epoch_high_water_tvl made cooldown_proposed_at_slot() read as nonzero — a
    // "phantom" proposal nobody made. With real fields, an untouched cooldown
    // timelock must report no pending proposal regardless of HWM activity.
    let mut pool = StakePool::zeroed();
    pool.set_discriminator();

    pool.set_hwm_enabled(true);
    pool.set_hwm_floor_bps(5_000);
    pool.refresh_hwm(1, 2_000_000_000);
    pool.refresh_hwm(2, 5_000_000_000);

    assert_eq!(
        pool.cooldown_proposed_at_slot(),
        0,
        "HWM activity must never fabricate a pending cooldown proposal"
    );
    assert_eq!(
        pool.pending_cooldown_slots(),
        0,
        "HWM activity must never fabricate a pending cooldown value"
    );
}
