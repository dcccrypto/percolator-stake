//! Regression: the #242 cooldown-timelock fields must never again share storage with
//! the PERC-313 HWM fields.
//!
//! On the DEPLOYED v3 program (474079f) they aliased:
//!
//!   pending_cooldown_slots     _reserved[10..18]   hwm_enabled           _reserved[10]
//!   cooldown_proposed_at_slot  _reserved[18..26]   hwm_floor_bps         _reserved[11..13]
//!                                                  epoch_high_water_tvl  _reserved[16..24]
//!                                                  hwm_last_epoch        _reserved[24..32]
//!
//! Both sides were live: propose/commit/cancel cooldown are dispatched instructions and
//! `processor.rs` writes the HWM TVL on withdraw. Measured on v3, these three tests
//! recorded `hwm_enabled` true->false, `hwm_floor_bps` 9000->843, `epoch_high_water_tvl`
//! 1e9->2.6e13, and `cooldown_proposed_at_slot` 400_000_000->15_258 (a ~400M-slot
//! timelock bypass). Each assertion below is the inverse of the measured v3 behaviour.

use percolator_stake::state::StakePool;

fn pool() -> StakePool {
    let mut p: StakePool = bytemuck::Zeroable::zeroed();
    p.set_discriminator();
    p
}

/// v3: a cooldown proposal silently DISABLED the HWM withdrawal floor.
#[test]
fn proposing_cooldown_leaves_hwm_floor_intact() {
    let mut p = pool();
    p.set_hwm_enabled(true);
    p.set_hwm_floor_bps(9_000); // 90% floor

    p.set_pending_cooldown_slots(216_000); // ~1 day

    assert!(
        p.hwm_enabled(),
        "cooldown proposal must not disable the HWM floor"
    );
    assert_eq!(
        p.hwm_floor_bps(),
        9_000,
        "cooldown proposal must not rewrite hwm_floor_bps"
    );
}

/// v3: an HWM refresh CLOBBERED the proposal slot, so the timelock read as long-elapsed.
#[test]
fn hwm_refresh_preserves_cooldown_timelock() {
    let mut p = pool();
    let proposed_at: u64 = 400_000_000;
    p.set_pending_cooldown_slots(216_000);
    p.set_cooldown_proposed_at_slot(proposed_at);

    // Any withdraw that refreshes the epoch HWM.
    p.set_epoch_high_water_tvl(1_000_000_000);
    p.set_hwm_last_epoch(0);

    assert_eq!(
        p.cooldown_proposed_at_slot(),
        proposed_at,
        "HWM refresh must not move the proposal slot — that is a timelock bypass"
    );
    assert_eq!(
        p.pending_cooldown_slots(),
        216_000,
        "HWM refresh must not move the pending value"
    );
}

/// v3: a cooldown proposal corrupted the HWM TVL that gates withdrawals.
#[test]
fn cooldown_proposal_preserves_hwm_tvl() {
    let mut p = pool();
    p.set_hwm_enabled(true);
    p.set_epoch_high_water_tvl(1_000_000_000);
    p.set_hwm_last_epoch(700);

    p.set_cooldown_proposed_at_slot(400_000_000);

    assert_eq!(
        p.epoch_high_water_tvl(),
        1_000_000_000,
        "proposal must not corrupt HWM TVL"
    );
    assert_eq!(
        p.hwm_last_epoch(),
        700,
        "proposal must not corrupt the HWM epoch"
    );
}

/// The discriminator, version byte and every other `_reserved` tenant must survive
/// both feature's writes — the collision was found because `_reserved` had no owner map.
#[test]
fn reserved_tenants_survive_both_features() {
    let mut p = pool();
    p.set_market_resolved(true);
    p.set_tranche_enabled(true);
    p.set_realized_junior_loss(12_345);
    p.set_asset_admin_burned(true);
    p.set_hwm_enabled(true);
    p.set_hwm_floor_bps(9_000);
    p.set_epoch_high_water_tvl(1_000_000_000);
    p.set_hwm_last_epoch(700);

    p.set_pending_cooldown_slots(u64::MAX);
    p.set_cooldown_proposed_at_slot(u64::MAX);

    assert!(p.validate_discriminator(), "discriminator must survive");
    assert_eq!(
        p.version(),
        StakePool::CURRENT_VERSION,
        "version byte must survive"
    );
    assert!(p.market_resolved());
    assert!(p.tranche_enabled());
    assert_eq!(p.realized_junior_loss(), 12_345);
    assert!(p.asset_admin_burned());
    assert!(p.hwm_enabled());
    assert_eq!(p.hwm_floor_bps(), 9_000);
    assert_eq!(p.epoch_high_water_tvl(), 1_000_000_000);
    assert_eq!(p.hwm_last_epoch(), 700);
}
