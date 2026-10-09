//! Pins the proof-only shim constants of `kani/v5-units/src/shim_consts.rs` to the real stake
//! values (ordinary cargo test; no Kani). The wrapper-side values in the same file
//! (`G9_ALLOWLIST_TIMELOCK_SLOTS`, `CL_OFF_FEED_OWNER`, `SB_OFF_FEED_AUTHORITY`) are pinned by a
//! wrapper test, because the stake crate does not link the wrapper.
mod shim {
    #![allow(dead_code)]
    include!("../kani/v5-units/src/shim_consts.rs");
}

#[test]
fn kani_v5_units_shim_matches_stake_minimum_liquidity() {
    assert_eq!(shim::MINIMUM_LIQUIDITY, percolator_stake::state::MINIMUM_LIQUIDITY);
}

/// The wrapper-side values in the shim are pinned to these literals here and, against the real
/// wrapper constants, by `percolator-prog/tests/kani_shim_pin.rs`.
#[test]
fn kani_v5_units_shim_wrapper_literals() {
    assert_eq!(shim::G9_ALLOWLIST_TIMELOCK_SLOTS, 216_000);
    assert_eq!(shim::CL_OFF_FEED_OWNER, 10);
    assert_eq!(shim::SB_OFF_FEED_AUTHORITY, 8 + 2_048);
}
