//! v2.2 layout pin (wrapper VERSION 19 / engine layout 19; wrapper f576bffc, engine 4ceac24a).
//!
//! Wave B grew the engine config by 40 B, so the engine header (`MARKET_GROUP_LEN`) grew
//! 758 -> 806 and EVERY asset slot, plus the two header fields stake reads that sit after the
//! config, moved +40. The wrapper per-asset profile offsets (inside the fixed 1024 B wrapper
//! region) did not. This file pins the numbers by value and as a delta against the v2.1
//! values, so a future edit to one input of `wrapper_layout` cannot pass by also editing the
//! assert next to it. The real-bytes proof is `f9_wrapper_layout_pin` (real InitMarket +
//! ResolveMarket against the wrapper .so) and the CPI e2e suites (the wrapper rejects a wrong
//! `market_id` / `authority_epoch` / `intent_id` with Custom(65) / EngineStale).

use percolator_stake::{state, wrapper_layout as w};

// v2.1 (VERSION 18, engine layout 18) values, as shipped in cpi.rs / state.rs before v2.2.
const V21_ASSET0_WRAPPER_START: usize = 1350;
const V21_ASSET0_MARKET_ID_OFF: usize = 2374;
const V21_ASSET0_AUTHORITY_EPOCH_OFF: usize = 1934;
const V21_ASSET0_INSURANCE_TOP_UP_OFF: usize = 1846;
const V21_FRONTIER_OFF: usize = 1173;
const V21_BACKING_FEE_LONG_OFF: usize = 1870;
const V21_BACKING_FEE_SHORT_OFF: usize = 1878;
const V21_TRADE_FEE_OFF: usize = 1886;
const V21_MODE_OFF: usize = 1218;

#[test]
fn every_slab_offset_moved_by_exactly_the_config_growth() {
    let d = w::MARKET_GROUP_LEN - w::V21_MARKET_GROUP_LEN;
    assert_eq!(d, 48, "engine V16Config grew by 48 B in v2.2 (32 + two appended u64)");
    assert_eq!(w::ASSET0_WRAPPER_START, V21_ASSET0_WRAPPER_START + d);
    assert_eq!(w::ASSET0_MARKET_ID_OFF, V21_ASSET0_MARKET_ID_OFF + d);
    assert_eq!(w::ASSET0_AUTHORITY_EPOCH_OFF, V21_ASSET0_AUTHORITY_EPOCH_OFF + d);
    assert_eq!(w::ASSET0_INSURANCE_TOP_UP_OFF, V21_ASSET0_INSURANCE_TOP_UP_OFF + d);
    assert_eq!(w::ASSET0_BACKING_FEE_LONG_OFF, V21_BACKING_FEE_LONG_OFF + d);
    assert_eq!(w::ASSET0_BACKING_FEE_SHORT_OFF, V21_BACKING_FEE_SHORT_OFF + d);
    assert_eq!(w::ASSET0_TRADE_FEE_OFF, V21_TRADE_FEE_OFF + d);
    // The two header fields sit AFTER the grown config, so they move by the same 40.
    assert_eq!(w::MARKET_ASSET_GENERATION_FRONTIER_OFF, V21_FRONTIER_OFF + d);
    assert_eq!(w::MARKET_MODE_OFF, V21_MODE_OFF + d);
}

#[test]
fn v22_absolute_values() {
    assert_eq!(w::WRAPPER_VERSION, 19);
    assert_eq!(w::MARKET_GROUP_OFF, 592);
    assert_eq!(w::MARKET_GROUP_LEN, 806);
    assert_eq!(w::ASSET0_WRAPPER_START, 1398);
    assert_eq!(w::ASSET0_MARKET_ID_OFF, 2422);
    assert_eq!(w::ASSET0_AUTHORITY_EPOCH_OFF, 1982);
    assert_eq!(w::ASSET0_INSURANCE_TOP_UP_OFF, 1894);
    assert_eq!(w::MARKET_ASSET_GENERATION_FRONTIER_OFF, 1221);
    assert_eq!(w::MARKET_MODE_OFF, 1266);
    // A cap-1 market: header 592 + engine header 806 + one asset slot (1024 wrapper blob + 1573 engine slot = 2597: + 112 band/rent + 160 funding-scale drift tail).
    assert_eq!(w::MARKET_GROUP_OFF + w::MARKET_GROUP_LEN + 2629, 4027);
}

#[test]
fn state_and_cpi_consume_the_single_source() {
    assert_eq!(state::WRAPPER_SUPPORTED_VERSION, w::WRAPPER_VERSION);
    assert_eq!(state::WRAPPER_OFF_MODE, w::MARKET_MODE_OFF);
    assert_eq!(state::WRAPPER_MIN_MARKET_LEN, w::MIN_MARKET_ACCOUNT_LEN);
    // The v2.1 header version must NOT be accepted by the terminal reader.
    assert_ne!(state::WRAPPER_SUPPORTED_VERSION, 18);
}

/// Behavioural pin: a slab whose mode byte sits at the v2.1 offset (1218) and NOT at 1266 must
/// not read as Resolved. Under a stale-offset program this exact image is Resolved.
#[test]
fn terminal_reader_does_not_look_at_the_v21_mode_byte() {
    let mut d = vec![0u8; 3835];
    d[0..8].copy_from_slice(&state::WRAPPER_MAGIC.to_le_bytes());
    d[8..10].copy_from_slice(&state::WRAPPER_SUPPORTED_VERSION.to_le_bytes());
    d[state::WRAPPER_OFF_KIND] = state::WRAPPER_KIND_MARKET;
    d[V21_MODE_OFF] = 1; // a v2.1 reader would call this Resolved
    assert_eq!(state::read_wrapper_terminal(&d), state::WrapperTerminal::NotTerminal);
    d[V21_MODE_OFF] = 0;
    d[w::MARKET_MODE_OFF] = 1;
    assert_eq!(state::read_wrapper_terminal(&d), state::WrapperTerminal::Resolved);
}
