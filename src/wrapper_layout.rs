//! The ONE place stake pins the wrapper market-account layout.
//!
//! Stake never links the wrapper crate (its solana 1.18 graph does not resolve against
//! this crate's solana 2.2 graph), so every field it needs off a wrapper market slab is
//! read RAW at a fixed offset. Before v2.2 those offsets were hand-computed absolute
//! numbers repeated in `cpi.rs`, `state.rs` and five test files, and a layout change
//! (v2.2: engine `V16Config` +32 B) moved all of them at once. Two of the readers
//! failed loudly (`AssetGenerationMismatch`, Custom(65), wrapper tag-65); the terminal
//! reader in `state.rs` would not have: it kept classifying the slab from a byte that
//! was no longer the engine `mode`.
//!
//! The structure here is deliberate. There are only THREE moving inputs:
//!
//!   * [`MARKET_GROUP_LEN`]: `size_of::<MarketGroupV16HeaderAccount>()`; the engine
//!     header that sits at [`MARKET_GROUP_OFF`] and places asset slot 0 after it;
//!   * [`GROUP_NEXT_MARKET_ID_OFF`] and [`GROUP_MODE_OFF`]: header-relative offsets of
//!     the two engine-header fields stake reads. They sit AFTER `V16ConfigAccount`, so
//!     they move whenever the config grows;
//!   * the wrapper's own per-asset profile offsets (`ASSET_*`), which live inside the
//!     fixed 1024-byte `ASSET_ORACLE_WRAPPER_LEN` slot and do not move with the engine.
//!
//! Every absolute offset below is DERIVED from those, then pinned by value in the
//! `const _` asserts at the bottom, so editing one input without the others is a
//! compile error rather than a silent misread. `tests/f9_wrapper_layout_pin.rs` and
//! `tests/wrapper_layout_v22_pin.rs` re-derive them against the real wrapper `.so` /
//! source.
//!
//! GROUND TRUTH (v2.2 Wave B): wrapper `dcccrypto/percolator-prog` `f576bffc`
//! (`feat/v22-wave-b`, PR #533), `VERSION = 19`, engine `dcccrypto/percolator`
//! `4ceac24a` (`feat/v22-band-rent`, PR #279), `V16_LAYOUT_DISCRIMINATOR = 19`.
//! Obtained with `core::mem::offset_of!` against the real wrapper/engine types
//! (a throwaway probe test, not committed). Layout 18 (v2.1) values are kept as
//! `V21_*` so the pin tests can prove the move.

/// Wrapper account header: magic u64, version u16, kind u8, pad (16 bytes).
pub const HEADER_LEN: usize = 16;
/// `WrapperConfigV16` (unchanged in v2.2).
pub const WRAPPER_CONFIG_LEN: usize = 576;

/// The wrapper account VERSION stake has pinned. Bumped 18 -> 19 with the engine
/// layout flag day (`V16_LAYOUT_DISCRIMINATOR` 18 -> 19). The wrapper stamps it in
/// every account header; stake refuses anything else (`UnsupportedWrapperLayout`).
pub const WRAPPER_VERSION: u16 = 19;

/// Start of the engine `MarketGroupV16HeaderAccount` inside a market account.
pub const MARKET_GROUP_OFF: usize = HEADER_LEN + WRAPPER_CONFIG_LEN;
/// `size_of::<MarketGroupV16HeaderAccount>()`. v2.1: 758. v2.2: 790
/// (`V16ConfigAccount` +32 B: band_bps, band_max_epoch_slots, band_max_pin_slots,
/// rent_max_e9_per_slot).
pub const MARKET_GROUP_LEN: usize = 790;
pub const V21_MARKET_GROUP_LEN: usize = 758;

/// Header-relative offset of `next_market_id` (the asset-generation frontier,
/// `ResolveMarket` tag 19). v2.1: 581; v2.2: 613 (after the grown config).
pub const GROUP_NEXT_MARKET_ID_OFF: usize = 613;
/// Header-relative offset of the engine `mode` byte (0 Live, 1 Resolved, 2 Recovery).
/// v2.1: 626; v2.2: 658.
pub const GROUP_MODE_OFF: usize = 658;

/// Fixed wrapper-owned region at the start of every asset slot (`Market.wrapper`).
pub const ASSET_ORACLE_WRAPPER_LEN: usize = 1024;
/// `AssetOracleProfileV16.insurance_top_up` within the asset's wrapper region.
pub const ASSET_INSURANCE_TOP_UP_OFF: usize = 496;
/// `AssetControlSequencesV16` within the asset's wrapper region (= profile length).
pub const ASSET_CONTROL_SEQUENCES_OFF: usize = 512;
/// Offsets inside `AssetControlSequencesV16`.
pub const CTRL_BACKING_FEE_LONG_OFF: usize = 8;
pub const CTRL_BACKING_FEE_SHORT_OFF: usize = 16;
pub const CTRL_TRADE_FEE_OFF: usize = 24;
pub const CTRL_AUTHORITY_EPOCH_OFF: usize = 72;

/// Start of asset slot 0 (`Market.wrapper`), directly after the engine header.
pub const ASSET0_WRAPPER_START: usize = MARKET_GROUP_OFF + MARKET_GROUP_LEN;
/// `AssetStateV16.market_id`: first field of the engine slot, which follows the
/// wrapper region. (v2.2 appended 112 B of band/rent state AFTER it; the first
/// field does not move relative to the slot.)
pub const ASSET0_MARKET_ID_OFF: usize = ASSET0_WRAPPER_START + ASSET_ORACLE_WRAPPER_LEN;
pub const ASSET0_INSURANCE_TOP_UP_OFF: usize = ASSET0_WRAPPER_START + ASSET_INSURANCE_TOP_UP_OFF;
pub const ASSET0_BACKING_FEE_LONG_OFF: usize =
    ASSET0_WRAPPER_START + ASSET_CONTROL_SEQUENCES_OFF + CTRL_BACKING_FEE_LONG_OFF;
pub const ASSET0_BACKING_FEE_SHORT_OFF: usize =
    ASSET0_WRAPPER_START + ASSET_CONTROL_SEQUENCES_OFF + CTRL_BACKING_FEE_SHORT_OFF;
pub const ASSET0_TRADE_FEE_OFF: usize =
    ASSET0_WRAPPER_START + ASSET_CONTROL_SEQUENCES_OFF + CTRL_TRADE_FEE_OFF;
pub const ASSET0_AUTHORITY_EPOCH_OFF: usize =
    ASSET0_WRAPPER_START + ASSET_CONTROL_SEQUENCES_OFF + CTRL_AUTHORITY_EPOCH_OFF;

/// Market-wide asset-generation frontier (`MarketGroupV16HeaderAccount.next_market_id`).
pub const MARKET_ASSET_GENERATION_FRONTIER_OFF: usize = MARKET_GROUP_OFF + GROUP_NEXT_MARKET_ID_OFF;
/// Engine `mode` byte.
pub const MARKET_MODE_OFF: usize = MARKET_GROUP_OFF + GROUP_MODE_OFF;
/// Shortest market account that can hold the engine header (and so the `mode` byte).
pub const MIN_MARKET_ACCOUNT_LEN: usize = MARKET_GROUP_OFF + MARKET_GROUP_LEN;

// ── Value pins. Edit an input above without updating these and the build fails. ──
const _: () = assert!(MARKET_GROUP_OFF == 592);
const _: () = assert!(ASSET0_WRAPPER_START == 1382);
const _: () = assert!(ASSET0_MARKET_ID_OFF == 2406);
const _: () = assert!(ASSET0_AUTHORITY_EPOCH_OFF == 1966);
const _: () = assert!(ASSET0_INSURANCE_TOP_UP_OFF == 1878);
const _: () = assert!(ASSET0_BACKING_FEE_LONG_OFF == 1902);
const _: () = assert!(ASSET0_BACKING_FEE_SHORT_OFF == 1910);
const _: () = assert!(ASSET0_TRADE_FEE_OFF == 1918);
const _: () = assert!(MARKET_ASSET_GENERATION_FRONTIER_OFF == 1205);
const _: () = assert!(MARKET_MODE_OFF == 1250);
const _: () = assert!(MIN_MARKET_ACCOUNT_LEN == 1382);
// Both header-field reads must lie INSIDE the header they are relative to.
const _: () = assert!(GROUP_NEXT_MARKET_ID_OFF + 8 <= MARKET_GROUP_LEN);
const _: () = assert!(GROUP_MODE_OFF < MARKET_GROUP_LEN);

/// True iff `data` carries the wrapper magic and EXACTLY the pinned header VERSION. Every raw
/// slab reader must call this before touching an offset in this module.
pub fn header_is_pinned(data: &[u8]) -> bool {
    const MAGIC: u64 = 0x5045_5243_5631_3600;
    match (data.get(0..8), data.get(8..10)) {
        (Some(m), Some(v)) => {
            u64::from_le_bytes(m.try_into().unwrap()) == MAGIC
                && u16::from_le_bytes(v.try_into().unwrap()) == WRAPPER_VERSION
        }
        _ => false,
    }
}
