//! The ONE place stake pins the wrapper market-account layout.
//!
//! Stake never links the wrapper crate (its solana 1.18 graph does not resolve against
//! this crate's solana 2.2 graph), so every field it needs off a wrapper market slab is
//! read RAW at a fixed offset. Before v2.2 those offsets were hand-computed absolute
//! numbers repeated in `cpi.rs`, `state.rs` and five test files, and a layout change
//! (v2.2: engine `V16Config` +40 B) moved all of them at once. Two of the readers
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
//! `30b2ec20` (`feat/v22-band-rent`, PR #279), `V16_LAYOUT_DISCRIMINATOR = 19`.
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
/// `size_of::<MarketGroupV16HeaderAccount>()`. v2.1: 758. v2.2: 806
/// (`V16ConfigAccount` +40 B: band_bps, band_max_epoch_slots, band_max_pin_slots,
/// rent_max_e9_per_slot, band_max_positions_per_side [Wave B review, engine 30b2ec20]).
pub const MARKET_GROUP_LEN: usize = 806;
pub const V21_MARKET_GROUP_LEN: usize = 758;

/// Header-relative offset of `next_market_id` (the asset-generation frontier,
/// `ResolveMarket` tag 19). v2.1: 581; v2.2: 629 (after the grown config).
pub const GROUP_NEXT_MARKET_ID_OFF: usize = 629;
/// Header-relative offset of the engine `mode` byte (0 Live, 1 Resolved, 2 Recovery).
/// v2.1: 626; v2.2: 674.
pub const GROUP_MODE_OFF: usize = 674;
/// Header-relative offset of the engine `insurance` balance (u128 LE; the fund wrapper tag 41
/// withdraws at terminal). v2.2: 349 = market_group_id 32 + `V16ConfigAccount` 297 +
/// asset_slot_capacity 4 + vault 16. CLOSE-OUT RULE (2026-10-14, every v5 mode): read once, at
/// BindInsuranceAuthority, to record the creator's seed. `offset_of!` against engine
/// 3ce4cbd1 (`MarketGroupV16HeaderAccount`: size 806, mode 674, next_market_id 629, i.e. the
/// pinned layout); real-bytes pin `f9_fee_only_bind_records_creator_seed_from_real_wrapper`.
pub const GROUP_INSURANCE_OFF: usize = 349;
/// Header-relative `source_insurance_credit_reserved_total_atoms` (u128 LE): insurance reserved
/// for source credits, not the insurance authority's. Engine 3ce4cbd1 layout dump: 493.
pub const GROUP_INS_CREDIT_RESERVED_OFF: usize = 493;
/// Header-relative `insurance_domain_budget_remaining_total` (u128 LE): the BUDGETED slice of
/// insurance, the only part the insurance authority/operator can withdraw (wrapper tags 57/41).
/// Fee legs (protocol / LP / staker reserve / creator), reserved credit and unrouted rent are
/// all outside it (wrapper CloseSlab: `unbudgeted = I - reserved - budget - rent_unrouted`).
/// Engine 3ce4cbd1 layout dump: 509.
pub const GROUP_INS_BUDGET_TOTAL_OFF: usize = 509;
/// Header-relative `config.max_market_slots` (u32 LE; `V16ConfigAccount` offset 2 + the 32-byte
/// group id). M-1b: the close-out seed is recorded only on single-asset markets.
/// `offset_of!` against engine 3ce4cbd1: 34.
pub const GROUP_MAX_MARKET_SLOTS_OFF: usize = 34;
/// Header-relative engine `vault` (u128 LE). `offset_of!` against engine 3ce4cbd1: 333.
pub const GROUP_VAULT_OFF: usize = 333;
/// `AssetStateV16Account` (first field of the engine slot) offsets, engine 3ce4cbd1:
/// `stale_account_count_long` / `_short` (u64 LE). M-1b LOW: a stale K/F cohort carries a hidden
/// loss reservation the stake program cannot compute, so the bind fails closed while either > 0.
pub const ASSET_STALE_COUNT_LONG_OFF: usize = 337;
pub const ASSET_STALE_COUNT_SHORT_OFF: usize = 345;
/// `EngineAssetSlotV16Account` per-domain insurance budget / spent (u128 LE), engine 3ce4cbd1.
pub const SLOT_INS_BUDGET_LONG_OFF: usize = 627;
pub const SLOT_INS_BUDGET_SHORT_OFF: usize = 643;
pub const SLOT_INS_SPENT_LONG_OFF: usize = 659;
pub const SLOT_INS_SPENT_SHORT_OFF: usize = 675;

/// Fixed wrapper-owned region at the start of every asset slot (`Market.wrapper`).
pub const ASSET_ORACLE_WRAPPER_LEN: usize = 1024;
/// `AssetOracleProfileV16.insurance_authority` / `insurance_operator` within the asset's wrapper
/// region (4 x u8, u32, 5 x u16, u8, [u8; 5] = 24 B before them). Real-bytes pin:
/// `closeout_burn_requires_custody_and_rotate_back_clears_seed`.
pub const ASSET_INSURANCE_AUTHORITY_OFF: usize = 24;
pub const ASSET_INSURANCE_OPERATOR_OFF: usize = 56;
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
/// Engine `insurance` balance (u128 LE).
pub const MARKET_INSURANCE_OFF: usize = MARKET_GROUP_OFF + GROUP_INSURANCE_OFF;
pub const MARKET_INS_CREDIT_RESERVED_OFF: usize = MARKET_GROUP_OFF + GROUP_INS_CREDIT_RESERVED_OFF;
pub const MARKET_INS_BUDGET_TOTAL_OFF: usize = MARKET_GROUP_OFF + GROUP_INS_BUDGET_TOTAL_OFF;
pub const MARKET_MAX_MARKET_SLOTS_OFF: usize = MARKET_GROUP_OFF + GROUP_MAX_MARKET_SLOTS_OFF;
pub const MARKET_VAULT_OFF: usize = MARKET_GROUP_OFF + GROUP_VAULT_OFF;
/// Start of asset 0's engine slot (`Market.engine`, after the 1024-byte wrapper region).
pub const ASSET0_ENGINE_SLOT_OFF: usize = ASSET0_MARKET_ID_OFF;
pub const ASSET0_STALE_COUNT_LONG_OFF: usize = ASSET0_ENGINE_SLOT_OFF + ASSET_STALE_COUNT_LONG_OFF;
pub const ASSET0_STALE_COUNT_SHORT_OFF: usize = ASSET0_ENGINE_SLOT_OFF + ASSET_STALE_COUNT_SHORT_OFF;
pub const ASSET0_INS_BUDGET_LONG_OFF: usize = ASSET0_ENGINE_SLOT_OFF + SLOT_INS_BUDGET_LONG_OFF;
pub const ASSET0_INS_BUDGET_SHORT_OFF: usize = ASSET0_ENGINE_SLOT_OFF + SLOT_INS_BUDGET_SHORT_OFF;
pub const ASSET0_INS_SPENT_LONG_OFF: usize = ASSET0_ENGINE_SLOT_OFF + SLOT_INS_SPENT_LONG_OFF;
pub const ASSET0_INS_SPENT_SHORT_OFF: usize = ASSET0_ENGINE_SLOT_OFF + SLOT_INS_SPENT_SHORT_OFF;
pub const ASSET0_INSURANCE_AUTHORITY_OFF: usize = ASSET0_WRAPPER_START + ASSET_INSURANCE_AUTHORITY_OFF;
pub const ASSET0_INSURANCE_OPERATOR_OFF: usize = ASSET0_WRAPPER_START + ASSET_INSURANCE_OPERATOR_OFF;
/// Shortest market account that can hold the engine header (and so the `mode` byte).
pub const MIN_MARKET_ACCOUNT_LEN: usize = MARKET_GROUP_OFF + MARKET_GROUP_LEN;

// ── Value pins. Edit an input above without updating these and the build fails. ──
const _: () = assert!(MARKET_GROUP_OFF == 592);
const _: () = assert!(ASSET0_WRAPPER_START == 1398);
const _: () = assert!(ASSET0_MARKET_ID_OFF == 2422);
const _: () = assert!(ASSET0_AUTHORITY_EPOCH_OFF == 1982);
const _: () = assert!(ASSET0_INSURANCE_TOP_UP_OFF == 1894);
const _: () = assert!(ASSET0_BACKING_FEE_LONG_OFF == 1918);
const _: () = assert!(ASSET0_BACKING_FEE_SHORT_OFF == 1926);
const _: () = assert!(ASSET0_TRADE_FEE_OFF == 1934);
const _: () = assert!(MARKET_ASSET_GENERATION_FRONTIER_OFF == 1221);
const _: () = assert!(MARKET_MODE_OFF == 1266);
const _: () = assert!(MARKET_INSURANCE_OFF == 941);
const _: () = assert!(MARKET_INS_CREDIT_RESERVED_OFF == 1085);
const _: () = assert!(MARKET_INS_BUDGET_TOTAL_OFF == 1101);
const _: () = assert!(MARKET_MAX_MARKET_SLOTS_OFF == 626);
const _: () = assert!(MARKET_VAULT_OFF == 925);
const _: () = assert!(ASSET0_ENGINE_SLOT_OFF == 2422);
const _: () = assert!(ASSET0_STALE_COUNT_LONG_OFF == 2759);
const _: () = assert!(ASSET0_STALE_COUNT_SHORT_OFF == 2767);
const _: () = assert!(ASSET0_INS_BUDGET_LONG_OFF == 3049);
const _: () = assert!(ASSET0_INS_BUDGET_SHORT_OFF == 3065);
const _: () = assert!(ASSET0_INS_SPENT_LONG_OFF == 3081);
const _: () = assert!(ASSET0_INS_SPENT_SHORT_OFF == 3097);
const _: () = assert!(GROUP_MAX_MARKET_SLOTS_OFF + 4 <= MARKET_GROUP_LEN);
const _: () = assert!(ASSET0_INSURANCE_AUTHORITY_OFF == 1422);
const _: () = assert!(ASSET0_INSURANCE_OPERATOR_OFF == 1454);
const _: () = assert!(GROUP_INS_BUDGET_TOTAL_OFF + 16 <= MARKET_GROUP_LEN);
const _: () = assert!(ASSET_INSURANCE_OPERATOR_OFF + 32 <= ASSET_INSURANCE_TOP_UP_OFF);
const _: () = assert!(MIN_MARKET_ACCOUNT_LEN == 1398);
// Both header-field reads must lie INSIDE the header they are relative to.
const _: () = assert!(GROUP_NEXT_MARKET_ID_OFF + 8 <= MARKET_GROUP_LEN);
const _: () = assert!(GROUP_MODE_OFF < MARKET_GROUP_LEN);
const _: () = assert!(GROUP_INSURANCE_OFF + 16 <= MARKET_GROUP_LEN);

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
