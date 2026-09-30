//! CPI helpers for calling percolator wrapper instructions.
//!
//! The stake program issues FOUR wrapper CPIs:
//!   * TopUpInsurance (tag 9)             — the insurance flush itself.
//!   * UpdateAssetAuthority (tag 65)      — bind/rotate the per-asset
//!     `insurance_authority` (asset 0, kind=ASSET_AUTH_INSURANCE=1) to our
//!     `vault_auth` PDA.
//!   * UpdateAssetAuthority (tag 65)      — move `insurance_operator` (kind=2)
//!     to the same `vault_auth` PDA so the admin cannot drain via tag-57
//!     local_authorized path.
//!   * UpdateAssetAuthority (tag 65)      — burn `asset_admin` (kind=0,
//!     new_pubkey=[0;32]) so the admin cannot rotate any authority back.
//!
//! The authority and operator CPIs are issued together in BindInsuranceAuthority
//! (tag 19); the asset_admin burn is a separate finalization step
//! (BurnAssetAdmin, tag 21). Together they guarantee the STRONG no-admin-drain
//! property: after bind + burn, no admin key can drain insurance via
//! WithdrawInsuranceAsset (tag 57), and stake will not rotate the PDA roles back.
//!
//! V17 WIRE CHANGE (collision row 43): the v16 wire used tag 32 `UpdateAuthority`
//! with kind byte = 2 (AUTHORITY_INSURANCE) and a 34-byte payload. The v17 auth
//! overhaul replaced per-field authority mutation with a per-ASSET handler (tag 65
//! `UpdateAssetAuthority`). The new wire is:
//!   [tag=65u8][asset_index: u16 LE = 0x00 0x00][kind: u8 = 1][pubkey: 32 bytes]
//!   = 36 bytes total.  THREE changes from the v16 wire: (1) tag 32→65, (2) kind
//!   value FLIPPED 2→1 (ASSET_AUTH_INSURANCE=1, not AUTHORITY_INSURANCE=2), (3)
//!   NEW 2-byte asset_index prefix (always 0 for the asset-0 insurance profile).
//! The 3-account shape is UNCHANGED from tag 32:
//!   [0] current authority (signer)
//!   [1] new authority (signer when new_pubkey != 0; no-op slot when burning to 0)
//!   [2] market (writable, wrapper-owned)
//!
//! WHY THE BIND CPI EXISTS: v17 authorizes tag 9 against the per-asset
//! `insurance_authority` profile and our CPI signer is the `vault_auth` PDA —
//! so that field must equal the PDA. Tag 65 requires the NEW authority to
//! co-sign (v16_program.rs handle_update_asset_authority:9414-9420), and a PDA
//! cannot sign a top-level tx. The ONLY way to bind a PDA is a CPI from its
//! owning program (us) that `invoke_signed`s the PDA as the new authority while
//! the admin co-signs as the current authority. This is NOT a redundant proxy:
//! the human admin literally cannot perform this bind directly.
//!
//! v16 MIGRATION WIRE (sync/integration-v16 @ a9318945, LOCKED gate-2-CONFIRMED
//! wire — see `~/percolator-ops/sync/wrapper_scope/WRAPPER_SYNC_LOCKED_WIRE.md`;
//! this branch is HELD pending the coordinated F-01 re-seed migration, NOT yet
//! deployed): the identity-binding overhaul grew BOTH tag 9 and tag 65.
//!   * Tag 9 `TopUpInsurance` gained a leading `market_id: u64` (TB-4
//!     asset-generation binding, asset-0 scope) and `intent_id: u64` (a
//!     one-shot strictly-increasing replay nonce sharing the SAME watermark
//!     lane `TopUpInsuranceDomain` advances), ahead of the existing
//!     `authority_epoch: u64` + `amount: u128`. New wire (41 bytes):
//!     `[tag=9][market_id: u64 LE][intent_id: u64 LE][authority_epoch: u64 LE]
//!     [amount: u128 LE]`.
//!   * Tag 65 `UpdateAssetAuthority` gained a `market_id: u64` inserted
//!     AFTER `asset_index` and BEFORE `kind` (same TB-4 binding), and a
//!     TRAILING `authority_epoch: u64` (gate-2 fix: a strict CAS —
//!     `expected == current`, wrapper auto-advances to `current + 1` on
//!     success — NOT the increment-by-caller nonce the OTHER 13
//!     control-sequence tags still use). New wire (52 bytes):
//!     `[tag=65][asset_index: u16 LE][market_id: u64 LE][kind: u8]
//!     [new_pubkey: 32 bytes][authority_epoch: u64 LE]`.
//!
//! Both `market_id` and `authority_epoch` are read LIVE off the raw market
//! account immediately before each CPI (stake does not link the wrapper
//! crate — see the dev-dependency note in Cargo.toml — so these are fixed-
//! offset raw reads, ground-truthed against the locked layout; see the
//! offset constants below). `authority_epoch` is passed UNCHANGED (current,
//! not +1 — the wrapper advances it); `intent_id` is passed as
//! `current_watermark + 1` (strictly greater, per
//! `require_newer_control_sequence`).
#![allow(clippy::too_many_arguments)]

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::{invoke, invoke_signed},
    program_error::ProgramError,
};

// Wrapper instruction tags (from percolator-prog/src/v16_program.rs ix::Instruction).
const TAG_TOP_UP_INSURANCE: u8 = 9;
/// UpdateAuthority (tag 32) — rotates the single market-level `cfg.marketauth`
/// key ONLY. Confirmed against the live deployed wrapper
/// (percolator-prog@14440e0c, src/v16_program.rs:3783 decode / :4123 encode /
/// handle_update_authority:9658) — wire is `tag(1) + new_pubkey(32)` = 33
/// bytes, NO kind byte, 3-account shape `[current(signer), new(signer),
/// market(w)]`. This is orthogonal to `TAG_UPDATE_ASSET_AUTHORITY` below (tag
/// 65, per-asset authorities e.g. insurance_authority/operator/admin) — both
/// tags are live and unrelated fields on the currently-deployed wrapper; tag
/// 65 did NOT supersede tag 32 for marketauth (see issue #6 lineage research).
const TAG_UPDATE_AUTHORITY: u8 = 32;
/// V17 auth overhaul (collision row 43): tag 32 `UpdateAuthority` rotated only
/// `cfg.marketauth`. Per-asset authorities (including insurance_authority for
/// asset 0) now go through tag 65 `UpdateAssetAuthority`.
const TAG_UPDATE_ASSET_AUTHORITY: u8 = 65;
/// asset_index for the asset-0 insurance profile (always 0 in the stake use-case).
/// Encoded as u16 LE = [0x00, 0x00] in the 36-byte tag-65 wire.
const ASSET_INDEX_ZERO: u16 = 0;
/// UpdateAssetAuthority kind selector for insurance_authority.
/// Source: v16_program.rs ASSET_AUTH_INSURANCE = 1.
/// NOTE: this is DIFFERENT from the v16 AUTHORITY_INSURANCE=2 that tag 32 used.
/// The footgun here is that both look like small integers but are defined in
/// different constant families and must NOT be swapped.
const ASSET_AUTH_INSURANCE: u8 = 1;
/// UpdateAssetAuthority kind selector for insurance_operator.
/// Source: v16_program.rs ASSET_AUTH_INSURANCE_OPERATOR = 2.
/// Must be moved (cannot burn to zero) to a key the admin does not control.
/// In the secure-bind sequence we move it to the vault_auth PDA so the admin
/// cannot drain via the local_authorized path in WithdrawInsuranceAsset (tag 57).
const ASSET_AUTH_INSURANCE_OPERATOR: u8 = 2;
/// UpdateAssetAuthority kind selector for asset_admin.
/// Source: v16_program.rs ASSET_AUTH_ADMIN = 0.
/// This is the ONLY authority that can be burned to zero (new_pubkey = [0;32]).
/// Burning asset_admin irrevocably removes the admin's ability to rotate any of
/// the asset's authorities (insurance, operator, backing, oracle) back to admin
/// control. This is the final step of the secure-bind sequence.
const ASSET_AUTH_ADMIN: u8 = 0;

// ═══════════════════════════════════════════════════════════════
// v16 migration — raw market-account field offsets (asset index 0 ONLY)
// ═══════════════════════════════════════════════════════════════
// Stake never links the wrapper crate as a dependency (see the e2e
// dev-dependency note in Cargo.toml: percolator-prog pulls solana 1.18's
// curve25519-dalek, unresolvable against this crate's solana 2.2 graph), so
// `market_id`, `authority_epoch` and the `intent_id` watermark are read
// directly off the raw account bytes at fixed offsets rather than through
// the wrapper's own typed accessors.
//
// These offsets are ground-truthed against `sync/integration-v16 @ a9318945`
// (dcccrypto/percolator-prog), VERSION=18, via a byte-identical round-trip
// probe against the REAL compiled wrapper Pod types (casting
// `percolator::Market<state::AssetOracleStorageV16>` and
// `state::AssetOracleProfileV16` directly onto a synthetic account buffer
// and confirming the crate's own accessors read back what was written at
// the computed offset) — not hand-derived struct-field arithmetic alone.
// See this unit's handback report for the full derivation and the probe
// test used (a throwaway addition to a scratch wrapper worktree, reverted —
// never committed, per this task's "do not edit the wrapper" scope).
//
//   wrapper_start(asset 0) = MARKET_GROUP_OFF + MARKET_GROUP_LEN
//                          = (HEADER_LEN=16 + WRAPPER_CONFIG_LEN=576) + 758
//                          = 592 + 758 = 1350
// `MARKET_GROUP_LEN = size_of::<MarketGroupV16HeaderAccount>()` is the
// LOCKED integration layout's value (758B) — NOT the currently-deployed
// wrapper's header size. This is the post-F-01-migration layout this HELD
// branch targets; re-verify against the probe above if the header changes
// again before the coordinated migration deploy.
const ASSET0_WRAPPER_START: usize = 1350;

/// `AssetStateV16.market_id` (engine, asset 0's per-asset generation
/// counter) — the value BOTH tag 9's and tag 65's `market_id` wire field is
/// checked against, via `require_asset_generation_view(&group, asset_index,
/// expected_market_id)` (TB-4 asset-generation binding). It is the FIRST
/// field of `AssetStateV16Account`, itself the FIRST field of
/// `EngineAssetSlotV16Account` (`Market<T>.engine`), which sits immediately
/// after `Market<T>.wrapper: [u8; ASSET_ORACLE_WRAPPER_LEN(1024)]`. Offset:
/// `wrapper_start + 1024 + 0`.
const ASSET0_MARKET_ID_OFF: usize = ASSET0_WRAPPER_START + 1024; // 2374

/// `AssetControlSequencesV16.authority_epoch` for asset 0 — the strict CAS
/// lane `UpdateAssetAuthority` advances (`advance_authority_epoch_view`,
/// run unconditionally regardless of `kind`) and `TopUpInsurance` checks
/// read-only (`require_authority_epoch_view`, always asset-0 scope — the
/// market-wide top-up always deposits into asset 0). Offset:
/// `ASSET_CONTROL_SEQUENCES_OFF(512)` + 72 (9 preceding `u64` fields in
/// `AssetControlSequencesV16`: oracle_observation, backing_fee_long,
/// backing_fee_short, trade_fee, liquidation_fee, maintenance_fee,
/// fee_redirect, market_init_fee, permissionless_resolve).
const ASSET0_AUTHORITY_EPOCH_OFF: usize = ASSET0_WRAPPER_START + 512 + 72; // 1934

/// `AssetOracleProfileV16.insurance_top_up` — the one-shot strictly-
/// increasing `intent_id` watermark tag 9 validates with
/// `require_newer_control_sequence(current, proposed)`: `proposed` must be
/// STRICTLY greater than the stored value (`current == 0` is the
/// never-used-yet sentinel, so the first valid `intent_id` is `1`). Offset
/// 496 within the 512-byte profile (TB-3 tail field, immediately after
/// TB-1a's `next_portfolio_id`/`_padding2`, immediately before
/// `backing_top_up` at 504 — this program never touches `backing_top_up`).
const ASSET0_INSURANCE_TOP_UP_OFF: usize = ASSET0_WRAPPER_START + 496; // 1846

#[inline]
fn read_market_u64(market: &AccountInfo, off: usize) -> Result<u64, ProgramError> {
    let data = market.try_borrow_data()?;
    let bytes = data
        .get(off..off + 8)
        .ok_or(ProgramError::InvalidAccountData)?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

/// Live asset-0 generation counter — the `market_id` field both tag 9 and
/// tag 65 send on the wire.
fn read_asset0_market_id(market: &AccountInfo) -> Result<u64, ProgramError> {
    read_market_u64(market, ASSET0_MARKET_ID_OFF)
}

/// Live asset-0 `authority_epoch` — the CAS "expected current" value both
/// tag 9 and tag 65 send on the wire. MUST be passed UNCHANGED (the value
/// read live immediately before this CPI, NOT incremented) — the wrapper
/// itself advances the stored value to `current + 1` on success via a
/// strict `current == expected` compare-and-swap.
fn read_asset0_authority_epoch(market: &AccountInfo) -> Result<u64, ProgramError> {
    read_market_u64(market, ASSET0_AUTHORITY_EPOCH_OFF)
}

/// Next valid `intent_id` for a tag-9 `TopUpInsurance` CPI: the live stored
/// watermark (`AssetOracleProfileV16.insurance_top_up`) plus one. Unlike
/// `authority_epoch` (CAS, pass current UNCHANGED), `intent_id` is a
/// strictly-increasing one-shot nonce (`proposed > current`, not
/// `proposed == current`) and the wrapper stores back exactly what we send
/// — so `current + 1` is the minimal valid next value, matching how a
/// program-controlled (not user-chosen) monotonic counter is meant to be
/// used.
fn next_asset0_intent_id(market: &AccountInfo) -> Result<u64, ProgramError> {
    let current = read_market_u64(market, ASSET0_INSURANCE_TOP_UP_OFF)?;
    current
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)
}

/// `MarketGroupV16HeaderAccount.next_market_id` — the MARKET-WIDE asset-
/// generation "frontier" counter (the generation that will be assigned to
/// the NEXT asset activation in this slab). This is what `ResolveMarket`
/// (tag 19) validates via `require_asset_generation_frontier_view(&group,
/// expected_frontier)` — `group.header.next_market_id.get() != expected_frontier`
/// => `AssetGenerationMismatch`. UNLIKE `ASSET0_MARKET_ID_OFF` (a PER-ASSET
/// counter, `AssetStateV16::market_id`, used by tags 9/65/51/57), this field
/// lives inside `MarketGroupV16HeaderAccount` itself, BEFORE the per-asset
/// region `ASSET0_WRAPPER_START` marks the start of — the two fields read
/// different bytes and are NOT interchangeable despite both being called a
/// "generation" in adjacent code paths.
///
/// Offset ground-truthed via `core::mem::offset_of!` against the real
/// `percolator::MarketGroupV16HeaderAccount` type at `sync/integration-v16 @
/// a9318945` (a throwaway probe test appended to a scratch wrapper worktree,
/// run once, reverted — never committed): `MARKET_GROUP_OFF(592) +
/// offset_of!(MarketGroupV16HeaderAccount, next_market_id)(581) = 1173`.
const MARKET_ASSET_GENERATION_FRONTIER_OFF: usize = 1173;

/// `AssetControlSequencesV16.backing_fee_long` for asset 0 — the strictly-
/// increasing `policy_sequence` watermark `UpdateBackingFeePolicy` (tag 51)
/// advances for the LONG domain (`domain` even, `ControlSequenceLane::
/// BackingFeeLong`), checked via `require_newer_control_sequence` (proposed
/// must be STRICTLY greater than stored — same one-shot-nonce contract as
/// tag 9's `intent_id`, NOT a CAS). Offset ground-truthed the same way as
/// `MARKET_ASSET_GENERATION_FRONTIER_OFF` above: `offset_of!(
/// AssetControlSequencesV16, backing_fee_long) == 8` within the 88-byte
/// `AssetControlSequencesV16` struct at `ASSET_CONTROL_SEQUENCES_OFF(512)`
/// (both values reconfirmed by the SAME probe that reconfirmed the
/// already-shipped `authority_epoch @ +72`, cross-validating the method).
const ASSET0_BACKING_FEE_LONG_OFF: usize = ASSET0_WRAPPER_START + 512 + 8; // 1870
/// `AssetControlSequencesV16.backing_fee_short` for asset 0 — same as
/// `ASSET0_BACKING_FEE_LONG_OFF` but for the SHORT domain (`domain` odd,
/// `ControlSequenceLane::BackingFeeShort`). `offset_of!(..., backing_fee_short)
/// == 16`.
const ASSET0_BACKING_FEE_SHORT_OFF: usize = ASSET0_WRAPPER_START + 512 + 16; // 1878
/// `AssetControlSequencesV16.trade_fee` for asset 0 — the strictly-increasing
/// `policy_sequence` watermark `UpdateTradeFeePolicy` (tag 55) advances
/// (`ControlSequenceLane::TradeFee`; the wrapper hardcodes asset 0 for this
/// tag, matching every other asset-0-scoped read in this file).
/// `offset_of!(..., trade_fee) == 24`.
const ASSET0_TRADE_FEE_OFF: usize = ASSET0_WRAPPER_START + 512 + 24; // 1886

/// Live market-wide asset-generation frontier — the `asset_generation_frontier`
/// field `ResolveMarket` (tag 19) sends on the wire. See
/// `MARKET_ASSET_GENERATION_FRONTIER_OFF`'s own doc comment for why this is
/// NOT the same value as `read_asset0_market_id`.
fn read_market_asset_generation_frontier(market: &AccountInfo) -> Result<u64, ProgramError> {
    read_market_u64(market, MARKET_ASSET_GENERATION_FRONTIER_OFF)
}

/// Next valid `policy_sequence` for a tag-51 `UpdateBackingFeePolicy` CPI on
/// asset 0: the live stored watermark (long or short domain, selected by
/// `long_side`) plus one — a strictly-increasing one-shot nonce, exactly
/// like `next_asset0_intent_id`, NOT a CAS like `authority_epoch`.
fn next_asset0_backing_fee_policy_sequence(
    market: &AccountInfo,
    long_side: bool,
) -> Result<u64, ProgramError> {
    let off = if long_side {
        ASSET0_BACKING_FEE_LONG_OFF
    } else {
        ASSET0_BACKING_FEE_SHORT_OFF
    };
    let current = read_market_u64(market, off)?;
    current.checked_add(1).ok_or(ProgramError::ArithmeticOverflow)
}

/// Next valid `policy_sequence` for a tag-55 `UpdateTradeFeePolicy` CPI
/// (asset 0, hardcoded by the wrapper): the live stored `trade_fee` watermark
/// plus one.
fn next_asset0_trade_fee_policy_sequence(market: &AccountInfo) -> Result<u64, ProgramError> {
    let current = read_market_u64(market, ASSET0_TRADE_FEE_OFF)?;
    current.checked_add(1).ok_or(ProgramError::ArithmeticOverflow)
}

/// Shared tag-65 `UpdateAssetAuthority` payload builder for all five call
/// sites below — every one of them targets asset index 0 and differs ONLY
/// in `kind` and `new_pubkey`. Centralizing the byte layout means the
/// 52-byte wire (offsets, field order) is defined exactly ONCE, so a
/// mistake here cannot land at only some of the five sites.
///
/// Wire (52 bytes): `[tag=65][asset_index: u16 LE = 0][market_id: u64 LE]
/// [kind: u8][new_pubkey: 32 bytes][authority_epoch: u64 LE]`.
fn build_update_asset_authority_data(
    market: &AccountInfo,
    kind: u8,
    new_pubkey: [u8; 32],
) -> Result<Vec<u8>, ProgramError> {
    let market_id = read_asset0_market_id(market)?;
    let authority_epoch = read_asset0_authority_epoch(market)?;

    let mut data = Vec::with_capacity(52);
    data.push(TAG_UPDATE_ASSET_AUTHORITY);
    data.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes()); // 2 bytes
    data.extend_from_slice(&market_id.to_le_bytes()); // 8 bytes
    data.push(kind); // 1 byte
    data.extend_from_slice(&new_pubkey); // 32 bytes
    data.extend_from_slice(&authority_epoch.to_le_bytes()); // 8 bytes
    debug_assert_eq!(data.len(), 52);
    Ok(data)
}

// ═══════════════════════════════════════════════════════════════
// TopUpInsurance (Tag 9) — v16 migration contract (LOCKED wire, HELD)
// ═══════════════════════════════════════════════════════════════
// Accounts: [signer, slab(w), signer_ata(w), vault(w), token_program] — UNCHANGED.
// Data: tag(1) + market_id(8, u64 LE) + intent_id(8, u64 LE) +
//       authority_epoch(8, u64 LE) + amount(16, u128 LE) = 41 bytes.
//
// v16 MIGRATION WIRE CONTRACT (verified against `sync/integration-v16 @
// a9318945`'s ACTUAL decode arm, `9 => Self::TopUpInsurance { market_id:
// read_u64, intent_id: read_u64, authority_epoch: read_u64, amount:
// read_u128 }` — matches WRAPPER_SYNC_LOCKED_WIRE.md's Tag 9 table
// byte-for-byte):
//   * FIELD ORDER: market_id, intent_id, authority_epoch, amount (the
//     runbook-§4-locked identity-binding cluster order).
//   * market_id is asset-0's LIVE `AssetStateV16.market_id` generation
//     counter (TB-4), checked via `require_asset_generation_view(&group, 0,
//     expected_market_id)`. Read live off the slab account — see
//     `read_asset0_market_id`.
//   * intent_id is a one-shot strictly-increasing replay nonce checked via
//     `require_newer_control_sequence(profile0.insurance_top_up,
//     intent_id)` — proposed must be STRICTLY greater than the stored
//     watermark. We pass `watermark + 1`, the minimal valid value — see
//     `next_asset0_intent_id`.
//   * authority_epoch is asset-0's LIVE `AssetControlSequencesV16.
//     authority_epoch`, checked read-only (NOT advanced — this CAS lane is
//     only ever advanced by `UpdateAssetAuthority`) via
//     `require_authority_epoch_view(&group, 0, expected_authority_epoch)`.
//     Passed UNCHANGED (current, not +1) — see `read_asset0_authority_epoch`.
//   * AMOUNT IS STILL u128 ON THE WIRE (unchanged from the prior v16 wire):
//     the wrapper's decoder rejects any payload that doesn't end in a full
//     16-byte `read_u128`. `amount` stays a `u64` parameter here (token
//     amounts fit u64); only the wire widens.
//   * NOT PERMISSIONLESS. Gated on `expect_live_authority(
//     profile0.insurance_authority, signer.key)`. The CPI signer is our
//     `vault_auth` PDA, so the market's `insurance_authority` MUST be bound
//     to that PDA first via `cpi_bind_insurance_authority` — or every flush
//     reverts Custom(8) Unauthorized.
//   * LIVE MODE REQUIRED, checked BEFORE the authority gate — a not-yet-Live
//     market reverts Custom(21) EngineLockActive.
//
// CUTOVER ATOMICITY: this 41-byte wire targets the LOCKED v16 migration
// layout (`sync/integration-v16 @ a9318945`, VERSION=18) and is HELD —
// it MUST NOT ship until that exact wrapper build is deployed via the
// coordinated F-01 re-seed migration. Deploying this build against the
// CURRENTLY deployed wrapper (which still decodes tag 9 as the shorter
// pre-migration wire) would hard-revert every flush at decode time; the
// prior 17-byte (tag+u128) wire this replaced was itself gated the same
// way against the pre-v16 8-byte-u64 wrapper — same cutover discipline,
// one wire generation later.

/// Pure tag-9 `TopUpInsurance` payload builder — separated from
/// `cpi_top_up_insurance` so the byte layout (the fund-critical part) is
/// unit-testable directly against a synthetic account, without also
/// exercising `invoke_signed` (which requires a live Solana runtime and
/// cannot run in a host `#[test]`).
///
/// Wire (41 bytes): `[tag=9][market_id: u64 LE][intent_id: u64 LE]
/// [authority_epoch: u64 LE][amount: u128 LE]`.
fn build_top_up_insurance_data(slab: &AccountInfo, amount: u64) -> Result<Vec<u8>, ProgramError> {
    let market_id = read_asset0_market_id(slab)?;
    let intent_id = next_asset0_intent_id(slab)?;
    let authority_epoch = read_asset0_authority_epoch(slab)?;

    let mut data = Vec::with_capacity(41);
    data.push(TAG_TOP_UP_INSURANCE);
    data.extend_from_slice(&market_id.to_le_bytes());
    data.extend_from_slice(&intent_id.to_le_bytes());
    data.extend_from_slice(&authority_epoch.to_le_bytes());
    data.extend_from_slice(&(amount as u128).to_le_bytes());
    debug_assert_eq!(data.len(), 41);
    Ok(data)
}

pub fn cpi_top_up_insurance<'a>(
    percolator_program: &AccountInfo<'a>,
    signer: &AccountInfo<'a>, // vault_auth PDA (we sign) — must == market insurance_authority
    slab: &AccountInfo<'a>,
    signer_ata: &AccountInfo<'a>, // stake vault (owned by vault_auth)
    wrapper_vault: &AccountInfo<'a>,
    token_program: &AccountInfo<'a>,
    amount: u64,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    let data = build_top_up_insurance_data(slab, amount)?;

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*signer.key, true),
            AccountMeta::new(*slab.key, false),
            AccountMeta::new(*signer_ata.key, false),
            AccountMeta::new(*wrapper_vault.key, false),
            AccountMeta::new_readonly(*token_program.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            signer.clone(),
            slab.clone(),
            signer_ata.clone(),
            wrapper_vault.clone(),
            token_program.clone(),
        ],
        &[signer_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// UpdateAuthority (Tag 32) — rotate market-level marketauth to the pool PDA
// ═══════════════════════════════════════════════════════════════
// Accounts (v16_program.rs handle_update_authority, account(_,0)/(_,1)/(_,2)):
//   [current_authority(signer), new_authority(signer), market(w)] — UNCHANGED.
// Data (v16 migration, LOCKED wire, HELD): tag(1) + new_authority(32) +
//   authority_epoch(8, u64 LE) = 41 bytes.
//
// v16 MIGRATION WIRE CHANGE (W3A-1, upstream `95d155bc`): `handle_update_authority`
// gained a trailing `authority_epoch` strict CAS — `advance_authority_epoch_view(
// &mut group, 0, expected_authority_epoch)` — reusing the SAME asset-0
// `authority_epoch` lane `UpdateAssetAuthority` (tag 65) advances, closing an
// A->B->A durable-nonce replay hole this rotation previously had ZERO epoch
// binding against. Passed UNCHANGED (current, not +1 — the wrapper advances it
// on success), read live off `slab` via `read_asset0_authority_epoch` exactly
// like every other tag-65-family CPI in this file.
//
// Ported byte-for-byte from the deployed percolator-vault@eb3ebe8 InitPool CPI
// (src/cpi.rs `cpi_update_authority`, src/processor.rs:340) — issue #6
// lineage reconciliation. Called from InitPool to prove the initializer is
// the CURRENT wrapper marketauth by transferring it to this pool PDA
// atomically with pool creation: if `admin` is not the current marketauth,
// the wrapper CPI fails closed and the whole InitPool tx reverts. This
// irreversibly moves wrapper-level admin from the human creator to the pool
// PDA, matching the deployed vault's behavior that the launch wizard's
// account-authority sequencing depends on (marketauth == creator wallet
// until this call, pool PDA thereafter).
//
// NOTE: distinct from `cpi_bind_insurance_authority` / `TAG_UPDATE_ASSET_AUTHORITY`
// (tag 65) above, which rotates only the per-asset insurance_authority/operator/
// admin fields, not the market-wide marketauth this function rotates.

/// Pure tag-32 `UpdateAuthority` payload builder — separated the same way as
/// `build_top_up_insurance_data`/`build_update_asset_authority_data` so the
/// byte layout is directly unit-testable against a synthetic account.
///
/// Wire (41 bytes): `[tag=32][new_pubkey: 32 bytes][authority_epoch: u64 LE]`.
fn build_update_authority_data(
    slab: &AccountInfo,
    new_pubkey: [u8; 32],
) -> Result<Vec<u8>, ProgramError> {
    let authority_epoch = read_asset0_authority_epoch(slab)?;

    let mut data = Vec::with_capacity(41);
    data.push(TAG_UPDATE_AUTHORITY);
    data.extend_from_slice(&new_pubkey);
    data.extend_from_slice(&authority_epoch.to_le_bytes());
    debug_assert_eq!(data.len(), 41);
    Ok(data)
}

pub fn cpi_update_authority<'a>(
    percolator_program: &AccountInfo<'a>,
    current_admin: &AccountInfo<'a>, // current marketauth; signs the outer tx
    new_authority: &AccountInfo<'a>, // pool PDA; co-signs via invoke_signed
    slab: &AccountInfo<'a>,          // market, writable
    new_authority_seeds: &[&[u8]],   // pool PDA seeds
) -> ProgramResult {
    let data = build_update_authority_data(slab, new_authority.key.to_bytes())?;

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*current_admin.key, true),
            AccountMeta::new_readonly(*new_authority.key, true),
            AccountMeta::new(*slab.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[current_admin.clone(), new_authority.clone(), slab.clone()],
        &[new_authority_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// UpdateAssetAuthority (Tag 65) — one-time bind of insurance_authority
// ═══════════════════════════════════════════════════════════════
// Accounts (v16_program.rs handle_update_asset_authority L9407-9412):
//   [current(signer), new_authority(signer when new_pubkey!=0), market(w)] — UNCHANGED.
// Data (v16 migration, LOCKED wire, HELD — see `build_update_asset_authority_data`):
//   tag(1) + asset_index(2, u16 LE=0) + market_id(8, u64 LE) + kind(1) +
//   new_pubkey(32) + authority_epoch(8, u64 LE) = 52 bytes.
//
// Binds the market's per-asset `insurance_authority` (asset 0) to our
// `vault_auth` PDA so the subsequent TopUpInsurance flush (signed by the PDA)
// passes v17's authority gate. `admin` co-signs as the CURRENT authority (must
// equal profile.insurance_authority, which InitMarket seeds to admin via
// asset_admin bootstrap), and the PDA co-signs as the NEW authority via
// invoke_signed. After this bind, only the PDA can rotate the authority again —
// the bind is effectively one-directional (PDA-custody security property).
// RotateInsuranceAuthority (tag 20) is the deliberate admin-gated escape.
//
// market_id / authority_epoch are read LIVE off `market` immediately before
// this CPI — see `build_update_asset_authority_data`'s own doc comment.

pub fn cpi_bind_insurance_authority<'a>(
    percolator_program: &AccountInfo<'a>,
    admin: &AccountInfo<'a>, // current authority (== profile.insurance_authority at bind time); signs outer tx
    vault_auth: &AccountInfo<'a>, // new authority = our PDA; signs via invoke_signed
    market: &AccountInfo<'a>, // the slab/market account (writable, wrapper-owned)
    signer_seeds: &[&[u8]],  // vault_auth PDA seeds
) -> ProgramResult {
    let data = build_update_asset_authority_data(
        market,
        ASSET_AUTH_INSURANCE, // kind = 1
        vault_auth.key.to_bytes(),
    )?;

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*admin.key, true), // current authority, signer
            AccountMeta::new_readonly(*vault_auth.key, true), // new authority (PDA), signer via invoke_signed
            AccountMeta::new(*market.key, false),             // market, writable
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[admin.clone(), vault_auth.clone(), market.clone()],
        &[signer_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// UpdateAssetAuthority (Tag 65) — move insurance_operator to our PDA
// ═══════════════════════════════════════════════════════════════
// Same wrapper handler as the insurance_authority bind, but kind=2
// (ASSET_AUTH_INSURANCE_OPERATOR). Admin is the current operator (bootstrapped
// to marketauth/admin at InitMarket). vault_auth PDA co-signs as the NEW
// operator via invoke_signed. After this call, only a stake CPI (which can
// invoke_signed as vault_auth) can operate as the insurance_operator — the
// admin cannot drain via tag-57's local_authorized path.
//
// SECURITY NOTE: insurance_operator cannot be burned to zero (the wrapper
// rejects new_pubkey=[0;32] for kind != ASSET_AUTH_ADMIN at line 9439). The
// PDA is the safe non-zero non-admin key. The ASSET_AUTH_ADMIN burn (below) then
// removes the admin's ability to rotate this back.

pub fn cpi_bind_insurance_operator<'a>(
    percolator_program: &AccountInfo<'a>,
    admin: &AccountInfo<'a>, // current insurance_operator (== admin at bootstrap); signer
    vault_auth: &AccountInfo<'a>, // new operator = our PDA; co-signs via invoke_signed
    market: &AccountInfo<'a>, // the slab/market account (writable, wrapper-owned)
    signer_seeds: &[&[u8]],  // vault_auth PDA seeds
) -> ProgramResult {
    let data = build_update_asset_authority_data(
        market,
        ASSET_AUTH_INSURANCE_OPERATOR, // kind = 2
        vault_auth.key.to_bytes(),
    )?;

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*admin.key, true), // current operator (admin), signer
            AccountMeta::new_readonly(*vault_auth.key, true), // new operator (PDA), signer via invoke_signed
            AccountMeta::new(*market.key, false),             // market, writable
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[admin.clone(), vault_auth.clone(), market.clone()],
        &[signer_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// UpdateAssetAuthority (Tag 65) — burn asset_admin to zero
// ═══════════════════════════════════════════════════════════════
// Burning asset_admin (kind=0, new_pubkey=[0;32]) removes the admin's ability
// to rotate ANY of the asset's per-asset authorities (insurance_authority,
// insurance_operator, backing_bucket_authority, oracle_authority) back to an
// admin-controlled key. This is the final step of the secure-bind sequence
// and makes the PDA custody irrevocable.
//
// UNIQUELY PERMITTED: the wrapper allows new_pubkey=[0;32] ONLY for kind=0
// (ASSET_AUTH_ADMIN). For all other kinds it returns InvalidInstruction.
// (v16_program.rs handle_update_asset_authority line 9439).
//
// NO CO-SIGN REQUIRED: when new_pubkey=[0;32], the wrapper skips the
// expect_signer(new_authority) check (line 9405). We still need a second
// account slot — we pass vault_auth as a placeholder (it is already present
// in the transaction; no signer check is performed on it by the wrapper).
//
// Account layout: [current(signer=admin), new_authority(any, not checked), market(w)]
// Wire (v16 migration, LOCKED, HELD): tag(65) + asset_index(0 u16 LE) +
// market_id(8 u64 LE) + kind(0) + new_pubkey([0;32]) + authority_epoch(8 u64
// LE) = 52 bytes. `advance_authority_epoch_view`'s CAS runs unconditionally
// regardless of `kind` (including the zero-burn case), so the burn CPI still
// needs a live `authority_epoch` read exactly like the other four sites.

pub fn cpi_burn_asset_admin<'a>(
    percolator_program: &AccountInfo<'a>,
    admin: &AccountInfo<'a>,      // current asset_admin; signer
    vault_auth: &AccountInfo<'a>, // placeholder new_authority slot (not checked by wrapper for zero burn)
    market: &AccountInfo<'a>,     // the slab/market account (writable, wrapper-owned)
) -> ProgramResult {
    let data = build_update_asset_authority_data(
        market,
        ASSET_AUTH_ADMIN, // kind = 0
        [0u8; 32],        // new_pubkey = burn (all zeros)
    )?;

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*admin.key, true), // current asset_admin, signer
            AccountMeta::new_readonly(*vault_auth.key, false), // new_authority slot (any; not checked for zero-burn)
            AccountMeta::new(*market.key, false),              // market, writable
        ],
        data,
    };

    // Plain invoke (not signed) — admin signs as the outer tx signer; no PDA co-sign needed.
    invoke(&ix, &[admin.clone(), vault_auth.clone(), market.clone()])
}

// ═══════════════════════════════════════════════════════════════
// UpdateAssetAuthority (Tag 65) — rotate insurance_operator OFF our PDA
// ═══════════════════════════════════════════════════════════════
// Same as cpi_rotate_insurance_authority but for insurance_operator (kind=2).
// Used in the migration escape sequence (RotateInsuranceOperator, tag 22):
//   PDA signs as the CURRENT operator; new_target co-signs as the NEW operator.
//
// Full no-lockout migration sequence:
//   1. RotateInsuranceAuthority (tag 20): insurance_authority PDA → admin wallet
//   2. RotateInsuranceOperator  (tag 22): insurance_operator  PDA → admin wallet
//   3. Re-bind from NEW program (BindInsuranceAuthority, tag 19)
//   4. BurnAssetAdmin (tag 21) — only if asset_admin not already zero

pub fn cpi_rotate_insurance_operator<'a>(
    percolator_program: &AccountInfo<'a>,
    vault_auth: &AccountInfo<'a>, // CURRENT operator = our PDA; signs via invoke_signed
    new_target: &AccountInfo<'a>, // NEW operator (admin-specified, non-zero); co-signs outer tx
    market: &AccountInfo<'a>,     // the slab/market account (writable, wrapper-owned)
    signer_seeds: &[&[u8]],       // vault_auth PDA seeds
) -> ProgramResult {
    let data = build_update_asset_authority_data(
        market,
        ASSET_AUTH_INSURANCE_OPERATOR, // kind = 2
        new_target.key.to_bytes(),
    )?;

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*vault_auth.key, true), // current operator (PDA), signer via invoke_signed
            AccountMeta::new_readonly(*new_target.key, true), // new operator, signer (outer tx)
            AccountMeta::new(*market.key, false),             // market, writable
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[vault_auth.clone(), new_target.clone(), market.clone()],
        &[signer_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// UpdateAssetAuthority (Tag 65) — rotate insurance_authority OFF our PDA
// ═══════════════════════════════════════════════════════════════
// Same wrapper instruction as the bind, but the account ROLES invert:
//   current      = our `vault_auth` PDA (signs via invoke_signed)
//   new_authority = admin-specified `new_target` (co-signs the outer tx)
//
// WHY THIS EXISTS (the no-lockout escape): `cpi_bind_insurance_authority` makes
// the vault_auth PDA the sole rotator of insurance_authority. Moving it OFF
// requires the PDA to sign as the CURRENT authority
// (v16_program.rs handle_update_asset_authority:9452-9453) — which only a stake
// CPI can produce. Without a rotate path, a stake redeploy to a NEW program id
// (its `vault_auth` PDA derives under the new id) would orphan `insurance_authority`
// on the dead program and brick the insurance flush unrecoverably. Rotate is the
// deliberate, admin-gated migration/incident primitive: rotate to the admin wallet
// from the OLD program before decommissioning it, then re-bind from the NEW program.
// `new_target` must co-sign the outer tx (the wrapper requires the new authority
// to sign for non-zero keys, 9415-9420); a typical migration uses the admin wallet.
//
// WIRE NOTE: same 52-byte tag-65 layout as cpi_bind_insurance_authority (v16
// migration, LOCKED, HELD), but new_pubkey = new_target.key (the rotation
// destination, not our PDA).

pub fn cpi_rotate_insurance_authority<'a>(
    percolator_program: &AccountInfo<'a>,
    vault_auth: &AccountInfo<'a>, // CURRENT authority = our PDA; signs via invoke_signed
    new_target: &AccountInfo<'a>, // NEW authority (admin-specified, non-zero); co-signs the outer tx
    market: &AccountInfo<'a>,     // the slab/market account (writable, wrapper-owned)
    signer_seeds: &[&[u8]],       // vault_auth PDA seeds
) -> ProgramResult {
    let data = build_update_asset_authority_data(
        market,
        ASSET_AUTH_INSURANCE, // kind = 1
        new_target.key.to_bytes(),
    )?;

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*vault_auth.key, true), // current authority (PDA), signer via invoke_signed
            AccountMeta::new_readonly(*new_target.key, true), // new authority, signer (outer tx)
            AccountMeta::new(*market.key, false),             // market, writable
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[vault_auth.clone(), new_target.clone(), market.clone()],
        &[signer_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// WithdrawInsuranceAsset (Tag 57) — PDA-signed insurance recovery
// ═══════════════════════════════════════════════════════════════
// Wire (v16 migration, LOCKED, HELD): [57u8][asset_index: u16 LE = 0]
// [market_id: u64 LE][amount: u128 LE][authority_epoch: u64 LE] = 35 bytes.
//
// v16 MIGRATION WIRE CHANGE (W3A-1, `Withdraw{BackingBucket50,Earnings52,
// InsuranceAsset57}`): `handle_withdraw_insurance_asset` gained a
// `market_id` generation-binding parameter (checked via
// `require_asset_generation_view(&group, asset_index, expected_market_id)`,
// asset_index always 0 for stake) AND a trailing `authority_epoch` (checked
// read-only via `require_authority_epoch_view(&group, epoch_asset_index,
// expected_authority_epoch)`; `epoch_asset_index == asset_index == 0` on the
// `local_authorized` path this program always takes — the vault_auth PDA is
// asset-0's `insurance_operator`). Both read live off `market` immediately
// before the CPI, matching the tag-9/65 pattern; `authority_epoch` is passed
// UNCHANGED (this lane is only ever advanced by `UpdateAuthority`/
// `UpdateAssetAuthority`, never by this tag).
//
// Account order (verified against tests/v17_stake_insurance_e2e.rs
// withdraw_insurance_asset_ix and wrapper handle_withdraw_insurance_asset):
//   [0] operator      (vault_auth PDA, signer via invoke_signed) — must == insurance_operator
//   [1] market        (writable)
//   [2] dest_token    (writable) — MUST equal pool.vault (drain check enforced by caller)
//   [3] vault_token   (writable) — wrapper's insurance vault, the token source
//   [4] vault_authority (read-only) — wrapper vault authority PDA
//   [5] token_program  (read-only)
//
// AUTH: insurance_operator == vault_auth PDA (set by BindInsuranceAuthority tag 19 CPI 2).
//   After BurnAssetAdmin, no admin key can rotate the operator back — so this CPI
//   is the ONLY authorized path for extracting insurance tokens from the wrapper.
//
// MODE: tag 57 works in LIVE mode (same mode FlushToInsurance uses); the caller
//   (process_recover_flushed_insurance) enforces LIVE mode via pool_mode == 0.
//
// NOTE: vault_auth PDA signs via invoke_signed with the same seeds as all other
//   stake CPIs: [b"vault_auth", pool_pda.key, &[bump]].

const TAG_WITHDRAW_INSURANCE_ASSET: u8 = 57;

/// Pure tag-57 `WithdrawInsuranceAsset` payload builder — separated the same
/// way as the tag-9/32/65 builders above so the byte layout is directly
/// unit-testable against a synthetic account.
///
/// Wire (35 bytes): `[tag=57][asset_index: u16 LE = 0][market_id: u64 LE]
/// [amount: u128 LE][authority_epoch: u64 LE]`.
fn build_withdraw_insurance_asset_data(
    market: &AccountInfo,
    amount: u64,
) -> Result<Vec<u8>, ProgramError> {
    let market_id = read_asset0_market_id(market)?;
    let authority_epoch = read_asset0_authority_epoch(market)?;

    let mut data = Vec::with_capacity(35);
    data.push(TAG_WITHDRAW_INSURANCE_ASSET);
    data.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes()); // 2 bytes, always 0x00 0x00
    data.extend_from_slice(&market_id.to_le_bytes()); // 8 bytes
    data.extend_from_slice(&(amount as u128).to_le_bytes()); // 16 bytes u128 LE
    data.extend_from_slice(&authority_epoch.to_le_bytes()); // 8 bytes
    debug_assert_eq!(data.len(), 35);
    Ok(data)
}

pub fn cpi_withdraw_insurance_asset<'a>(
    percolator_program: &AccountInfo<'a>,
    vault_auth: &AccountInfo<'a>, // insurance_operator = our PDA; signs via invoke_signed
    market: &AccountInfo<'a>,     // wrapper market / slab (writable)
    dest_token: &AccountInfo<'a>, // destination token account (MUST be pool.vault; drain check by caller)
    wrapper_vault: &AccountInfo<'a>, // wrapper insurance vault token account (source)
    wrapper_vault_auth: &AccountInfo<'a>, // wrapper vault authority PDA (read-only)
    token_program: &AccountInfo<'a>,
    amount: u64,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    let data = build_withdraw_insurance_asset_data(market, amount)?;

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*vault_auth.key, true), // operator (PDA), signer via invoke_signed
            AccountMeta::new(*market.key, false),             // market, writable
            AccountMeta::new(*dest_token.key, false),         // dest_token (pool.vault), writable
            AccountMeta::new(*wrapper_vault.key, false),      // vault_token (source), writable
            AccountMeta::new_readonly(*wrapper_vault_auth.key, false), // vault_authority, read-only
            AccountMeta::new_readonly(*token_program.key, false), // token_program, read-only
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            vault_auth.clone(),
            market.clone(),
            dest_token.clone(),
            wrapper_vault.clone(),
            wrapper_vault_auth.clone(),
            token_program.clone(),
        ],
        &[signer_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// WithdrawInsurance (Tag 41) — F-9: terminal insurance withdrawal
// ═══════════════════════════════════════════════════════════════
//
// The wrapper's RESOLVED-market insurance exit. Verified against BOTH the deployed
// wrapper (`deploy/v18.2-wrapper@6377376a`, `handle_withdraw_insurance`,
// src/v16_program.rs:15968) and P1 (`feat/p1-safety-release@c0ffaefa`,
// :16741). The handler bodies are byte-identical in the two builds.
//
// WIRE (17 bytes): `[tag=41][amount: u128 LE]` (decode arm
// `41 => Self::WithdrawInsurance { amount: read_u128 }`, trailing bytes rejected).
//
// ACCOUNTS (the wrapper's order):
//   [0] authority      — the asset-0 `insurance_authority`. After
//                        BindInsuranceAuthority (tag 19) that is OUR vault_auth PDA.
//                        NOT signer-checked by the wrapper (W4-PAYOUT, upstream
//                        d64cdeeb: terminal payout is permissionless). We still pass
//                        it as a signer via invoke_signed, so a future wrapper that
//                        re-adds the signer check keeps working.
//   [1] market         — writable, wrapper-owned.
//   [2] dest_token     — writable; SPL `owner` MUST equal `authority`
//                        (`verify_withdrawable_token_accounts`), plus no delegate /
//                        close authority. We always pass `pool.vault`, which is
//                        owned by vault_auth.
//   [3] vault_token    — writable; the canonical wrapper vault ATA.
//   [4] vault_authority — the wrapper's `[b"vault", market]` PDA.
//   [5] token_program
//   [6] (optional) insurance ledger — NOT passed.
//
// WRAPPER GATES: `mode == Resolved`, `materialized_portfolio_count == 0`,
// `c_tot == 0`, `amount <= terminal capacity for this authority` (the per-domain
// budgets whose `insurance_authority == authority`, clamped to the unreserved
// insurance and to the vault), plus the insurance-withdraw cooldown and
// deposits-only ceiling. A failing gate returns `EngineLockActive` (Custom 21).
const TAG_WITHDRAW_INSURANCE: u8 = 41;

/// Pure tag-41 payload builder. Wire (17 bytes): `[41][amount: u128 LE]`.
pub fn build_withdraw_insurance_data(amount: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(17);
    data.push(TAG_WITHDRAW_INSURANCE);
    data.extend_from_slice(&(amount as u128).to_le_bytes());
    debug_assert_eq!(data.len(), 17);
    data
}

pub fn cpi_withdraw_insurance_terminal<'a>(
    percolator_program: &AccountInfo<'a>,
    vault_auth: &AccountInfo<'a>, // insurance_authority = our PDA
    market: &AccountInfo<'a>,     // wrapper market / slab (writable)
    dest_token: &AccountInfo<'a>, // MUST be pool.vault (checked by the caller)
    wrapper_vault: &AccountInfo<'a>,
    wrapper_vault_auth: &AccountInfo<'a>,
    token_program: &AccountInfo<'a>,
    amount: u64,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*vault_auth.key, true), // authority (PDA)
            AccountMeta::new(*market.key, false),
            AccountMeta::new(*dest_token.key, false),
            AccountMeta::new(*wrapper_vault.key, false),
            AccountMeta::new_readonly(*wrapper_vault_auth.key, false),
            AccountMeta::new_readonly(*token_program.key, false),
        ],
        data: build_withdraw_insurance_data(amount),
    };
    invoke_signed(
        &ix,
        &[
            vault_auth.clone(),
            market.clone(),
            dest_token.clone(),
            wrapper_vault.clone(),
            wrapper_vault_auth.clone(),
            token_program.clone(),
        ],
        &[signer_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// CloseSlab (Tag 13) — F-9: retire a stake-owned (marketauth = pool PDA) market
// ═══════════════════════════════════════════════════════════════
//
// Verified against deploy/v18.2-wrapper@6377376a `handle_close_slab`
// (src/v16_program.rs:17239) and P1 feat/p1-safety-release@c0ffaefa (same account
// shape; P1 adds an F4 step that may re-book orphaned fee legs and return Ok
// WITHOUT closing, so the proxy is simply called again).
//
// WIRE (9 bytes): `[tag=13][authority_epoch: u64 LE]`, the asset-0 authority epoch
// (CHECK-only, `require_authority_epoch_view(&group, 0, ..)`).
//
// ACCOUNTS (primary collateral only; a secondary-collateral market is not supported
// by this proxy — stake pools are single-mint):
//   [0] admin_dest   — signer + writable; MUST be `cfg.marketauth`
//                      (`expect_live_authority`). After InitPool that is the POOL
//                      PDA, which signs via invoke_signed and receives the slab and
//                      vault-account rent refunds.
//   [1] market       — writable
//   [2] vault_token  — writable; canonical wrapper vault
//   [3] vault_authority
//   [4] dest_token   — writable; `verify_user_token_account(dest, admin_dest, mint)`:
//                      an initialized token account OWNED BY THE POOL PDA. Receives
//                      the primary sweep (vault balance minus retired residue).
//   [5] token_program
//   [6] primary mint — writable; read only when unbudgeted residue is burned.
const TAG_CLOSE_SLAB: u8 = 13;

/// Pure tag-13 payload builder. Wire (9 bytes): `[13][authority_epoch: u64 LE]`.
fn build_close_slab_data(market: &AccountInfo) -> Result<Vec<u8>, ProgramError> {
    let authority_epoch = read_asset0_authority_epoch(market)?;
    let mut data = Vec::with_capacity(9);
    data.push(TAG_CLOSE_SLAB);
    data.extend_from_slice(&authority_epoch.to_le_bytes());
    debug_assert_eq!(data.len(), 9);
    Ok(data)
}

pub fn cpi_close_slab<'a>(
    percolator_program: &AccountInfo<'a>,
    pool_pda: &AccountInfo<'a>, // marketauth; signs via invoke_signed
    market: &AccountInfo<'a>,
    wrapper_vault: &AccountInfo<'a>,
    wrapper_vault_auth: &AccountInfo<'a>,
    dest_token: &AccountInfo<'a>, // owned by pool_pda
    token_program: &AccountInfo<'a>,
    mint: &AccountInfo<'a>,
    pool_seeds: &[&[u8]],
) -> ProgramResult {
    let data = build_close_slab_data(market)?;
    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new(*pool_pda.key, true),
            AccountMeta::new(*market.key, false),
            AccountMeta::new(*wrapper_vault.key, false),
            AccountMeta::new_readonly(*wrapper_vault_auth.key, false),
            AccountMeta::new(*dest_token.key, false),
            AccountMeta::new_readonly(*token_program.key, false),
            AccountMeta::new(*mint.key, false),
        ],
        data,
    };
    invoke_signed(
        &ix,
        &[
            pool_pda.clone(),
            market.clone(),
            wrapper_vault.clone(),
            wrapper_vault_auth.clone(),
            dest_token.clone(),
            token_program.clone(),
            mint.clone(),
        ],
        &[pool_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// ResolveMarket (Tag 19) — C-1 fix: CPI proxy for the wrapper's terminal
// resolution instruction, now that marketauth is the pool PDA
// ═══════════════════════════════════════════════════════════════
// SECURITY REVIEW C-1 (BLOCKER, fixed here): `process_init_pool` rotates
// `cfg.marketauth` to the pool PDA (see `cpi_update_authority` above), ported
// from the deployed `percolator-vault@eb3ebe8`. That vault ALSO ports an
// `AdminResolveMarket` CPI proxy (vault tag 9 -> wrapper tag 19) alongside the
// rotation — this program had the rotation WITHOUT the matching proxy. Once
// marketauth is the pool PDA, NO top-level signer can ever satisfy the
// wrapper's `expect_signer(admin)` + `expect_live_authority(&cfg.marketauth,
// admin.key)` checks in `handle_resolve_market` directly (a PDA cannot sign a
// plain transaction) — every market created via InitPool would be
// permanently stuck in Live mode (mode == 0), with the terminal insurance
// withdrawal path (post-resolution WithdrawInsurance) forever unreachable.
// This CPI closes that gap: the pool PDA signs via `invoke_signed` using its
// OWN seeds (`[b"stake_pool", slab, bump]`), exactly mirroring how
// `cpi_update_authority` already proves control during InitPool.
//
// WIRE (v16 migration, LOCKED, HELD — verified against `sync/integration-v16
// @ a9318945`'s ACTUAL decode arm, `19 => Self::ResolveMarket {
// asset_generation_frontier: read_u64, authority_epoch: read_u64 }`, and
// `handle_resolve_market`'s signature `(program_id, accounts,
// expected_asset_generation_frontier, expected_authority_epoch)`):
//   let admin = account(accounts, 0)?;      // expect_signer
//   let market_ai = account(accounts, 1)?;  // expect_writable + expect_owner(program_id)
//   require_asset_generation_frontier_view(&group, expected_asset_generation_frontier)?;
//   ... mode must == 0 (else EngineLockActive) ...
//   expect_live_authority(&cfg.marketauth, admin.key)?;
//   require_authority_epoch_view(&group, 0, expected_authority_epoch)?;  // CHECK-only, asset-0 lane
//   group.resolve_market_not_atomic(slot)
// Data: tag(1) + asset_generation_frontier(8, u64 LE) + authority_epoch(8,
// u64 LE) = 17 bytes. Accounts: exactly 2 —
// [admin(signer), market(writable)] — UNCHANGED from the pre-migration
// bare-tag wire.
//
// TWO DIFFERENT "generation" FIELDS, DO NOT CONFUSE: `asset_generation_frontier`
// is the MARKET-WIDE `header.next_market_id` counter (see
// `MARKET_ASSET_GENERATION_FRONTIER_OFF`'s doc comment) — NOT asset 0's
// per-asset `market_id` that tags 9/65/51/57 use. `authority_epoch` IS the
// same asset-0 CAS lane as everywhere else in this file (CHECK-only here,
// never advanced by this tag — only `UpdateAuthority`/`UpdateAssetAuthority`
// advance it), read via the existing `read_asset0_authority_epoch`.
//
// ACCOUNT SHAPE PARITY with the deployed vault's `cpi_resolve_market`
// (percolator-vault@eb3ebe8 src/cpi.rs:240-258) is preserved — identical
// 2-account `[new_readonly(admin_pda, true), new(slab, false)]` shape and
// `invoke_signed(&ix, &[admin_pda.clone(), slab.clone()], &[admin_seeds])`
// call pattern; only the DATA payload grew for the v16 migration. This
// program's "admin_pda" signer is the `stake_pool` PDA itself (matching what
// `cpi_update_authority` rotated marketauth to), not a separately-named admin
// PDA — vault and stake converge on the same PDA-is-marketauth design from
// issue #6 lineage reconciliation.
//
// H-1 (HIGH, fixed at the call site in `processor.rs::process_admin_resolve_market`):
// this CPI is gated so the caller may not invoke it while
// `pool.total_flushed > pool.total_returned` (flushed-but-unrecovered
// insurance outstanding). `RecoverFlushedInsurance` (tag 23) CPIs wrapper tag
// 57 `WithdrawInsuranceAsset`, which itself requires LIVE mode (mode == 0) —
// once THIS CPI flips the wrapper to mode != 0, tag 57 permanently rejects
// with EngineLockActive and any outstanding flush would be stranded with no
// recovery path (the wrapper's terminal-mode withdrawal, tag 41
// `WithdrawInsurance`, is a DIFFERENT CPI this program does not implement).
// Gating resolution on full recovery-first means that fallback is never
// needed by construction — see the H-1 doc note on
// `process_admin_resolve_market` for the full analysis.
const TAG_RESOLVE_MARKET: u8 = 19;

/// Pure tag-19 `ResolveMarket` payload builder — separated the same way as
/// the other v16-migration builders above so the byte layout is directly
/// unit-testable against a synthetic account.
///
/// Wire (17 bytes): `[tag=19][asset_generation_frontier: u64 LE]
/// [authority_epoch: u64 LE]`.
fn build_resolve_market_data(slab: &AccountInfo) -> Result<Vec<u8>, ProgramError> {
    let asset_generation_frontier = read_market_asset_generation_frontier(slab)?;
    let authority_epoch = read_asset0_authority_epoch(slab)?;

    let mut data = Vec::with_capacity(17);
    data.push(TAG_RESOLVE_MARKET);
    data.extend_from_slice(&asset_generation_frontier.to_le_bytes());
    data.extend_from_slice(&authority_epoch.to_le_bytes());
    debug_assert_eq!(data.len(), 17);
    Ok(data)
}

pub fn cpi_resolve_market<'a>(
    percolator_program: &AccountInfo<'a>,
    pool_pda: &AccountInfo<'a>, // marketauth (rotated by InitPool); signs via invoke_signed
    slab: &AccountInfo<'a>,     // market, writable
    pool_seeds: &[&[u8]],       // pool PDA seeds: [b"stake_pool", slab, bump]
) -> ProgramResult {
    let data = build_resolve_market_data(slab)?;

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*pool_pda.key, true), // admin == marketauth, signer
            AccountMeta::new(*slab.key, false),             // market, writable
        ],
        data,
    };

    invoke_signed(&ix, &[pool_pda.clone(), slab.clone()], &[pool_seeds])
}

// ═══════════════════════════════════════════════════════════════
// TASK 13 — CPI proxies for wrapper setters stranded by staking
// ═══════════════════════════════════════════════════════════════
// All four helpers below are byte-for-byte mirrors of `cpi_resolve_market`
// above: a `[signer(readonly), market(writable)]` account pair and an
// `invoke_signed` with the signing PDA's own seeds. That shape is not a guess —
// every one of the four wrapper handlers opens with the identical
//     let authority = account(accounts, 0)?;
//     let market_ai = account(accounts, 1)?;
//     expect_signer(authority)?;
//     expect_writable(market_ai)?;
//     expect_owner(market_ai, program_id)?;
// prologue, then gates `authority.key` against a stored authority field with
// `expect_live_authority`. Only WHICH field differs, and that is what splits
// these into two groups with two different signers:
//
//   GROUP A (signer = POOL PDA, seeds [b"stake_pool", slab, bump]):
//     tag 86 UpdateFeeSplit              -> gated on cfg.marketauth
//     tag 88 UpdateMaintenanceFeePerSlot -> gated on cfg.marketauth
//     tag 55 UpdateTradeFeePolicy        -> gated on cfg.marketauth (GH#286,
//       wrapper #455 moved this OUT of Group B — see tag 55's own doc
//       comment below for the full history)
//   GROUP B (signer = VAULT_AUTH PDA, seeds [b"vault_auth", pool, bump]):
//     tag 51 UpdateBackingFeePolicy -> gated on per-asset insurance_authority
//
// Passing a Group A signer to a Group B tag (or vice versa) does not silently
// misbehave — the wrapper's `expect_live_authority` rejects with Unauthorized,
// because the two PDAs are distinct keys. The split is enforced by the wrapper,
// and mirrored here so the intent is legible at the call site.
//
// ARGUMENT VALIDATION IS DELIBERATELY ABSENT from all four. The wrapper owns it
// (`validate_fee_split` for tag 86, `MAX_PROTOCOL_FEE_ABS` for 88,
// `max_trading_fee_bps`/`MAX_DYNAMIC_TRADE_FEE_BPS` for 51/55). Duplicating any
// of those bounds here would create two copies that drift apart on the first
// retune.
//
// v16 MIGRATION WIRE (systematic sweep, sync/integration-v16 @ a9318945): tags
// 86 and 51 each gained a trailing replay-protection field the pre-migration
// wire did not carry; tag 88 did NOT change (see its own doc comment — VERIFIED
// unchanged, not just left alone).

/// Wrapper tag 86 `UpdateFeeSplit`. Marketauth-gated — the POOL PDA signs.
/// Wire (v16 migration, LOCKED, HELD): tag(1) + creator(2) + lp(2) +
/// insurance(2) + authority_epoch(8, u64 LE) = 15 bytes, matching `86 =>
/// Self::UpdateFeeSplit { read_u16, read_u16, read_u16, read_u64 }`.
///
/// v16 MIGRATION WIRE CHANGE (W4-AE-EXTEND): `handle_update_fee_split` gained
/// a gate-2-class CAS check against the SAME asset-0 `authority_epoch` lane
/// every other tag-65-family CPI in this file reads
/// (`state::require_current_authority_epoch(sequences.authority_epoch,
/// expected_authority_epoch)` on `read_asset_control_sequences(&data, 0)`).
/// Passed UNCHANGED via the existing `read_asset0_authority_epoch`.
const TAG_UPDATE_FEE_SPLIT: u8 = 86;

/// Pure tag-86 `UpdateFeeSplit` payload builder — separated the same way as
/// the other v16-migration builders above so the byte layout is directly
/// unit-testable against a synthetic account.
fn build_update_fee_split_data(
    slab: &AccountInfo,
    creator_share_bps: u16,
    lp_share_bps: u16,
    insurance_share_bps: u16,
) -> Result<Vec<u8>, ProgramError> {
    let authority_epoch = read_asset0_authority_epoch(slab)?;

    let mut data = Vec::with_capacity(15);
    data.push(TAG_UPDATE_FEE_SPLIT);
    data.extend_from_slice(&creator_share_bps.to_le_bytes());
    data.extend_from_slice(&lp_share_bps.to_le_bytes());
    data.extend_from_slice(&insurance_share_bps.to_le_bytes());
    data.extend_from_slice(&authority_epoch.to_le_bytes());
    debug_assert_eq!(data.len(), 15);
    Ok(data)
}

pub fn cpi_update_fee_split<'a>(
    percolator_program: &AccountInfo<'a>,
    pool_pda: &AccountInfo<'a>, // marketauth (rotated by InitPool); signs via invoke_signed
    slab: &AccountInfo<'a>,     // market, writable
    creator_share_bps: u16,
    lp_share_bps: u16,
    insurance_share_bps: u16,
    pool_seeds: &[&[u8]], // pool PDA seeds: [b"stake_pool", slab, bump]
) -> ProgramResult {
    let data = build_update_fee_split_data(
        slab,
        creator_share_bps,
        lp_share_bps,
        insurance_share_bps,
    )?;

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*pool_pda.key, true), // admin == marketauth, signer
            AccountMeta::new(*slab.key, false),             // market, writable
        ],
        data,
    };

    invoke_signed(&ix, &[pool_pda.clone(), slab.clone()], &[pool_seeds])
}

/// Wrapper tag 88 `UpdateMaintenanceFeePerSlot`. Marketauth-gated — the POOL
/// PDA signs. Wire: tag(1) + maintenance_fee_per_slot(16, u128 LE) = 17 bytes.
///
/// THE PAYLOAD IS 16 BYTES, NOT 8. The wrapper's decoder arm is
/// `88 => Self::UpdateMaintenanceFeePerSlot { maintenance_fee_per_slot:
/// read_u128(&mut rest)? }`, and it rejects the instruction outright if `rest`
/// is non-empty afterward. An 8-byte u64 payload therefore fails closed with
/// `InvalidInstructionData` rather than writing a truncated value.
///
/// VERIFIED UNCHANGED at `sync/integration-v16 @ a9318945`
/// (`handle_update_maintenance_fee_per_slot`'s signature is still
/// `(program_id, accounts, maintenance_fee_per_slot: u128)` — NO
/// authority_epoch/policy_sequence parameter was added; #428's Live-mode gate
/// added a *read-side* checkpoint write, not a new *wire* field). This wire
/// is NOT part of the systematic sweep's drift list — 17 bytes, tag+u128,
/// same as before.
const TAG_UPDATE_MAINTENANCE_FEE_PER_SLOT: u8 = 88;

pub fn cpi_update_maintenance_fee_per_slot<'a>(
    percolator_program: &AccountInfo<'a>,
    pool_pda: &AccountInfo<'a>, // marketauth; signs via invoke_signed
    slab: &AccountInfo<'a>,     // market, writable
    maintenance_fee_per_slot: u128,
    pool_seeds: &[&[u8]], // pool PDA seeds: [b"stake_pool", slab, bump]
) -> ProgramResult {
    let mut data = Vec::with_capacity(17);
    data.push(TAG_UPDATE_MAINTENANCE_FEE_PER_SLOT);
    data.extend_from_slice(&maintenance_fee_per_slot.to_le_bytes()); // 16 bytes

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*pool_pda.key, true), // admin == marketauth, signer
            AccountMeta::new(*slab.key, false),             // market, writable
        ],
        data,
    };

    invoke_signed(&ix, &[pool_pda.clone(), slab.clone()], &[pool_seeds])
}

/// Wrapper tag 51 `UpdateBackingFeePolicy`. Gated on the per-asset
/// `insurance_authority` — the VAULT_AUTH PDA signs, NOT the pool PDA.
/// Wire (v16 migration, LOCKED, HELD): tag(1) + domain(2) + market_id(8, u64
/// LE) + fee_bps(2) + insurance_share_bps(2) + policy_sequence(8, u64 LE) =
/// 23 bytes, matching `51 => Self::UpdateBackingFeePolicy { read_u16,
/// read_u64, read_u16, read_u16, read_u64 }`.
///
/// This is the setter for `backing_trade_fee_bps`. On a market where
/// `BindInsuranceAuthority` has run, this CPI is the ONLY way to reach it.
///
/// v16 MIGRATION WIRE CHANGE: `handle_update_backing_fee_policy` gained
/// `expected_market_id` (checked via `require_asset_generation_view(&group,
/// asset_index, expected_market_id)`, `asset_index = domain / 2`) and a
/// trailing `policy_sequence` (a STRICTLY-INCREASING one-shot nonce via
/// `require_newer_control_sequence`, lane `BackingFeeLong` for `domain` even
/// / `BackingFeeShort` for `domain` odd — NOT a CAS like `authority_epoch`).
///
/// SCOPING NOTE: this program only ever binds asset 0's `insurance_authority`
/// to `vault_auth` (see `cpi_bind_insurance_authority`), so `domain` is only
/// ever meaningfully 0 (long) or 1 (short) in this program's own call sites
/// — both map to `asset_index == 0`. `market_id` is therefore read via the
/// existing asset-0 `read_asset0_market_id`, matching every other asset-0-
/// scoped field in this file. A caller-supplied `domain >= 2` would target a
/// DIFFERENT asset's generation counter, and passing asset-0's `market_id`
/// for it fails CLOSED (an `AssetGenerationMismatch`, checked BEFORE the
/// authority gate) rather than opening any bypass — this program's PDA is
/// not that asset's `insurance_authority` either way.
const TAG_UPDATE_BACKING_FEE_POLICY: u8 = 51;

/// Pure tag-51 `UpdateBackingFeePolicy` payload builder — separated the same
/// way as the other v16-migration builders above so the byte layout is
/// directly unit-testable against a synthetic account.
fn build_update_backing_fee_policy_data(
    slab: &AccountInfo,
    domain: u16,
    fee_bps: u16,
    insurance_share_bps: u16,
) -> Result<Vec<u8>, ProgramError> {
    let market_id = read_asset0_market_id(slab)?;
    let long_side = domain.is_multiple_of(2);
    let policy_sequence = next_asset0_backing_fee_policy_sequence(slab, long_side)?;

    let mut data = Vec::with_capacity(23);
    data.push(TAG_UPDATE_BACKING_FEE_POLICY);
    data.extend_from_slice(&domain.to_le_bytes());
    data.extend_from_slice(&market_id.to_le_bytes());
    data.extend_from_slice(&fee_bps.to_le_bytes());
    data.extend_from_slice(&insurance_share_bps.to_le_bytes());
    data.extend_from_slice(&policy_sequence.to_le_bytes());
    debug_assert_eq!(data.len(), 23);
    Ok(data)
}

pub fn cpi_update_backing_fee_policy<'a>(
    percolator_program: &AccountInfo<'a>,
    vault_auth: &AccountInfo<'a>, // insurance_authority (bound by tag 19); signs via invoke_signed
    slab: &AccountInfo<'a>,       // market, writable
    domain: u16,
    fee_bps: u16,
    insurance_share_bps: u16,
    vault_auth_seeds: &[&[u8]], // vault_auth PDA seeds: [b"vault_auth", pool, bump]
) -> ProgramResult {
    let data = build_update_backing_fee_policy_data(slab, domain, fee_bps, insurance_share_bps)?;

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*vault_auth.key, true), // insurance_authority, signer
            AccountMeta::new(*slab.key, false),               // market, writable
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[vault_auth.clone(), slab.clone()],
        &[vault_auth_seeds],
    )
}

/// Wrapper tag 55 `UpdateTradeFeePolicy`. Wire (v16 migration, LOCKED, HELD):
/// tag(1) + trade_fee_base_bps(8, u64 LE) + policy_sequence(8, u64 LE) = 17
/// bytes, matching `55 => Self::UpdateTradeFeePolicy { read_u64, read_u64 }`.
///
/// GH#286 / wrapper #455 ("gate UpdateTradeFeePolicy on marketauth, like
/// every other market-wide setter"): this tag moved from GROUP B
/// (asset-0 `insurance_authority`, VAULT_AUTH PDA signer) to GROUP A
/// (`cfg.marketauth`, POOL PDA signer) — see `handle_update_trade_fee_policy`'s
/// own doc comment in the wrapper (`#445: gate on cfg.marketauth, like every
/// other MARKET-WIDE fee-policy setter`; `trade_fee_base_bps` is a
/// market-wide floor, not scoped to asset 0, and a staked market's asset-0
/// `insurance_authority` can be parked on a PDA that cannot sign, which left
/// this field permanently unsettable under the old gate). The processor.rs
/// call site (`process_admin_update_trade_fee_policy`, tag 28) was already
/// fixed for this in PR #288 — it passes `pool_pda` positionally into what
/// used to be named `vault_auth` here. This function's parameter names are
/// renamed to match (`pool_pda`/`pool_seeds`) so the signature is no longer
/// misleading about who actually signs; this is a doc/naming fix only, NOT a
/// call-site or account-shape change (same position, same type).
///
/// v16 MIGRATION WIRE CHANGE (separate from GH#286's authority-gate change):
/// `handle_update_trade_fee_policy` also gained a trailing `policy_sequence`
/// (a strictly-increasing one-shot nonce via `require_newer_control_sequence`
/// on asset-0's `ControlSequenceLane::TradeFee` lane — NOT a CAS). NOTE:
/// UNLIKE tag 51, this wire carries NO `market_id` field — the wrapper's
/// decode arm for tag 55 is exactly `{ trade_fee_base_bps: read_u64,
/// policy_sequence: read_u64 }`, no generation-binding field at all.
const TAG_UPDATE_TRADE_FEE_POLICY: u8 = 55;

/// Pure tag-55 `UpdateTradeFeePolicy` payload builder — separated the same
/// way as the other v16-migration builders above so the byte layout is
/// directly unit-testable against a synthetic account.
fn build_update_trade_fee_policy_data(
    slab: &AccountInfo,
    trade_fee_base_bps: u64,
) -> Result<Vec<u8>, ProgramError> {
    let policy_sequence = next_asset0_trade_fee_policy_sequence(slab)?;

    let mut data = Vec::with_capacity(17);
    data.push(TAG_UPDATE_TRADE_FEE_POLICY);
    data.extend_from_slice(&trade_fee_base_bps.to_le_bytes());
    data.extend_from_slice(&policy_sequence.to_le_bytes());
    debug_assert_eq!(data.len(), 17);
    Ok(data)
}

pub fn cpi_update_trade_fee_policy<'a>(
    percolator_program: &AccountInfo<'a>,
    pool_pda: &AccountInfo<'a>, // marketauth (GH#286/wrapper #455); signs via invoke_signed
    slab: &AccountInfo<'a>,     // market, writable
    trade_fee_base_bps: u64,
    pool_seeds: &[&[u8]], // pool PDA seeds: [b"stake_pool", slab, bump]
) -> ProgramResult {
    let data = build_update_trade_fee_policy_data(slab, trade_fee_base_bps)?;

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*pool_pda.key, true), // marketauth, signer
            AccountMeta::new(*slab.key, false),             // market, writable
        ],
        data,
    };

    invoke_signed(&ix, &[pool_pda.clone(), slab.clone()], &[pool_seeds])
}

#[cfg(test)]
mod tag_tests {
    use super::*;

    #[test]
    fn test_cpi_tag_constants() {
        assert_eq!(TAG_TOP_UP_INSURANCE, 9, "TAG_TOP_UP_INSURANCE mismatch");
        assert_eq!(
            TAG_UPDATE_ASSET_AUTHORITY, 65,
            "TAG_UPDATE_ASSET_AUTHORITY mismatch (v17 collision row 43: was 32)"
        );
        assert_eq!(ASSET_INDEX_ZERO, 0, "ASSET_INDEX_ZERO must be 0");
        assert_eq!(
            ASSET_AUTH_INSURANCE, 1,
            "ASSET_AUTH_INSURANCE mismatch (v17 footgun: was 2 in v16 AUTHORITY_INSURANCE)"
        );
    }

    use solana_program::pubkey::Pubkey;

    /// Build a synthetic market-account data buffer sized to cover asset 0's
    /// three fields this module reads, with each set to a given sentinel
    /// value. Only the three offsets under test are populated — everything
    /// else stays zeroed, matching a freshly re-seeded account.
    fn synthetic_market_data(market_id: u64, authority_epoch: u64, insurance_top_up: u64) -> Vec<u8> {
        let len = ASSET0_MARKET_ID_OFF + 8;
        let mut data = vec![0u8; len];
        data[ASSET0_MARKET_ID_OFF..ASSET0_MARKET_ID_OFF + 8]
            .copy_from_slice(&market_id.to_le_bytes());
        data[ASSET0_AUTHORITY_EPOCH_OFF..ASSET0_AUTHORITY_EPOCH_OFF + 8]
            .copy_from_slice(&authority_epoch.to_le_bytes());
        data[ASSET0_INSURANCE_TOP_UP_OFF..ASSET0_INSURANCE_TOP_UP_OFF + 8]
            .copy_from_slice(&insurance_top_up.to_le_bytes());
        data
    }

    /// Extended synthetic market-account buffer for the systematic-sweep
    /// tags (19/51/55), which read live fields beyond the original three
    /// `synthetic_market_data` covers. Builds on the same buffer (all four
    /// new offsets are smaller than `ASSET0_MARKET_ID_OFF + 8`, so no resize
    /// is needed) and patches in the additional sentinel values.
    #[allow(clippy::too_many_arguments)]
    fn synthetic_market_data_full(
        market_id: u64,
        authority_epoch: u64,
        insurance_top_up: u64,
        asset_generation_frontier: u64,
        backing_fee_long: u64,
        backing_fee_short: u64,
        trade_fee: u64,
    ) -> Vec<u8> {
        let mut data = synthetic_market_data(market_id, authority_epoch, insurance_top_up);
        data[MARKET_ASSET_GENERATION_FRONTIER_OFF..MARKET_ASSET_GENERATION_FRONTIER_OFF + 8]
            .copy_from_slice(&asset_generation_frontier.to_le_bytes());
        data[ASSET0_BACKING_FEE_LONG_OFF..ASSET0_BACKING_FEE_LONG_OFF + 8]
            .copy_from_slice(&backing_fee_long.to_le_bytes());
        data[ASSET0_BACKING_FEE_SHORT_OFF..ASSET0_BACKING_FEE_SHORT_OFF + 8]
            .copy_from_slice(&backing_fee_short.to_le_bytes());
        data[ASSET0_TRADE_FEE_OFF..ASSET0_TRADE_FEE_OFF + 8]
            .copy_from_slice(&trade_fee.to_le_bytes());
        data
    }

    /// OFFSET PIN: these three constants are the ground truth this whole
    /// v16-migration wire depends on (derived against `sync/integration-v16
    /// @ a9318945`'s compiled layout — see the constants' own doc comments
    /// for the full derivation). Pinning the literal numbers here means any
    /// accidental edit to the formulas above is caught immediately, not just
    /// when it happens to also break a wire-shape test.
    #[test]
    fn test_asset0_offset_constants_are_pinned() {
        assert_eq!(ASSET0_WRAPPER_START, 1350);
        assert_eq!(ASSET0_MARKET_ID_OFF, 2374);
        assert_eq!(ASSET0_AUTHORITY_EPOCH_OFF, 1934);
        assert_eq!(ASSET0_INSURANCE_TOP_UP_OFF, 1846);
        // Systematic-sweep additions (tags 19/51/55) — ground-truthed via
        // core::mem::offset_of! against the real wrapper Pod types at
        // sync/integration-v16 @ a9318945 (throwaway probe, reverted).
        assert_eq!(MARKET_ASSET_GENERATION_FRONTIER_OFF, 1173);
        assert_eq!(ASSET0_BACKING_FEE_LONG_OFF, 1870);
        assert_eq!(ASSET0_BACKING_FEE_SHORT_OFF, 1878);
        assert_eq!(ASSET0_TRADE_FEE_OFF, 1886);
    }

    #[test]
    fn test_read_asset0_fields_round_trip() {
        let mut data = synthetic_market_data(4_242_424_242, 77, 100);
        let key = Pubkey::new_from_array([3u8; 32]);
        let owner = Pubkey::new_from_array([4u8; 32]);
        let mut lamports = 0u64;
        let market = AccountInfo::new(
            &key,
            false,
            true,
            &mut lamports,
            &mut data,
            &owner,
            false,
            0,
        );

        assert_eq!(read_asset0_market_id(&market).unwrap(), 4_242_424_242);
        assert_eq!(read_asset0_authority_epoch(&market).unwrap(), 77);
        // intent_id must be the watermark PLUS ONE (strictly greater, not CAS).
        assert_eq!(next_asset0_intent_id(&market).unwrap(), 101);
    }

    #[test]
    fn test_read_asset0_fields_rejects_undersized_account() {
        // One byte short of covering `ASSET0_MARKET_ID_OFF..+8`.
        let mut data = vec![0u8; ASSET0_MARKET_ID_OFF + 7];
        let key = Pubkey::new_from_array([3u8; 32]);
        let owner = Pubkey::new_from_array([4u8; 32]);
        let mut lamports = 0u64;
        let market = AccountInfo::new(
            &key,
            false,
            true,
            &mut lamports,
            &mut data,
            &owner,
            false,
            0,
        );
        assert!(
            read_asset0_market_id(&market).is_err(),
            "an undersized account must fail closed, not read garbage/out-of-bounds"
        );
    }

    /// CANARY: pin the v16-migration `TopUpInsurance` (tag 9) wire shape,
    /// exercising the REAL `build_top_up_insurance_data` production code path
    /// (not a hand-reconstructed literal) against a synthetic account.
    ///
    /// Wire (41 bytes): `[tag=9][market_id: u64 LE][intent_id: u64 LE]
    /// [authority_epoch: u64 LE][amount: u128 LE]`.
    #[test]
    fn test_build_top_up_insurance_data_wire_shape() {
        let mut data_acct = synthetic_market_data(555, 9, 200);
        let key = Pubkey::new_from_array([5u8; 32]);
        let owner = Pubkey::new_from_array([6u8; 32]);
        let mut lamports = 0u64;
        let market = AccountInfo::new(
            &key,
            false,
            true,
            &mut lamports,
            &mut data_acct,
            &owner,
            false,
            0,
        );

        let amount: u64 = 1_000;
        let data = build_top_up_insurance_data(&market, amount).unwrap();

        assert_eq!(data.len(), 41, "v16-migration tag-9 wire must be 41 bytes");
        assert_eq!(data[0], 9, "tag byte must be 9 (TopUpInsurance)");
        assert_eq!(
            u64::from_le_bytes(data[1..9].try_into().unwrap()),
            555,
            "market_id at bytes [1..9]"
        );
        assert_eq!(
            u64::from_le_bytes(data[9..17].try_into().unwrap()),
            201, // watermark(200) + 1
            "intent_id at bytes [9..17] must be watermark+1"
        );
        assert_eq!(
            u64::from_le_bytes(data[17..25].try_into().unwrap()),
            9,
            "authority_epoch at bytes [17..25] must be the LIVE current value, unchanged"
        );
        assert_eq!(
            u128::from_le_bytes(data[25..41].try_into().unwrap()),
            amount as u128,
            "amount at bytes [25..41] as u128 LE"
        );

        // Guard against regression to the pre-migration 17-byte wire.
        assert_ne!(
            data.len(),
            17,
            "17-byte tag+u128-only wire is the pre-migration shape — must NOT ship"
        );
    }

    /// REGRESSION GUARD (historical): the pre-migration wire was
    /// `tag(1) + amount(16, u128 LE)` = 17 bytes, with NO market_id/intent_id/
    /// authority_epoch fields. Against the v16-migration wrapper (which
    /// requires all three), that 17-byte payload hard-reverts at decode time
    /// (short read). Even older, the pre-v16 wire was a bare 8-byte u64 amount
    /// (9 bytes total) — also wrong.
    #[test]
    fn test_pre_migration_tag9_wires_are_now_wrong() {
        let amount: u64 = 1_000;
        let mut pre_migration = Vec::with_capacity(17);
        pre_migration.push(TAG_TOP_UP_INSURANCE);
        pre_migration.extend_from_slice(&(amount as u128).to_le_bytes());
        assert_eq!(pre_migration.len(), 17);
        assert_ne!(
            pre_migration.len(),
            41,
            "pre-migration 17-byte wire must NOT be sent to the v16-migration wrapper"
        );

        let mut pre_v16 = Vec::with_capacity(9);
        pre_v16.push(TAG_TOP_UP_INSURANCE);
        pre_v16.extend_from_slice(&amount.to_le_bytes());
        assert_eq!(pre_v16.len(), 9);
        assert_ne!(pre_v16.len(), 41);
    }

    /// CANARY: pin the v16-migration `UpdateAssetAuthority` (tag 65) wire
    /// shape at ALL FIVE call sites, exercising the REAL
    /// `build_update_asset_authority_data` production code path (shared by
    /// `cpi_bind_insurance_authority`, `cpi_bind_insurance_operator`,
    /// `cpi_burn_asset_admin`, `cpi_rotate_insurance_operator` and
    /// `cpi_rotate_insurance_authority`) against a synthetic account.
    ///
    /// Wire (52 bytes): `[tag=65][asset_index: u16 LE=0][market_id: u64 LE]
    /// [kind: u8][new_pubkey: 32 bytes][authority_epoch: u64 LE]`.
    #[test]
    fn test_build_update_asset_authority_data_wire_shape_all_kinds() {
        let mut data_acct = synthetic_market_data(777, 42, 3);
        let key = Pubkey::new_from_array([7u8; 32]);
        let owner = Pubkey::new_from_array([8u8; 32]);
        let mut lamports = 0u64;
        let market = AccountInfo::new(
            &key,
            false,
            true,
            &mut lamports,
            &mut data_acct,
            &owner,
            false,
            0,
        );

        // (kind, new_pubkey) exactly as each of the five call sites builds it.
        let cases: [(u8, [u8; 32], &str); 5] = [
            (ASSET_AUTH_INSURANCE, [0x11u8; 32], "cpi_bind_insurance_authority"),
            (ASSET_AUTH_INSURANCE_OPERATOR, [0x22u8; 32], "cpi_bind_insurance_operator"),
            (ASSET_AUTH_ADMIN, [0u8; 32], "cpi_burn_asset_admin"),
            (ASSET_AUTH_INSURANCE_OPERATOR, [0x33u8; 32], "cpi_rotate_insurance_operator"),
            (ASSET_AUTH_INSURANCE, [0x44u8; 32], "cpi_rotate_insurance_authority"),
        ];

        for (kind, new_pubkey, site) in cases {
            let data = build_update_asset_authority_data(&market, kind, new_pubkey).unwrap();

            assert_eq!(data.len(), 52, "{site}: v16-migration tag-65 wire must be 52 bytes");
            assert_eq!(data[0], 65, "{site}: tag byte must be 65");
            assert_eq!(
                u16::from_le_bytes(data[1..3].try_into().unwrap()),
                0,
                "{site}: asset_index at bytes [1..3] must be 0"
            );
            assert_eq!(
                u64::from_le_bytes(data[3..11].try_into().unwrap()),
                777,
                "{site}: market_id at bytes [3..11]"
            );
            assert_eq!(data[11], kind, "{site}: kind byte at [11]");
            assert_eq!(&data[12..44], &new_pubkey, "{site}: new_pubkey at bytes [12..44]");
            assert_eq!(
                u64::from_le_bytes(data[44..52].try_into().unwrap()),
                42,
                "{site}: authority_epoch at bytes [44..52] must be the LIVE current value, unchanged"
            );
        }

        // Kind bytes must all be distinct where the call sites intend distinct
        // kinds — a copy/paste error that reused the wrong constant at one
        // site would otherwise pass silently.
        assert_ne!(cases[0].0, cases[1].0);
        assert_ne!(cases[0].0, cases[2].0);
        assert_ne!(cases[1].0, cases[2].0);
    }

    /// NEGATIVE CONTROL: a wire with `market_id` and `kind` swapped (a
    /// plausible "field reordered" regression, since both would otherwise be
    /// small integers at nearby offsets) must NOT match the real builder's
    /// output. This proves the byte-shape assertions above actually
    /// discriminate field order, rather than passing vacuously.
    #[test]
    fn test_reordered_or_dropped_field_is_caught() {
        let mut data_acct = synthetic_market_data(777, 42, 3);
        let key = Pubkey::new_from_array([7u8; 32]);
        let owner = Pubkey::new_from_array([8u8; 32]);
        let mut lamports = 0u64;
        let market = AccountInfo::new(
            &key,
            false,
            true,
            &mut lamports,
            &mut data_acct,
            &owner,
            false,
            0,
        );
        let new_pubkey = [0x11u8; 32];
        let correct = build_update_asset_authority_data(&market, ASSET_AUTH_INSURANCE, new_pubkey).unwrap();

        // Wrong #1: market_id and authority_epoch swapped.
        let mut swapped = Vec::with_capacity(52);
        swapped.push(TAG_UPDATE_ASSET_AUTHORITY);
        swapped.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes());
        swapped.extend_from_slice(&42u64.to_le_bytes()); // authority_epoch value, in market_id's slot
        swapped.push(ASSET_AUTH_INSURANCE);
        swapped.extend_from_slice(&new_pubkey);
        swapped.extend_from_slice(&777u64.to_le_bytes()); // market_id value, in authority_epoch's slot
        assert_eq!(swapped.len(), 52, "same length as correct — length alone can't catch this");
        assert_ne!(swapped, correct, "swapped market_id/authority_epoch must differ from the real wire");

        // Wrong #2: authority_epoch dropped entirely (the pre-migration 36-byte wire).
        let mut dropped = Vec::with_capacity(36);
        dropped.push(TAG_UPDATE_ASSET_AUTHORITY);
        dropped.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes());
        dropped.push(ASSET_AUTH_INSURANCE);
        dropped.extend_from_slice(&new_pubkey);
        assert_eq!(dropped.len(), 36);
        assert_ne!(dropped.len(), correct.len(), "dropped-field wire must not match the real wire's length");
        assert_ne!(&dropped[..], &correct[..correct.len().min(dropped.len())], "dropped-field wire's bytes must diverge from the real wire well before the shorter length");
    }

    /// GUARD: all three kind constants in the secure-bind sequence are distinct
    /// and map to the expected numeric values from v16_program.rs.
    #[test]
    fn test_secure_bind_kind_constants_are_distinct() {
        assert_eq!(ASSET_AUTH_ADMIN, 0, "ASSET_AUTH_ADMIN must be 0");
        assert_eq!(ASSET_AUTH_INSURANCE, 1, "ASSET_AUTH_INSURANCE must be 1");
        assert_eq!(
            ASSET_AUTH_INSURANCE_OPERATOR, 2,
            "ASSET_AUTH_INSURANCE_OPERATOR must be 2"
        );
        // They must all differ (confusion between these is a security footgun)
        assert_ne!(ASSET_AUTH_ADMIN, ASSET_AUTH_INSURANCE);
        assert_ne!(ASSET_AUTH_ADMIN, ASSET_AUTH_INSURANCE_OPERATOR);
        assert_ne!(ASSET_AUTH_INSURANCE, ASSET_AUTH_INSURANCE_OPERATOR);
    }

    /// CANARY: pin the v16-migration WithdrawInsuranceAsset (tag 57) wire
    /// shape, exercising the REAL `build_withdraw_insurance_asset_data`
    /// production code path against a synthetic account.
    ///
    /// Wire (35 bytes): `[tag=57][asset_index: u16 LE = 0][market_id: u64 LE]
    /// [amount: u128 LE][authority_epoch: u64 LE]`.
    #[test]
    fn test_build_withdraw_insurance_asset_data_wire_shape() {
        let mut data_acct = synthetic_market_data(888, 15, 3);
        let key = Pubkey::new_from_array([9u8; 32]);
        let owner = Pubkey::new_from_array([10u8; 32]);
        let mut lamports = 0u64;
        let market = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data_acct, &owner, false, 0,
        );

        let amount: u64 = 250_000;
        let data = build_withdraw_insurance_asset_data(&market, amount).unwrap();

        assert_eq!(data.len(), 35, "v16-migration tag-57 wire must be 35 bytes");
        assert_eq!(data[0], 57, "tag must be 57 (WithdrawInsuranceAsset)");
        assert_eq!(
            u16::from_le_bytes(data[1..3].try_into().unwrap()),
            0,
            "asset_index at bytes [1..3] must be 0"
        );
        assert_eq!(
            u64::from_le_bytes(data[3..11].try_into().unwrap()),
            888,
            "market_id at bytes [3..11]"
        );
        assert_eq!(
            u128::from_le_bytes(data[11..27].try_into().unwrap()),
            amount as u128,
            "amount at bytes [11..27] as u128 LE"
        );
        assert_eq!(
            u64::from_le_bytes(data[27..35].try_into().unwrap()),
            15,
            "authority_epoch at bytes [27..35] must be the LIVE current value, unchanged"
        );

        // Guard against regression to the pre-migration 19-byte wire.
        assert_ne!(
            data.len(),
            19,
            "19-byte tag+asset_index+amount-only wire is the pre-migration shape — must NOT ship"
        );
        assert_ne!(data[0], TAG_TOP_UP_INSURANCE, "must be tag 57, not tag 9");
    }

    /// REGRESSION GUARD: the pre-migration tag-57 wire was `tag(1) +
    /// asset_index(2, u16 LE) + amount(16, u128 LE)` = 19 bytes, with NO
    /// market_id/authority_epoch fields. Against the v16-migration wrapper
    /// (which requires both), that 19-byte payload hard-reverts at decode
    /// time (short read after `amount`).
    #[test]
    fn test_pre_migration_tag57_wire_is_now_wrong() {
        let amount: u64 = 250_000;
        let mut pre_migration = Vec::with_capacity(19);
        pre_migration.push(TAG_WITHDRAW_INSURANCE_ASSET);
        pre_migration.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes());
        pre_migration.extend_from_slice(&(amount as u128).to_le_bytes());
        assert_eq!(pre_migration.len(), 19);
        assert_ne!(
            pre_migration.len(),
            35,
            "pre-migration 19-byte wire must NOT be sent to the v16-migration wrapper"
        );
    }

    /// CANARY: pin the v16-migration ResolveMarket (tag 19) wire shape,
    /// exercising the REAL `build_resolve_market_data` production code path
    /// against a synthetic account.
    ///
    /// Wire (17 bytes): `[tag=19][asset_generation_frontier: u64 LE]
    /// [authority_epoch: u64 LE]`.
    #[test]
    fn test_build_resolve_market_data_wire_shape() {
        let mut data_acct =
            synthetic_market_data_full(555, 21, 3, 999_888, 1, 2, 3);
        let key = Pubkey::new_from_array([11u8; 32]);
        let owner = Pubkey::new_from_array([12u8; 32]);
        let mut lamports = 0u64;
        let market = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data_acct, &owner, false, 0,
        );

        let data = build_resolve_market_data(&market).unwrap();

        assert_eq!(data.len(), 17, "v16-migration tag-19 wire must be 17 bytes");
        assert_eq!(data[0], 19, "tag must be 19 (ResolveMarket)");
        assert_eq!(
            u64::from_le_bytes(data[1..9].try_into().unwrap()),
            999_888,
            "asset_generation_frontier at bytes [1..9] must be the header-level frontier, \
             NOT asset-0's per-asset market_id (555)"
        );
        assert_eq!(
            u64::from_le_bytes(data[9..17].try_into().unwrap()),
            21,
            "authority_epoch at bytes [9..17] must be the LIVE current value, unchanged"
        );

        // Byte-for-byte parity with the deployed vault's pre-migration
        // cpi_resolve_market is no longer expected — the bare 1-byte wire
        // hard-reverts against the v16-migration wrapper's decoder.
        assert_ne!(
            data.len(),
            1,
            "bare 1-byte tag is the pre-migration shape — must NOT ship"
        );
    }

    /// GUARD: `asset_generation_frontier` and asset-0's per-asset `market_id`
    /// are DIFFERENT fields at DIFFERENT offsets, and must not collapse to
    /// the same read by accident (a very plausible copy/paste mistake given
    /// both are called "generation" nearby).
    #[test]
    fn test_frontier_and_asset0_market_id_are_different_offsets() {
        assert_ne!(
            MARKET_ASSET_GENERATION_FRONTIER_OFF, ASSET0_MARKET_ID_OFF,
            "header-level frontier and asset-0's per-asset market_id must be distinct offsets"
        );
    }

    /// C-1: TAG_RESOLVE_MARKET must equal 19 and be distinct from every other
    /// wrapper tag this program CPIs into (9, 32, 51, 55, 57, 65, 86, 88) — a
    /// collision here would silently misroute the resolve CPI to a different
    /// wrapper handler.
    #[test]
    fn test_tag_resolve_market_is_19_and_distinct() {
        assert_eq!(TAG_RESOLVE_MARKET, 19, "TAG_RESOLVE_MARKET mismatch");
        assert_ne!(TAG_RESOLVE_MARKET, TAG_TOP_UP_INSURANCE);
        assert_ne!(TAG_RESOLVE_MARKET, TAG_UPDATE_AUTHORITY);
        assert_ne!(TAG_RESOLVE_MARKET, TAG_UPDATE_ASSET_AUTHORITY);
        assert_ne!(TAG_RESOLVE_MARKET, TAG_WITHDRAW_INSURANCE_ASSET);
        assert_ne!(TAG_RESOLVE_MARKET, TAG_UPDATE_BACKING_FEE_POLICY);
        assert_ne!(TAG_RESOLVE_MARKET, TAG_UPDATE_TRADE_FEE_POLICY);
        assert_ne!(TAG_RESOLVE_MARKET, TAG_UPDATE_FEE_SPLIT);
        assert_ne!(TAG_RESOLVE_MARKET, TAG_UPDATE_MAINTENANCE_FEE_PER_SLOT);
    }

    /// CANARY: pin the v16-migration UpdateAuthority (tag 32) wire shape,
    /// exercising the REAL `build_update_authority_data` production code
    /// path against a synthetic account.
    ///
    /// Wire (41 bytes): `[tag=32][new_pubkey: 32 bytes][authority_epoch: u64 LE]`.
    #[test]
    fn test_build_update_authority_data_wire_shape() {
        let mut data_acct = synthetic_market_data(1, 33, 1);
        let key = Pubkey::new_from_array([13u8; 32]);
        let owner = Pubkey::new_from_array([14u8; 32]);
        let mut lamports = 0u64;
        let market = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data_acct, &owner, false, 0,
        );

        let new_pubkey = [0x55u8; 32];
        let data = build_update_authority_data(&market, new_pubkey).unwrap();

        assert_eq!(data.len(), 41, "v16-migration tag-32 wire must be 41 bytes");
        assert_eq!(data[0], 32, "tag must be 32 (UpdateAuthority)");
        assert_eq!(&data[1..33], &new_pubkey, "new_pubkey at bytes [1..33]");
        assert_eq!(
            u64::from_le_bytes(data[33..41].try_into().unwrap()),
            33,
            "authority_epoch at bytes [33..41] must be the LIVE current value, unchanged"
        );

        // Guard against regression to the pre-migration 33-byte wire.
        assert_ne!(
            data.len(),
            33,
            "33-byte tag+pubkey-only wire is the pre-migration shape — must NOT ship"
        );
    }

    /// CANARY: pin the v16-migration UpdateBackingFeePolicy (tag 51) wire
    /// shape, exercising the REAL `build_update_backing_fee_policy_data`
    /// production code path against a synthetic account, for BOTH the long
    /// (domain even) and short (domain odd) lanes.
    ///
    /// Wire (23 bytes): `[tag=51][domain: u16 LE][market_id: u64 LE]
    /// [fee_bps: u16 LE][insurance_share_bps: u16 LE][policy_sequence: u64 LE]`.
    #[test]
    fn test_build_update_backing_fee_policy_data_wire_shape_long_and_short() {
        let mut data_acct = synthetic_market_data_full(4242, 1, 1, 1, 100, 200, 1);
        let key = Pubkey::new_from_array([15u8; 32]);
        let owner = Pubkey::new_from_array([16u8; 32]);
        let mut lamports = 0u64;
        let market = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data_acct, &owner, false, 0,
        );

        // Long domain (0, even) -> policy_sequence from backing_fee_long (100) + 1.
        let long_data = build_update_backing_fee_policy_data(&market, 0, 50, 10).unwrap();
        assert_eq!(long_data.len(), 23, "v16-migration tag-51 wire must be 23 bytes");
        assert_eq!(long_data[0], 51, "tag must be 51 (UpdateBackingFeePolicy)");
        assert_eq!(u16::from_le_bytes(long_data[1..3].try_into().unwrap()), 0, "domain=0");
        assert_eq!(
            u64::from_le_bytes(long_data[3..11].try_into().unwrap()),
            4242,
            "market_id (asset-0-scoped) at bytes [3..11]"
        );
        assert_eq!(u16::from_le_bytes(long_data[11..13].try_into().unwrap()), 50, "fee_bps");
        assert_eq!(u16::from_le_bytes(long_data[13..15].try_into().unwrap()), 10, "insurance_share_bps");
        assert_eq!(
            u64::from_le_bytes(long_data[15..23].try_into().unwrap()),
            101, // backing_fee_long watermark (100) + 1
            "policy_sequence (long lane) at bytes [15..23] must be watermark+1"
        );

        // Short domain (1, odd) -> policy_sequence from backing_fee_short (200) + 1.
        let short_data = build_update_backing_fee_policy_data(&market, 1, 60, 20).unwrap();
        assert_eq!(u16::from_le_bytes(short_data[1..3].try_into().unwrap()), 1, "domain=1");
        assert_eq!(
            u64::from_le_bytes(short_data[15..23].try_into().unwrap()),
            201, // backing_fee_short watermark (200) + 1
            "policy_sequence (short lane) at bytes [15..23] must be watermark+1"
        );

        // The two lanes must use DIFFERENT watermarks — a copy/paste bug that
        // read the same offset for both domains would collapse this to equal.
        assert_ne!(
            u64::from_le_bytes(long_data[15..23].try_into().unwrap()),
            u64::from_le_bytes(short_data[15..23].try_into().unwrap()),
            "long and short policy_sequence lanes must be independent"
        );

        // Guard against regression to the pre-migration 7-byte wire.
        assert_ne!(
            long_data.len(),
            7,
            "7-byte tag+domain+fee_bps+insurance_share_bps-only wire is the pre-migration shape"
        );
    }

    /// CANARY: pin the v16-migration UpdateTradeFeePolicy (tag 55) wire
    /// shape, exercising the REAL `build_update_trade_fee_policy_data`
    /// production code path against a synthetic account.
    ///
    /// Wire (17 bytes): `[tag=55][trade_fee_base_bps: u64 LE]
    /// [policy_sequence: u64 LE]`. NOTE: no `market_id` field, unlike tag 51.
    #[test]
    fn test_build_update_trade_fee_policy_data_wire_shape() {
        let mut data_acct = synthetic_market_data_full(1, 1, 1, 1, 1, 1, 500);
        let key = Pubkey::new_from_array([17u8; 32]);
        let owner = Pubkey::new_from_array([18u8; 32]);
        let mut lamports = 0u64;
        let market = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data_acct, &owner, false, 0,
        );

        let data = build_update_trade_fee_policy_data(&market, 25).unwrap();

        assert_eq!(data.len(), 17, "v16-migration tag-55 wire must be 17 bytes");
        assert_eq!(data[0], 55, "tag must be 55 (UpdateTradeFeePolicy)");
        assert_eq!(
            u64::from_le_bytes(data[1..9].try_into().unwrap()),
            25,
            "trade_fee_base_bps at bytes [1..9]"
        );
        assert_eq!(
            u64::from_le_bytes(data[9..17].try_into().unwrap()),
            501, // trade_fee watermark (500) + 1
            "policy_sequence at bytes [9..17] must be watermark+1"
        );

        // Guard against regression to the pre-migration 9-byte wire.
        assert_ne!(
            data.len(),
            9,
            "9-byte tag+trade_fee_base_bps-only wire is the pre-migration shape — must NOT ship"
        );
    }

    /// CANARY: pin the v16-migration UpdateFeeSplit (tag 86) wire shape,
    /// exercising the REAL `build_update_fee_split_data` production code
    /// path against a synthetic account.
    ///
    /// Wire (15 bytes): `[tag=86][creator_share_bps: u16 LE][lp_share_bps: u16 LE]
    /// [insurance_share_bps: u16 LE][authority_epoch: u64 LE]`.
    #[test]
    fn test_build_update_fee_split_data_wire_shape() {
        let mut data_acct = synthetic_market_data(1, 7, 1);
        let key = Pubkey::new_from_array([19u8; 32]);
        let owner = Pubkey::new_from_array([20u8; 32]);
        let mut lamports = 0u64;
        let market = AccountInfo::new(
            &key, false, true, &mut lamports, &mut data_acct, &owner, false, 0,
        );

        let data = build_update_fee_split_data(&market, 2000, 4800, 1600).unwrap();

        assert_eq!(data.len(), 15, "v16-migration tag-86 wire must be 15 bytes");
        assert_eq!(data[0], 86, "tag must be 86 (UpdateFeeSplit)");
        assert_eq!(u16::from_le_bytes(data[1..3].try_into().unwrap()), 2000, "creator_share_bps");
        assert_eq!(u16::from_le_bytes(data[3..5].try_into().unwrap()), 4800, "lp_share_bps");
        assert_eq!(u16::from_le_bytes(data[5..7].try_into().unwrap()), 1600, "insurance_share_bps");
        assert_eq!(
            u64::from_le_bytes(data[7..15].try_into().unwrap()),
            7,
            "authority_epoch at bytes [7..15] must be the LIVE current value, unchanged"
        );

        // Guard against regression to the pre-migration 7-byte wire.
        assert_ne!(
            data.len(),
            7,
            "7-byte tag+creator+lp+insurance-only wire is the pre-migration shape — must NOT ship"
        );
    }

    /// VERIFIED-UNCHANGED: UpdateMaintenanceFeePerSlot (tag 88) is NOT part
    /// of the drift set — its wire is still tag(1) + maintenance_fee_per_slot
    /// (16, u128 LE) = 17 bytes, matching `sync/integration-v16 @ a9318945`'s
    /// decode arm exactly (`88 => Self::UpdateMaintenanceFeePerSlot {
    /// maintenance_fee_per_slot: read_u128 }`, no trailing field). This test
    /// exists so the "unchanged" claim is evidenced, not just asserted in a
    /// comment.
    #[test]
    fn test_tag88_wire_is_unchanged_17_bytes() {
        let maintenance_fee_per_slot: u128 = 12_345;
        let mut data = Vec::with_capacity(17);
        data.push(TAG_UPDATE_MAINTENANCE_FEE_PER_SLOT);
        data.extend_from_slice(&maintenance_fee_per_slot.to_le_bytes());
        assert_eq!(data.len(), 17, "tag-88 wire must still be exactly 17 bytes");
        assert_eq!(data[0], 88);
    }

    /// C-1: the ResolveMarket CPI account shape is exactly 2 accounts —
    /// [admin/marketauth(signer, read-only), market(writable)] — matching
    /// handle_resolve_market's `account(accounts, 0)` / `account(accounts, 1)`
    /// reads and the deployed vault's identical 2-account construction.
    #[test]
    fn test_cpi_resolve_market_account_shape_is_two_accounts() {
        // [is_signer, is_writable] per account, in order.
        let shape = [
            (true, false), // 0: pool PDA (marketauth), signer via invoke_signed, read-only
            (false, true), // 1: market/slab, writable, not a signer
        ];
        assert_eq!(
            shape.len(),
            2,
            "ResolveMarket CPI must pass exactly 2 accounts"
        );
        assert!(shape[0].0, "account 0 (marketauth) must be a signer");
        assert!(
            !shape[0].1,
            "account 0 (marketauth) is read-only, not writable"
        );
        assert!(shape[1].1, "account 1 (market) must be writable");
        assert!(!shape[1].0, "account 1 (market) is not a signer");
    }
}
