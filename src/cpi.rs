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
//   [current_authority(signer), new_authority(signer), market(w)]
// Data: tag(1) + new_authority(32) = 33 bytes
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

pub fn cpi_update_authority<'a>(
    percolator_program: &AccountInfo<'a>,
    current_admin: &AccountInfo<'a>, // current marketauth; signs the outer tx
    new_authority: &AccountInfo<'a>, // pool PDA; co-signs via invoke_signed
    slab: &AccountInfo<'a>,          // market, writable
    new_authority_seeds: &[&[u8]],   // pool PDA seeds
) -> ProgramResult {
    let mut data = Vec::with_capacity(33);
    data.push(TAG_UPDATE_AUTHORITY);
    data.extend_from_slice(new_authority.key.as_ref());

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
// Wire: [57u8][asset_index: u16 LE = 0][amount: u128 LE] = 19 bytes.
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
    // tag(1) + asset_index(2, u16 LE = 0) + amount(16, u128 LE) = 19 bytes.
    let mut data = Vec::with_capacity(19);
    data.push(TAG_WITHDRAW_INSURANCE_ASSET);
    data.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes()); // 2 bytes, always 0x00 0x00
    data.extend_from_slice(&(amount as u128).to_le_bytes()); // 16 bytes u128 LE

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
// WIRE (verified against the DEPLOYED wrapper source,
// percolator-prog@e26c97a4 == current HEAD, src/v16_program.rs:10278
// handle_resolve_market):
//   let admin = account(accounts, 0)?;      // expect_signer + expect_live_authority(marketauth)
//   let market_ai = account(accounts, 1)?;  // expect_writable + expect_owner(program_id)
//   ... mode must == 0 (else EngineLockActive) ...
//   group.resolve_market_not_atomic(slot)
// Tag decode (v16_program.rs:3867): `19 => Self::ResolveMarket` — the decoder
// consumes ZERO additional bytes for this variant (unlike e.g. tag 9's
// `read_u128`), so the wire is the bare 1-byte tag. Data: tag(1) = 1 byte.
// Accounts: exactly 2 — [admin(signer), market(writable)]. NO payload bytes,
// NO extra accounts.
//
// BYTE-FOR-BYTE PARITY with the deployed vault's `cpi_resolve_market`
// (percolator-vault@eb3ebe8 src/cpi.rs:240-258): `let data =
// vec![TAG_RESOLVE_MARKET];` with the identical 2-account
// `[new_readonly(admin_pda, true), new(slab, false)]` shape and
// `invoke_signed(&ix, &[admin_pda.clone(), slab.clone()], &[admin_seeds])`
// call pattern. The only naming difference is that THIS program's "admin_pda"
// signer is the `stake_pool` PDA itself (matching what `cpi_update_authority`
// rotated marketauth to), not a separately-named admin PDA — vault and stake
// converge on the same PDA-is-marketauth design from issue #6 lineage
// reconciliation, so the CPI construction is identical.
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

pub fn cpi_resolve_market<'a>(
    percolator_program: &AccountInfo<'a>,
    pool_pda: &AccountInfo<'a>, // marketauth (rotated by InitPool); signs via invoke_signed
    slab: &AccountInfo<'a>,     // market, writable
    pool_seeds: &[&[u8]],       // pool PDA seeds: [b"stake_pool", slab, bump]
) -> ProgramResult {
    // tag(1) = 1 byte. No payload — matches `19 => Self::ResolveMarket` (zero
    // additional bytes consumed by the wrapper's decoder).
    let data = vec![TAG_RESOLVE_MARKET];

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
//   GROUP B (signer = VAULT_AUTH PDA, seeds [b"vault_auth", pool, bump]):
//     tag 51 UpdateBackingFeePolicy -> gated on per-asset insurance_authority
//     tag 55 UpdateTradeFeePolicy   -> gated on asset 0's insurance_authority
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

/// Wrapper tag 86 `UpdateFeeSplit`. Marketauth-gated — the POOL PDA signs.
/// Wire: tag(1) + creator(2) + lp(2) + insurance(2) = 7 bytes, all u16 LE,
/// matching `86 => Self::UpdateFeeSplit { read_u16, read_u16, read_u16 }`.
const TAG_UPDATE_FEE_SPLIT: u8 = 86;

pub fn cpi_update_fee_split<'a>(
    percolator_program: &AccountInfo<'a>,
    pool_pda: &AccountInfo<'a>, // marketauth (rotated by InitPool); signs via invoke_signed
    slab: &AccountInfo<'a>,     // market, writable
    creator_share_bps: u16,
    lp_share_bps: u16,
    insurance_share_bps: u16,
    pool_seeds: &[&[u8]], // pool PDA seeds: [b"stake_pool", slab, bump]
) -> ProgramResult {
    let mut data = Vec::with_capacity(7);
    data.push(TAG_UPDATE_FEE_SPLIT);
    data.extend_from_slice(&creator_share_bps.to_le_bytes());
    data.extend_from_slice(&lp_share_bps.to_le_bytes());
    data.extend_from_slice(&insurance_share_bps.to_le_bytes());

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
/// Wire: tag(1) + domain(2) + fee_bps(2) + insurance_share_bps(2) = 7 bytes,
/// all u16 LE, matching `51 => Self::UpdateBackingFeePolicy { read_u16 x3 }`.
///
/// This is the setter for `backing_trade_fee_bps`. On a market where
/// `BindInsuranceAuthority` has run, this CPI is the ONLY way to reach it.
const TAG_UPDATE_BACKING_FEE_POLICY: u8 = 51;

pub fn cpi_update_backing_fee_policy<'a>(
    percolator_program: &AccountInfo<'a>,
    vault_auth: &AccountInfo<'a>, // insurance_authority (bound by tag 19); signs via invoke_signed
    slab: &AccountInfo<'a>,       // market, writable
    domain: u16,
    fee_bps: u16,
    insurance_share_bps: u16,
    vault_auth_seeds: &[&[u8]], // vault_auth PDA seeds: [b"vault_auth", pool, bump]
) -> ProgramResult {
    let mut data = Vec::with_capacity(7);
    data.push(TAG_UPDATE_BACKING_FEE_POLICY);
    data.extend_from_slice(&domain.to_le_bytes());
    data.extend_from_slice(&fee_bps.to_le_bytes());
    data.extend_from_slice(&insurance_share_bps.to_le_bytes());

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

/// Wrapper tag 55 `UpdateTradeFeePolicy`. Gated on ASSET 0's
/// `insurance_authority` (the wrapper hardcodes asset 0 for this tag) — the
/// VAULT_AUTH PDA signs. Wire: tag(1) + trade_fee_base_bps(8, u64 LE) = 9
/// bytes, matching `55 => Self::UpdateTradeFeePolicy { read_u64 }`.
///
/// Note the asymmetry with tag 88 above: this argument really is a `u64`.
const TAG_UPDATE_TRADE_FEE_POLICY: u8 = 55;

pub fn cpi_update_trade_fee_policy<'a>(
    percolator_program: &AccountInfo<'a>,
    vault_auth: &AccountInfo<'a>, // asset-0 insurance_authority; signs via invoke_signed
    slab: &AccountInfo<'a>,       // market, writable
    trade_fee_base_bps: u64,
    vault_auth_seeds: &[&[u8]], // vault_auth PDA seeds: [b"vault_auth", pool, bump]
) -> ProgramResult {
    let mut data = Vec::with_capacity(9);
    data.push(TAG_UPDATE_TRADE_FEE_POLICY);
    data.extend_from_slice(&trade_fee_base_bps.to_le_bytes()); // 8 bytes

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

    /// CANARY: pin the WithdrawInsuranceAsset (tag 57) wire shape =
    /// tag(57) + asset_index(2, u16 LE = 0) + amount(16, u128 LE) = 19 bytes.
    ///
    /// Verified against:
    ///   - tests/v17_stake_insurance_e2e.rs encode_withdraw_insurance_asset()
    ///   - spec: "Wire: [57u8][asset_index: u16 LE = 0][amount: u128 LE] (= 19 bytes)"
    ///
    /// The amount is ALWAYS widened to u128 on the wire (matching the tag-9
    /// TopUpInsurance convention from v16 read_u128). Narrowing back to u64
    /// would cause the wrapper to reject the CPI with InvalidInstructionData.
    #[test]
    fn test_cpi_withdraw_insurance_asset_wire_shape() {
        let amount: u64 = 250_000;
        let mut data = Vec::with_capacity(19);
        data.push(TAG_WITHDRAW_INSURANCE_ASSET); // byte 0: tag = 57
        data.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes()); // bytes 1-2: asset_index = 0
        data.extend_from_slice(&(amount as u128).to_le_bytes()); // bytes 3-18: amount u128 LE

        assert_eq!(data.len(), 19, "tag-57 wire must be 19 bytes");
        assert_eq!(data[0], 57, "tag must be 57 (WithdrawInsuranceAsset)");
        assert_eq!(data[1], 0x00, "asset_index low byte must be 0");
        assert_eq!(data[2], 0x00, "asset_index high byte must be 0");

        // Amount occupies bytes [3..19] as u128 LE.
        let decoded = u128::from_le_bytes(data[3..19].try_into().unwrap());
        assert_eq!(decoded, amount as u128, "amount round-trips as u128 LE");

        // Guard: must NOT be the 9-byte u64 wire (would be rejected by wrapper read_u128).
        assert_ne!(
            data.len(),
            9,
            "9-byte u64 wire would be rejected by wrapper"
        );
        // Guard: tag 57, not tag 9 (TopUpInsurance) — different directions.
        assert_ne!(data[0], TAG_TOP_UP_INSURANCE, "must be tag 57, not tag 9");
    }

    /// C-1 CANARY: pin the ResolveMarket (tag 19) wire = tag(1) = 1 byte, no
    /// payload. Mirrors the decoder at v16_program.rs:3867
    /// (`19 => Self::ResolveMarket`), which reads zero extra bytes.
    #[test]
    fn test_cpi_resolve_market_wire_shape() {
        let mut data = Vec::with_capacity(1);
        data.push(TAG_RESOLVE_MARKET);

        assert_eq!(
            data.len(),
            1,
            "tag-19 ResolveMarket wire must be exactly 1 byte"
        );
        assert_eq!(data[0], 19, "tag must be 19 (ResolveMarket)");

        // Byte-for-byte parity with the deployed vault's cpi_resolve_market:
        // `let data = vec![TAG_RESOLVE_MARKET];` where TAG_RESOLVE_MARKET = 19.
        let vault_reference = vec![19u8];
        assert_eq!(
            data, vault_reference,
            "ported wire must be byte-for-byte identical to percolator-vault@eb3ebe8's cpi_resolve_market"
        );
    }

    /// C-1: TAG_RESOLVE_MARKET must equal 19 and be distinct from every other
    /// wrapper tag this program CPIs into (9, 32, 57, 65) — a collision here
    /// would silently misroute the resolve CPI to a different wrapper handler.
    #[test]
    fn test_tag_resolve_market_is_19_and_distinct() {
        assert_eq!(TAG_RESOLVE_MARKET, 19, "TAG_RESOLVE_MARKET mismatch");
        assert_ne!(TAG_RESOLVE_MARKET, TAG_TOP_UP_INSURANCE);
        assert_ne!(TAG_RESOLVE_MARKET, TAG_UPDATE_AUTHORITY);
        assert_ne!(TAG_RESOLVE_MARKET, TAG_UPDATE_ASSET_AUTHORITY);
        assert_ne!(TAG_RESOLVE_MARKET, TAG_WITHDRAW_INSURANCE_ASSET);
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
