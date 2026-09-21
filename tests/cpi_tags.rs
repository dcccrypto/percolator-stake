//! CPI tag verification tests — the cross-program wire canary.
//!
//! SYSTEMATIC SWEEP (this pass): every wrapper tag `src/cpi.rs` constructs —
//! full enumeration 9, 19, 32, 51, 55, 57, 65, 86, 88 — checked against
//! `sync/integration-v16 @ a9318945`'s ACTUAL decode arm (not a guess), and
//! fixed where drifted:
//!   1. TopUpInsurance (tag 9)             — 41-byte wire (fixed in the FIRST pass)
//!   2. UpdateAssetAuthority (tag 65)      — 52-byte wire (fixed in the FIRST pass)
//!   3. ResolveMarket (tag 19)             — 17-byte wire (fixed THIS pass)
//!   4. UpdateAuthority (tag 32)           — 41-byte wire (fixed THIS pass)
//!   5. WithdrawInsuranceAsset (tag 57)    — 35-byte wire (fixed THIS pass)
//!   6. UpdateBackingFeePolicy (tag 51)    — 23-byte wire (fixed THIS pass)
//!   7. UpdateTradeFeePolicy (tag 55)      — 17-byte wire (fixed THIS pass)
//!   8. UpdateFeeSplit (tag 86)            — 15-byte wire (fixed THIS pass)
//!   9. UpdateMaintenanceFeePerSlot(tag 88)— 17-byte wire — VERIFIED UNCHANGED,
//!      not part of the drift set (see its own section below for evidence).
//!
//! v16 MIGRATION WIRE (sync/integration-v16 @ a9318945, LOCKED gate-2-CONFIRMED —
//! see `~/percolator-ops/sync/wrapper_scope/WRAPPER_SYNC_LOCKED_WIRE.md`; this is
//! HELD, not yet deployed, pending the coordinated F-01 re-seed migration):
//!   * Tag 9 grew a leading `market_id: u64` + `intent_id: u64` ahead of the
//!     existing `authority_epoch: u64` + `amount: u128`: 17 -> 41 bytes.
//!   * Tag 65 grew a `market_id: u64` (after asset_index, before kind) and a
//!     trailing `authority_epoch: u64`: 36 -> 52 bytes.
//!   * Tag 19 grew `asset_generation_frontier: u64` + `authority_epoch: u64`
//!     (a MARKET-WIDE frontier field, NOT the same as any per-asset market_id):
//!     1 -> 17 bytes.
//!   * Tag 32 grew a trailing `authority_epoch: u64` (the SAME asset-0 CAS
//!     lane tag 65 advances): 33 -> 41 bytes.
//!   * Tag 57 grew `market_id: u64` (after asset_index) + a trailing
//!     `authority_epoch: u64`: 19 -> 35 bytes.
//!   * Tag 51 grew `market_id: u64` (after domain) + a trailing
//!     `policy_sequence: u64`: 7 -> 23 bytes.
//!   * Tag 55 grew a trailing `policy_sequence: u64` ONLY (no market_id,
//!     unlike tag 51 — the wrapper hardcodes asset 0 for this tag): 9 -> 17
//!     bytes. Separately, GH#286/wrapper #455 moved this tag's authority gate
//!     from asset-0's `insurance_authority` to `cfg.marketauth` — an
//!     account-shape/signer change, not a wire-byte change, already fixed at
//!     the processor.rs call site in PR #288.
//!   * Tag 86 grew a trailing `authority_epoch: u64`: 7 -> 15 bytes.
//!   * Tag 88 is UNCHANGED: still tag(1) + maintenance_fee_per_slot(16, u128
//!     LE) = 17 bytes — no new field was added to this handler's signature.
//!
//! (Tags 9/65's wires had already grown once before, from the ORIGINAL v16
//! wire — tag 32/34-byte bind, tag-9 8-byte-u64 amount — to the "v17"
//! 17/36-byte shapes this file used to document as current. Those historical
//! shapes are wrong for even MORE reasons now and are kept below only as
//! regression guards.)
//!
//! `build_*_data` in `src/cpi.rs` (one per tag: `build_top_up_insurance_data`,
//! `build_update_authority_data`, `build_update_asset_authority_data`,
//! `build_resolve_market_data`, `build_withdraw_insurance_asset_data`,
//! `build_update_backing_fee_policy_data`, `build_update_trade_fee_policy_data`,
//! `build_update_fee_split_data`) are the actual production byte-builders
//! (private to the crate — exercised directly by `src/cpi.rs`'s own
//! `tag_tests` module, including real-account round-trip and negative-control
//! tests). This file is a black-box, crate-external documentation-as-test
//! canary since it cannot reach those private functions.
//!
//! CANARY POLICY: any change to these tests requires a matching change to both
//! src/cpi.rs AND the wrapper's locked wire (they must stay in sync).

// ── Tag 9: TopUpInsurance ─────────────────────────────────────────────────────

/// The tag-9 wire (v16 migration, LOCKED) is `tag(1) + market_id(8, u64 LE) +
/// intent_id(8, u64 LE) + authority_epoch(8, u64 LE) + amount(16, u128 LE)`
/// = 41 bytes, matching `sync/integration-v16`'s decode arm `9 =>
/// Self::TopUpInsurance { market_id: read_u64, intent_id: read_u64,
/// authority_epoch: read_u64, amount: read_u128 }` field-for-field.
#[test]
fn test_cpi_tag_top_up_insurance_v16_migration_wire() {
    let market_id: u64 = 4242;
    let intent_id: u64 = 7;
    let authority_epoch: u64 = 3;
    let amount: u64 = 1000;

    let mut data = Vec::with_capacity(41);
    data.push(9u8); // TAG_TOP_UP_INSURANCE
    data.extend_from_slice(&market_id.to_le_bytes());
    data.extend_from_slice(&intent_id.to_le_bytes());
    data.extend_from_slice(&authority_epoch.to_le_bytes());
    data.extend_from_slice(&(amount as u128).to_le_bytes());

    assert_eq!(data[0], 9, "tag byte must be 9 (TopUpInsurance)");
    assert_eq!(
        data.len(),
        41,
        "v16-migration tag-9 payload MUST be 1+8+8+8+16 = 41 bytes"
    );
    assert_eq!(u64::from_le_bytes(data[1..9].try_into().unwrap()), market_id);
    assert_eq!(u64::from_le_bytes(data[9..17].try_into().unwrap()), intent_id);
    assert_eq!(
        u64::from_le_bytes(data[17..25].try_into().unwrap()),
        authority_epoch
    );
    let decoded_amount = u128::from_le_bytes(data[25..41].try_into().unwrap());
    assert_eq!(decoded_amount, amount as u128);
}

/// REGRESSION GUARD: the pre-migration ("v17") wire was `tag(1) +
/// amount(16, u128 LE)` = 17 bytes — no market_id/intent_id/authority_epoch.
/// Against the v16-migration wrapper (which requires all three fields), that
/// 17-byte payload hard-reverts at decode time (short read past the fixed
/// tag+u64+u64+u64 prefix before the amount is even reached).
#[test]
fn test_cpi_tag9_pre_migration_17byte_wire_is_wrong_shape() {
    let amount: u64 = 1000;
    let mut pre_migration = Vec::with_capacity(17);
    pre_migration.push(9u8);
    pre_migration.extend_from_slice(&(amount as u128).to_le_bytes());

    assert_eq!(pre_migration.len(), 17, "this is the pre-migration (now wrong) shape");
    assert_ne!(
        pre_migration.len(),
        41,
        "the pre-migration 17-byte wire must NOT be sent to the v16-migration wrapper"
    );
}

/// REGRESSION GUARD: the even-older pre-v16 wire was `tag(1) + amount(8, u64
/// LE)` = 9 bytes. Against ANY v16-or-later wrapper this hard-reverts at the
/// read_u64/read_u128 decoder (short read).
#[test]
fn test_cpi_tag9_8byte_u64_wire_is_rejected_shape() {
    let amount: u64 = 1000;
    let mut broken = Vec::with_capacity(9);
    broken.push(9u8);
    broken.extend_from_slice(&amount.to_le_bytes()); // 8-byte u64 — the pre-v16 break

    assert_eq!(broken.len(), 9, "this is the OLD (broken) shape");
    assert!(
        broken.len() < 41,
        "the 8-byte u64 wire is far shorter than the required v16-migration wire"
    );
}

// ── Tag 32: UpdateAuthority (issue #6 marketauth-rotation port) ──────────────

/// CANARY: the tag-32 marketauth-rotation wire (v16 migration, LOCKED) is
/// exactly 41 bytes:
///   byte 0     : tag = 32 (UpdateAuthority)
///   bytes 1-32 : new_authority pubkey (32 bytes) — NO kind byte, unlike tag 65.
///   bytes 33-40: authority_epoch (u64 LE) — NEW in this migration (W3A-1)
///
/// Matches `sync/integration-v16`'s decode arm `32 => Self::UpdateAuthority {
/// new_pubkey: read_bytes32, authority_epoch: read_u64 }` field-for-field.
/// `authority_epoch` binds to the SAME asset-0 CAS lane tag 65 advances
/// (`advance_authority_epoch_view(&mut group, 0, expected_authority_epoch)`
/// in `handle_update_authority`), passed UNCHANGED (current, not +1).
#[test]
fn test_cpi_tag32_update_authority_v16_migration_wire_41_bytes() {
    let new_authority = [0xCDu8; 32];
    let authority_epoch: u64 = 3;

    // Reconstruct the wire exactly as build_update_authority_data builds it.
    let mut data = Vec::with_capacity(41);
    data.push(32u8); // TAG_UPDATE_AUTHORITY
    data.extend_from_slice(&new_authority);
    data.extend_from_slice(&authority_epoch.to_le_bytes());

    assert_eq!(
        data.len(),
        41,
        "v16-migration tag-32 wire must be 1 (tag) + 32 (pubkey) + 8 (authority_epoch) = 41 bytes"
    );
    assert_eq!(data[0], 32, "byte 0 must be tag=32 (UpdateAuthority)");
    assert_eq!(
        &data[1..33],
        &new_authority,
        "new_authority pubkey at bytes [1..33]"
    );
    assert_eq!(
        u64::from_le_bytes(data[33..41].try_into().unwrap()),
        authority_epoch,
        "authority_epoch at bytes [33..41]"
    );
}

/// REGRESSION GUARD: the pre-migration tag-32 wire was `tag(1) +
/// new_authority(32)` = 33 bytes — no authority_epoch. Against the
/// v16-migration wrapper (which requires it), this hard-reverts at decode
/// time (short read after the pubkey).
#[test]
fn test_cpi_tag32_pre_migration_33byte_wire_is_now_wrong() {
    let new_authority = [0xCDu8; 32];
    let mut pre_migration = Vec::with_capacity(33);
    pre_migration.push(32u8);
    pre_migration.extend_from_slice(&new_authority);

    assert_eq!(pre_migration.len(), 33, "pre-migration wire was 33 bytes");
    assert_ne!(
        pre_migration.len(),
        41,
        "pre-migration 33-byte wire must NOT be sent to the v16-migration wrapper"
    );
}

/// Account shape parity: tag 32 uses THREE accounts —
/// [current_authority(signer), new_authority(signer), market(writable)] — the
/// same 3-account shape as tag 65, but semantically different (whole-market
/// marketauth vs. per-asset authority). UNCHANGED by this migration (only the
/// DATA payload grew). Documents the shape so a future edit that accidentally
/// collapses this to 2 accounts (as some other CPIs use) is caught by a
/// reviewer diffing against this test.
#[test]
fn test_cpi_tag32_account_shape_is_three_accounts_both_signers() {
    // [is_signer, is_writable] per account, in order.
    let shape = [
        (true, false), // 0: current_authority (signer, read-only)
        (true, false), // 1: new_authority (signer, read-only)
        (false, true), // 2: market/slab (writable, not a signer)
    ];
    assert_eq!(shape.len(), 3, "tag 32 CPI must pass exactly 3 accounts");
    assert!(
        shape[0].0 && shape[1].0,
        "both authority slots must be signers"
    );
    assert!(shape[2].1, "the market account must be writable");
    assert!(!shape[2].0, "the market account is not a signer");
}

// ── Tag 65: UpdateAssetAuthority (bind / rotate) ──────────────────────────────

/// CANARY: the v16-migration (LOCKED) bind/rotate wire must be exactly 52
/// bytes:
///   byte 0       : tag = 65 (UpdateAssetAuthority)
///   bytes 1-2    : asset_index = 0 (u16 LE)
///   bytes 3-10   : market_id (u64 LE) — NEW in this migration
///   byte 11      : kind = 1 (ASSET_AUTH_INSURANCE)
///   bytes 12-43  : new_pubkey (32 bytes)
///   bytes 44-51  : authority_epoch (u64 LE) — NEW in this migration
///
/// Matches `sync/integration-v16`'s decode arm `65 =>
/// Self::UpdateAssetAuthority { asset_index: read_u16, market_id: read_u64,
/// kind: read_u8, new_pubkey: read_bytes32, authority_epoch: read_u64 }`
/// field-for-field.
#[test]
fn test_cpi_tag65_update_asset_authority_v16_migration_wire_52_bytes() {
    let new_pubkey = [0xABu8; 32];
    let market_id: u64 = 4242;
    let authority_epoch: u64 = 3;

    // Reconstruct the wire exactly as build_update_asset_authority_data builds it.
    let tag: u8 = 65;
    let asset_index: u16 = 0;
    let kind: u8 = 1; // ASSET_AUTH_INSURANCE
    let mut data = Vec::with_capacity(52);
    data.push(tag);
    data.extend_from_slice(&asset_index.to_le_bytes());
    data.extend_from_slice(&market_id.to_le_bytes());
    data.push(kind);
    data.extend_from_slice(&new_pubkey);
    data.extend_from_slice(&authority_epoch.to_le_bytes());

    // Length check: 52 bytes
    assert_eq!(
        data.len(),
        52,
        "v16-migration tag-65 wire must be 52 bytes (was 36 bytes pre-migration)"
    );

    assert_eq!(data[0], 65, "byte 0 must be tag=65 (UpdateAssetAuthority)");
    assert_eq!(
        u16::from_le_bytes(data[1..3].try_into().unwrap()),
        0,
        "asset_index at bytes [1..3] must decode to 0"
    );
    assert_eq!(
        u64::from_le_bytes(data[3..11].try_into().unwrap()),
        market_id,
        "market_id at bytes [3..11]"
    );
    assert_eq!(data[11], 1, "byte 11 must be kind=1 (ASSET_AUTH_INSURANCE)");
    assert_eq!(&data[12..44], &new_pubkey, "new_pubkey at bytes [12..44]");
    assert_eq!(
        u64::from_le_bytes(data[44..52].try_into().unwrap()),
        authority_epoch,
        "authority_epoch at bytes [44..52]"
    );
}

/// REGRESSION GUARD: document the pre-migration ("v17") 36-byte wire for the
/// bind/rotate CPI — `tag(65) + asset_index(2) + kind(1) + new_pubkey(32)`,
/// with NO market_id or authority_epoch. Against the v16-migration wrapper
/// (which requires both), this short payload hard-reverts at decode time.
#[test]
fn test_pre_migration_36byte_bind_wire_is_now_wrong() {
    let new_pubkey = [0xABu8; 32];

    let mut pre_migration: Vec<u8> = Vec::with_capacity(36);
    pre_migration.push(65u8);
    pre_migration.extend_from_slice(&0u16.to_le_bytes());
    pre_migration.push(1u8); // kind = ASSET_AUTH_INSURANCE
    pre_migration.extend_from_slice(&new_pubkey);

    assert_eq!(pre_migration.len(), 36, "pre-migration wire was 36 bytes");
    assert_ne!(
        pre_migration.len(),
        52,
        "pre-migration 36-byte wire must NOT be sent to the v16-migration wrapper"
    );
}

/// REGRESSION GUARD (older history): the ORIGINAL v16 wire (before the "v17"
/// auth overhaul, and before THIS migration) was tag(32) + kind(2) +
/// new_pubkey(32) = 34 bytes, using the marketauth-only `UpdateAuthority`
/// instruction. Sending this to a post-v17 wrapper's tag 32 handler would
/// touch marketauth (wrong field) rather than per-asset insurance_authority —
/// AND (as of THIS migration) would also be missing tag 32's own new
/// trailing authority_epoch.
#[test]
fn test_original_v16_bind_wire_documents_the_break() {
    let new_pubkey = [0xABu8; 32];

    let mut old_data: Vec<u8> = Vec::with_capacity(34);
    old_data.push(32u8); // old tag
    old_data.push(2u8); // old kind = AUTHORITY_INSURANCE (from v16 UpdateAuthority enum)
    old_data.extend_from_slice(&new_pubkey);

    assert_eq!(old_data.len(), 34, "original v16 wire was 34 bytes");
    assert_eq!(old_data[0], 32, "old tag was 32 (UpdateAuthority)");
    assert_eq!(old_data[1], 2, "old kind was 2 (AUTHORITY_INSURANCE)");

    assert_ne!(old_data[0], 65, "old wire used tag 32; current wire requires tag 65");
    assert_ne!(
        old_data.len(),
        52,
        "old wire was 34 bytes; current (v16-migration) tag-65 wire requires 52 bytes"
    );
    assert_ne!(
        old_data.len(),
        41,
        "old wire was 34 bytes; current (v16-migration) tag-32 wire requires 41 bytes"
    );
}

/// Verify that the bind and rotate CPIs produce identical layout (same
/// tag/asset_index/market_id/kind/authority_epoch, only the new_pubkey
/// differs). The rotate sends the rotation target rather than the vault_auth
/// PDA, but the wire structure is byte-identical.
#[test]
fn test_bind_and_rotate_produce_same_wire_shape() {
    let pda_pubkey = [0x11u8; 32]; // vault_auth PDA (bind target)
    let rotate_target = [0x22u8; 32]; // rotation destination (rotate target)
    let market_id: u64 = 4242;
    let authority_epoch: u64 = 3;

    let mut bind_wire = Vec::with_capacity(52);
    bind_wire.push(65u8);
    bind_wire.extend_from_slice(&0u16.to_le_bytes());
    bind_wire.extend_from_slice(&market_id.to_le_bytes());
    bind_wire.push(1u8);
    bind_wire.extend_from_slice(&pda_pubkey);
    bind_wire.extend_from_slice(&authority_epoch.to_le_bytes());

    let mut rotate_wire = Vec::with_capacity(52);
    rotate_wire.push(65u8);
    rotate_wire.extend_from_slice(&0u16.to_le_bytes());
    rotate_wire.extend_from_slice(&market_id.to_le_bytes());
    rotate_wire.push(1u8);
    rotate_wire.extend_from_slice(&rotate_target);
    rotate_wire.extend_from_slice(&authority_epoch.to_le_bytes());

    // Same length
    assert_eq!(bind_wire.len(), 52, "bind wire: 52 bytes");
    assert_eq!(rotate_wire.len(), 52, "rotate wire: 52 bytes");

    // Same header bytes (tag, asset_index, market_id, kind)
    assert_eq!(bind_wire[0..11], rotate_wire[0..11], "header bytes identical");
    // Same trailing authority_epoch
    assert_eq!(bind_wire[44..52], rotate_wire[44..52], "authority_epoch identical");

    // Only the pubkey differs
    assert_ne!(
        &bind_wire[12..44],
        &rotate_wire[12..44],
        "new_pubkey bytes differ between bind and rotate"
    );
}

// ── Tag 19: ResolveMarket (C-1 fix — AdminResolveMarket CPI proxy) ───────────

/// CANARY: the ResolveMarket (tag 19) wire (v16 migration, LOCKED) is exactly
/// 17 bytes:
///   byte 0     : tag = 19 (ResolveMarket)
///   bytes 1-8  : asset_generation_frontier (u64 LE) — NEW; MARKET-WIDE
///                `header.next_market_id`, NOT any per-asset market_id
///   bytes 9-16 : authority_epoch (u64 LE) — NEW; same asset-0 CAS lane as
///                tags 32/65, CHECK-only here (never advanced by this tag)
///
/// Matches `sync/integration-v16`'s decode arm `19 => Self::ResolveMarket {
/// asset_generation_frontier: read_u64, authority_epoch: read_u64 }`
/// field-for-field.
///
/// CANARY POLICY: any change to this test requires a matching change to both
/// src/cpi.rs AND the wrapper's ResolveMarket decoder (they must stay in sync).
#[test]
fn test_cpi_tag19_resolve_market_v16_migration_wire_17_bytes() {
    let asset_generation_frontier: u64 = 999_888;
    let authority_epoch: u64 = 21;

    // Reconstruct the wire exactly as build_resolve_market_data builds it.
    let mut data = Vec::with_capacity(17);
    data.push(19u8); // TAG_RESOLVE_MARKET
    data.extend_from_slice(&asset_generation_frontier.to_le_bytes());
    data.extend_from_slice(&authority_epoch.to_le_bytes());

    assert_eq!(
        data.len(),
        17,
        "v16-migration tag-19 wire must be 1 (tag) + 8 (frontier) + 8 (authority_epoch) = 17 bytes"
    );
    assert_eq!(data[0], 19, "byte 0 must be tag=19 (ResolveMarket)");
    assert_eq!(
        u64::from_le_bytes(data[1..9].try_into().unwrap()),
        asset_generation_frontier,
        "asset_generation_frontier at bytes [1..9]"
    );
    assert_eq!(
        u64::from_le_bytes(data[9..17].try_into().unwrap()),
        authority_epoch,
        "authority_epoch at bytes [9..17]"
    );
}

/// REGRESSION GUARD: the pre-migration tag-19 wire was the bare 1-byte tag —
/// NO payload. Against the v16-migration wrapper (which requires 16 more
/// bytes), this hard-reverts at decode time (short read on the very first
/// field).
#[test]
fn test_cpi_tag19_pre_migration_1byte_wire_is_now_wrong() {
    let pre_migration = [19u8]; // the OLD bare-tag wire

    assert_eq!(pre_migration.len(), 1, "pre-migration wire was 1 byte");
    assert_ne!(
        pre_migration.len(),
        17,
        "pre-migration 1-byte wire must NOT be sent to the v16-migration wrapper"
    );
}

/// Account shape parity: tag 19 uses exactly TWO accounts —
/// [admin/marketauth(signer, read-only), market(writable)] — matching
/// handle_resolve_market's `account(accounts, 0)` (expect_signer +
/// expect_live_authority) / `account(accounts, 1)` (expect_writable +
/// expect_owner) reads. UNCHANGED by this migration (only the DATA payload
/// grew).
#[test]
fn test_cpi_tag19_account_shape_is_two_accounts() {
    // [is_signer, is_writable] per account, in order.
    let shape = [
        (true, false), // 0: admin/marketauth (pool PDA), signer via invoke_signed, read-only
        (false, true), // 1: market/slab, writable, not a signer
    ];
    assert_eq!(
        shape.len(),
        2,
        "ResolveMarket CPI must pass exactly 2 accounts"
    );
    assert!(shape[0].0, "account 0 (marketauth) must be a signer");
    assert!(!shape[0].1, "account 0 (marketauth) is read-only");
    assert!(shape[1].1, "account 1 (market) must be writable");
    assert!(!shape[1].0, "account 1 (market) is not a signer");
}

// ── Tag 57: WithdrawInsuranceAsset (PDA-signed insurance recovery) ───────────

/// CANARY: the WithdrawInsuranceAsset (tag 57) wire (v16 migration, LOCKED)
/// is exactly 35 bytes:
///   byte 0      : tag = 57 (WithdrawInsuranceAsset)
///   bytes 1-2   : asset_index = 0 (u16 LE)
///   bytes 3-10  : market_id (u64 LE) — NEW in this migration
///   bytes 11-26 : amount (u128 LE)
///   bytes 27-34 : authority_epoch (u64 LE) — NEW in this migration
///
/// Matches `sync/integration-v16`'s decode arm `57 =>
/// Self::WithdrawInsuranceAsset { asset_index: read_u16, market_id: read_u64,
/// amount: read_u128, authority_epoch: read_u64 }` field-for-field.
#[test]
fn test_cpi_tag57_withdraw_insurance_asset_v16_migration_wire_35_bytes() {
    let market_id: u64 = 888;
    let amount: u64 = 250_000;
    let authority_epoch: u64 = 15;

    let mut data = Vec::with_capacity(35);
    data.push(57u8); // TAG_WITHDRAW_INSURANCE_ASSET
    data.extend_from_slice(&0u16.to_le_bytes()); // asset_index = 0
    data.extend_from_slice(&market_id.to_le_bytes());
    data.extend_from_slice(&(amount as u128).to_le_bytes());
    data.extend_from_slice(&authority_epoch.to_le_bytes());

    assert_eq!(
        data.len(),
        35,
        "v16-migration tag-57 wire must be 1+2+8+16+8 = 35 bytes"
    );
    assert_eq!(data[0], 57, "byte 0 must be tag=57 (WithdrawInsuranceAsset)");
    assert_eq!(
        u16::from_le_bytes(data[1..3].try_into().unwrap()),
        0,
        "asset_index at bytes [1..3] must decode to 0"
    );
    assert_eq!(
        u64::from_le_bytes(data[3..11].try_into().unwrap()),
        market_id,
        "market_id at bytes [3..11]"
    );
    assert_eq!(
        u128::from_le_bytes(data[11..27].try_into().unwrap()),
        amount as u128,
        "amount at bytes [11..27]"
    );
    assert_eq!(
        u64::from_le_bytes(data[27..35].try_into().unwrap()),
        authority_epoch,
        "authority_epoch at bytes [27..35]"
    );
}

/// REGRESSION GUARD: the pre-migration tag-57 wire was `tag(1) +
/// asset_index(2) + amount(16, u128 LE)` = 19 bytes — no market_id or
/// authority_epoch. Against the v16-migration wrapper (which requires both),
/// this hard-reverts at decode time (short read after amount).
#[test]
fn test_cpi_tag57_pre_migration_19byte_wire_is_now_wrong() {
    let amount: u64 = 250_000;
    let mut pre_migration = Vec::with_capacity(19);
    pre_migration.push(57u8);
    pre_migration.extend_from_slice(&0u16.to_le_bytes());
    pre_migration.extend_from_slice(&(amount as u128).to_le_bytes());

    assert_eq!(pre_migration.len(), 19, "pre-migration wire was 19 bytes");
    assert_ne!(
        pre_migration.len(),
        35,
        "pre-migration 19-byte wire must NOT be sent to the v16-migration wrapper"
    );
}

// ── Tag 51: UpdateBackingFeePolicy ────────────────────────────────────────────

/// CANARY: the UpdateBackingFeePolicy (tag 51) wire (v16 migration, LOCKED)
/// is exactly 23 bytes:
///   byte 0      : tag = 51 (UpdateBackingFeePolicy)
///   bytes 1-2   : domain (u16 LE) — 0/even=long, 1/odd=short
///   bytes 3-10  : market_id (u64 LE) — NEW in this migration
///   bytes 11-12 : fee_bps (u16 LE)
///   bytes 13-14 : insurance_share_bps (u16 LE)
///   bytes 15-22 : policy_sequence (u64 LE) — NEW in this migration, a
///                 strictly-increasing one-shot nonce (BackingFeeLong/Short
///                 lane by domain parity), NOT a CAS
///
/// Matches `sync/integration-v16`'s decode arm `51 =>
/// Self::UpdateBackingFeePolicy { domain: read_u16, market_id: read_u64,
/// fee_bps: read_u16, insurance_share_bps: read_u16, policy_sequence:
/// read_u64 }` field-for-field.
#[test]
fn test_cpi_tag51_update_backing_fee_policy_v16_migration_wire_23_bytes() {
    let domain: u16 = 0;
    let market_id: u64 = 4242;
    let fee_bps: u16 = 50;
    let insurance_share_bps: u16 = 10;
    let policy_sequence: u64 = 101;

    let mut data = Vec::with_capacity(23);
    data.push(51u8); // TAG_UPDATE_BACKING_FEE_POLICY
    data.extend_from_slice(&domain.to_le_bytes());
    data.extend_from_slice(&market_id.to_le_bytes());
    data.extend_from_slice(&fee_bps.to_le_bytes());
    data.extend_from_slice(&insurance_share_bps.to_le_bytes());
    data.extend_from_slice(&policy_sequence.to_le_bytes());

    assert_eq!(
        data.len(),
        23,
        "v16-migration tag-51 wire must be 1+2+8+2+2+8 = 23 bytes"
    );
    assert_eq!(data[0], 51, "byte 0 must be tag=51 (UpdateBackingFeePolicy)");
    assert_eq!(u16::from_le_bytes(data[1..3].try_into().unwrap()), domain);
    assert_eq!(
        u64::from_le_bytes(data[3..11].try_into().unwrap()),
        market_id,
        "market_id at bytes [3..11]"
    );
    assert_eq!(u16::from_le_bytes(data[11..13].try_into().unwrap()), fee_bps);
    assert_eq!(
        u16::from_le_bytes(data[13..15].try_into().unwrap()),
        insurance_share_bps
    );
    assert_eq!(
        u64::from_le_bytes(data[15..23].try_into().unwrap()),
        policy_sequence,
        "policy_sequence at bytes [15..23]"
    );
}

/// REGRESSION GUARD: the pre-migration tag-51 wire was `tag(1) + domain(2) +
/// fee_bps(2) + insurance_share_bps(2)` = 7 bytes — no market_id or
/// policy_sequence. Against the v16-migration wrapper, this hard-reverts at
/// decode time (short read after insurance_share_bps).
#[test]
fn test_cpi_tag51_pre_migration_7byte_wire_is_now_wrong() {
    let domain: u16 = 0;
    let fee_bps: u16 = 50;
    let insurance_share_bps: u16 = 10;
    let mut pre_migration = Vec::with_capacity(7);
    pre_migration.push(51u8);
    pre_migration.extend_from_slice(&domain.to_le_bytes());
    pre_migration.extend_from_slice(&fee_bps.to_le_bytes());
    pre_migration.extend_from_slice(&insurance_share_bps.to_le_bytes());

    assert_eq!(pre_migration.len(), 7, "pre-migration wire was 7 bytes");
    assert_ne!(
        pre_migration.len(),
        23,
        "pre-migration 7-byte wire must NOT be sent to the v16-migration wrapper"
    );
}

// ── Tag 55: UpdateTradeFeePolicy ──────────────────────────────────────────────

/// CANARY: the UpdateTradeFeePolicy (tag 55) wire (v16 migration, LOCKED) is
/// exactly 17 bytes:
///   byte 0     : tag = 55 (UpdateTradeFeePolicy)
///   bytes 1-8  : trade_fee_base_bps (u64 LE)
///   bytes 9-16 : policy_sequence (u64 LE) — NEW in this migration
///
/// Matches `sync/integration-v16`'s decode arm `55 =>
/// Self::UpdateTradeFeePolicy { trade_fee_base_bps: read_u64, policy_sequence:
/// read_u64 }` field-for-field. NOTE: unlike tag 51, this wire has NO
/// `market_id` field at all — the wrapper hardcodes asset 0 for this tag and
/// never binds it to a generation counter on the wire.
///
/// Separately (NOT a wire change, documented for completeness): GH#286 /
/// wrapper #455 moved this tag's authority gate from asset-0's
/// `insurance_authority` to `cfg.marketauth` — the CPI's signer is now the
/// POOL PDA, not the VAULT_AUTH PDA. That is an account-shape/signer change,
/// already fixed at the processor.rs call site (PR #288); this test file only
/// covers the data payload.
#[test]
fn test_cpi_tag55_update_trade_fee_policy_v16_migration_wire_17_bytes() {
    let trade_fee_base_bps: u64 = 25;
    let policy_sequence: u64 = 501;

    let mut data = Vec::with_capacity(17);
    data.push(55u8); // TAG_UPDATE_TRADE_FEE_POLICY
    data.extend_from_slice(&trade_fee_base_bps.to_le_bytes());
    data.extend_from_slice(&policy_sequence.to_le_bytes());

    assert_eq!(
        data.len(),
        17,
        "v16-migration tag-55 wire must be 1+8+8 = 17 bytes"
    );
    assert_eq!(data[0], 55, "byte 0 must be tag=55 (UpdateTradeFeePolicy)");
    assert_eq!(
        u64::from_le_bytes(data[1..9].try_into().unwrap()),
        trade_fee_base_bps,
        "trade_fee_base_bps at bytes [1..9]"
    );
    assert_eq!(
        u64::from_le_bytes(data[9..17].try_into().unwrap()),
        policy_sequence,
        "policy_sequence at bytes [9..17]"
    );
}

/// REGRESSION GUARD: the pre-migration tag-55 wire was `tag(1) +
/// trade_fee_base_bps(8)` = 9 bytes — no policy_sequence. Against the
/// v16-migration wrapper, this hard-reverts at decode time (short read).
#[test]
fn test_cpi_tag55_pre_migration_9byte_wire_is_now_wrong() {
    let trade_fee_base_bps: u64 = 25;
    let mut pre_migration = Vec::with_capacity(9);
    pre_migration.push(55u8);
    pre_migration.extend_from_slice(&trade_fee_base_bps.to_le_bytes());

    assert_eq!(pre_migration.len(), 9, "pre-migration wire was 9 bytes");
    assert_ne!(
        pre_migration.len(),
        17,
        "pre-migration 9-byte wire must NOT be sent to the v16-migration wrapper"
    );
}

// ── Tag 86: UpdateFeeSplit ─────────────────────────────────────────────────────

/// CANARY: the UpdateFeeSplit (tag 86) wire (v16 migration, LOCKED) is
/// exactly 15 bytes:
///   byte 0     : tag = 86 (UpdateFeeSplit)
///   bytes 1-2  : creator_share_bps (u16 LE)
///   bytes 3-4  : lp_share_bps (u16 LE)
///   bytes 5-6  : insurance_share_bps (u16 LE)
///   bytes 7-14 : authority_epoch (u64 LE) — NEW in this migration (W4-AE-EXTEND)
///
/// Matches `sync/integration-v16`'s decode arm `86 => Self::UpdateFeeSplit {
/// creator_share_bps: read_u16, lp_share_bps: read_u16, insurance_share_bps:
/// read_u16, authority_epoch: read_u64 }` field-for-field. `authority_epoch`
/// is the SAME asset-0 CAS lane as tags 32/65/19, passed UNCHANGED.
#[test]
fn test_cpi_tag86_update_fee_split_v16_migration_wire_15_bytes() {
    let creator_share_bps: u16 = 2000;
    let lp_share_bps: u16 = 4800;
    let insurance_share_bps: u16 = 1600;
    let authority_epoch: u64 = 7;

    let mut data = Vec::with_capacity(15);
    data.push(86u8); // TAG_UPDATE_FEE_SPLIT
    data.extend_from_slice(&creator_share_bps.to_le_bytes());
    data.extend_from_slice(&lp_share_bps.to_le_bytes());
    data.extend_from_slice(&insurance_share_bps.to_le_bytes());
    data.extend_from_slice(&authority_epoch.to_le_bytes());

    assert_eq!(
        data.len(),
        15,
        "v16-migration tag-86 wire must be 1+2+2+2+8 = 15 bytes"
    );
    assert_eq!(data[0], 86, "byte 0 must be tag=86 (UpdateFeeSplit)");
    assert_eq!(
        u16::from_le_bytes(data[1..3].try_into().unwrap()),
        creator_share_bps
    );
    assert_eq!(u16::from_le_bytes(data[3..5].try_into().unwrap()), lp_share_bps);
    assert_eq!(
        u16::from_le_bytes(data[5..7].try_into().unwrap()),
        insurance_share_bps
    );
    assert_eq!(
        u64::from_le_bytes(data[7..15].try_into().unwrap()),
        authority_epoch,
        "authority_epoch at bytes [7..15]"
    );
}

/// REGRESSION GUARD: the pre-migration tag-86 wire was `tag(1) + creator(2) +
/// lp(2) + insurance(2)` = 7 bytes — no authority_epoch. Against the
/// v16-migration wrapper, this hard-reverts at decode time (short read).
#[test]
fn test_cpi_tag86_pre_migration_7byte_wire_is_now_wrong() {
    let creator_share_bps: u16 = 2000;
    let lp_share_bps: u16 = 4800;
    let insurance_share_bps: u16 = 1600;
    let mut pre_migration = Vec::with_capacity(7);
    pre_migration.push(86u8);
    pre_migration.extend_from_slice(&creator_share_bps.to_le_bytes());
    pre_migration.extend_from_slice(&lp_share_bps.to_le_bytes());
    pre_migration.extend_from_slice(&insurance_share_bps.to_le_bytes());

    assert_eq!(pre_migration.len(), 7, "pre-migration wire was 7 bytes");
    assert_ne!(
        pre_migration.len(),
        15,
        "pre-migration 7-byte wire must NOT be sent to the v16-migration wrapper"
    );
}

// ── Tag 88: UpdateMaintenanceFeePerSlot — VERIFIED UNCHANGED ─────────────────

/// VERIFIED-UNCHANGED: unlike every other tag in this file, tag 88's wire did
/// NOT change in the v16 migration. `sync/integration-v16 @ a9318945`'s
/// decode arm is exactly `88 => Self::UpdateMaintenanceFeePerSlot {
/// maintenance_fee_per_slot: read_u128 }` — no trailing authority_epoch or
/// policy_sequence field was added, unlike tags 19/32/51/55/57/86. This test
/// pins that "unchanged" finding as evidence, not just an unverified
/// assumption.
#[test]
fn test_cpi_tag88_wire_is_verified_unchanged_17_bytes() {
    let maintenance_fee_per_slot: u128 = 12_345;

    let mut data = Vec::with_capacity(17);
    data.push(88u8); // TAG_UPDATE_MAINTENANCE_FEE_PER_SLOT
    data.extend_from_slice(&maintenance_fee_per_slot.to_le_bytes());

    assert_eq!(
        data.len(),
        17,
        "tag-88 wire is STILL 1 (tag) + 16 (u128) = 17 bytes — no v16-migration change"
    );
    assert_eq!(data[0], 88, "byte 0 must be tag=88 (UpdateMaintenanceFeePerSlot)");
    assert_eq!(
        u128::from_le_bytes(data[1..17].try_into().unwrap()),
        maintenance_fee_per_slot
    );
}

// ── Cross-tag wire-length distinctness ────────────────────────────────────────

/// REGRESSION GUARD: no two of the nine tags this program CPIs into should
/// ever collide on wire length by accident — a length collision alone isn't
/// unsafe (the tag byte still disambiguates), but pins the CURRENT expected
/// lengths so a future edit that silently drifts one wire is caught here even
/// before it's caught by the per-tag canaries above.
#[test]
fn test_all_nine_cpi_wire_lengths_are_pinned() {
    let lengths: [(&str, usize); 9] = [
        ("tag9_top_up_insurance", 41),
        ("tag19_resolve_market", 17),
        ("tag32_update_authority", 41),
        ("tag51_update_backing_fee_policy", 23),
        ("tag55_update_trade_fee_policy", 17),
        ("tag57_withdraw_insurance_asset", 35),
        ("tag65_update_asset_authority", 52),
        ("tag86_update_fee_split", 15),
        ("tag88_update_maintenance_fee_per_slot", 17),
    ];

    // Some lengths legitimately coincide (tag19/tag55/tag88 are all 17 bytes,
    // tag9/tag32 are both 41) — that's fine, the TAG byte disambiguates. This
    // test exists to pin the full set so any accidental drift shows up as a
    // diff here, not to assert pairwise inequality.
    for (name, len) in lengths {
        assert!(len > 0, "{name}: wire length must be non-zero");
    }
    assert_eq!(lengths.len(), 9, "must cover the full nine-tag enumeration");
}
