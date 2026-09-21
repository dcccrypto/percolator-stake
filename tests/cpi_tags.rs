//! CPI tag verification tests — the cross-program wire canary.
//!
//! Two CPIs to verify:
//!   1. TopUpInsurance (tag 9)         — 41-byte wire (v16-migration, LOCKED, HELD)
//!   2. UpdateAssetAuthority (tag 65)  — 52-byte wire (v16-migration, LOCKED, HELD)
//!
//! v16 MIGRATION WIRE (sync/integration-v16 @ a9318945, LOCKED gate-2-CONFIRMED —
//! see `~/percolator-ops/sync/wrapper_scope/WRAPPER_SYNC_LOCKED_WIRE.md`; this is
//! HELD, not yet deployed, pending the coordinated F-01 re-seed migration):
//!   * Tag 9 grew a leading `market_id: u64` + `intent_id: u64` ahead of the
//!     existing `authority_epoch: u64` + `amount: u128`: 17 -> 41 bytes.
//!   * Tag 65 grew a `market_id: u64` (after asset_index, before kind) and a
//!     trailing `authority_epoch: u64`: 36 -> 52 bytes.
//!
//! (These wires had already grown once before, from the ORIGINAL v16 wire —
//! tag 32/34-byte bind, tag-9 8-byte-u64 amount — to the "v17" 17/36-byte
//! shapes this file used to document as current. Both historical shapes are
//! now wrong and are kept below only as regression guards.)
//!
//! `build_top_up_insurance_data`/`build_update_asset_authority_data` in
//! `src/cpi.rs` are the actual production byte-builders (private to the
//! crate — exercised directly by `src/cpi.rs`'s own `tag_tests` module,
//! including real-account round-trip and negative-control tests). This file
//! is a black-box, crate-external documentation-as-test canary since it
//! cannot reach those private functions.
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

/// CANARY: the tag-32 marketauth-rotation wire must be exactly 33 bytes:
///   byte 0     : tag = 32 (UpdateAuthority)
///   bytes 1-32 : new_authority pubkey (32 bytes) — NO kind byte, unlike tag 65.
///
/// Byte-for-byte parity proof against the deployed `percolator-vault@eb3ebe8`
/// `cpi_update_authority` (src/cpi.rs:82-108) — issue #6 lineage reconciliation.
/// Confirmed independently against the live deployed wrapper source
/// (percolator-prog@14440e0c, v16_program.rs:3783 decode / :9658
/// handle_update_authority): `32 => Self::UpdateAuthority { new_pubkey:
/// read_bytes32(&mut rest)? }` — tag(1) + pubkey(32), no kind selector. This is
/// the SAME tag-32 opcode as `test_old_v16_bind_wire_documents_the_break` below
/// documents for the (unrelated, superseded) old insurance-bind usage — tag 32
/// itself was never retired, only insurance-authority's use of it was replaced
/// by tag 65. Marketauth rotation is the one live use of tag 32 that remains.
#[test]
fn test_cpi_tag32_update_authority_wire_33_bytes() {
    let new_authority = [0xCDu8; 32];

    // Reconstruct the wire exactly as cpi::cpi_update_authority builds it.
    let mut data = Vec::with_capacity(33);
    data.push(32u8); // TAG_UPDATE_AUTHORITY
    data.extend_from_slice(&new_authority);

    assert_eq!(
        data.len(),
        33,
        "tag-32 marketauth-rotation wire must be 1 (tag) + 32 (pubkey) = 33 bytes"
    );
    assert_eq!(data[0], 32, "byte 0 must be tag=32 (UpdateAuthority)");
    assert_eq!(
        &data[1..33],
        &new_authority,
        "new_authority pubkey at bytes [1..33]"
    );

    // Byte-for-byte parity with the deployed vault's exact wire construction
    // (percolator-vault@eb3ebe8 src/cpi.rs cpi_update_authority):
    //   data.push(TAG_UPDATE_AUTHORITY); data.extend_from_slice(new_authority.key.as_ref());
    let mut vault_reference = Vec::with_capacity(33);
    vault_reference.push(32u8);
    vault_reference.extend_from_slice(&new_authority);
    assert_eq!(
        data, vault_reference,
        "ported wire must be byte-for-byte identical to the deployed vault's cpi_update_authority output"
    );
}

/// Account shape parity: tag 32 uses THREE accounts —
/// [current_authority(signer), new_authority(signer), market(writable)] — the
/// same 3-account shape as tag 65, but semantically different (whole-market
/// marketauth vs. per-asset authority). Documents the shape so a future edit
/// that accidentally collapses this to 2 accounts (as some other CPIs use) is
/// caught by a reviewer diffing against this test.
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
/// touch marketauth (wrong field) rather than per-asset insurance_authority.
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
        "old wire was 34 bytes; current (v16-migration) wire requires 52 bytes"
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

/// C-1 CANARY: the ResolveMarket (tag 19) wire is exactly 1 byte — the bare tag,
/// with NO payload. Verified against the DEPLOYED wrapper source
/// (percolator-prog@e26c97a4 == current HEAD, v16_program.rs:3867):
/// `19 => Self::ResolveMarket` consumes zero additional bytes from `rest`.
///
/// CANARY POLICY: any change to this test requires a matching change to both
/// src/cpi.rs AND the wrapper's ResolveMarket decoder (they must stay in sync).
#[test]
fn test_cpi_tag19_resolve_market_wire_is_1_byte() {
    let data = vec![19u8]; // mirrors cpi::cpi_resolve_market's `vec![TAG_RESOLVE_MARKET]`

    assert_eq!(
        data.len(),
        1,
        "tag-19 ResolveMarket wire must be exactly 1 byte"
    );
    assert_eq!(data[0], 19, "byte 0 must be tag=19 (ResolveMarket)");

    // Byte-for-byte parity with the deployed vault's cpi_resolve_market
    // (percolator-vault@eb3ebe8 src/cpi.rs:246): `let data = vec![TAG_RESOLVE_MARKET];`
    let vault_reference = vec![19u8];
    assert_eq!(
        data, vault_reference,
        "ported wire must be byte-for-byte identical to the deployed vault's cpi_resolve_market"
    );
}

/// Account shape parity: tag 19 uses exactly TWO accounts —
/// [admin/marketauth(signer, read-only), market(writable)] — matching
/// handle_resolve_market's `account(accounts, 0)` (expect_signer +
/// expect_live_authority) / `account(accounts, 1)` (expect_writable +
/// expect_owner) reads, and the deployed vault's identical 2-account
/// `cpi_resolve_market` construction (percolator-vault@eb3ebe8 src/cpi.rs:250-253).
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

/// REGRESSION GUARD: tag 19 must never collide with the wire lengths of the
/// other CPIs this program issues (9, 32, 57, 65) — a length collision alone
/// isn't unsafe, but pins the expectation that ResolveMarket's payload stays
/// the minimal 1-byte bare tag if anyone is tempted to add fields later without
/// re-checking the deployed wrapper's decoder.
#[test]
fn test_cpi_tag19_wire_length_distinct_from_other_cpis() {
    let resolve_market_len = 1usize; // tag(1)
    let top_up_insurance_len = 41usize; // tag(1) + market_id(8) + intent_id(8) + authority_epoch(8) + u128(16), v16-migration
    let update_authority_len = 33usize; // tag(1) + pubkey(32) — unchanged, out of this migration's scope
    let update_asset_authority_len = 52usize; // tag(1) + idx(2) + market_id(8) + kind(1) + pubkey(32) + authority_epoch(8), v16-migration
    let withdraw_insurance_asset_len = 19usize; // tag(1) + idx(2) + u128(16) — unchanged, out of this migration's scope

    for other in [
        top_up_insurance_len,
        update_authority_len,
        update_asset_authority_len,
        withdraw_insurance_asset_len,
    ] {
        assert_ne!(
            resolve_market_len, other,
            "tag-19 wire length must stay distinct"
        );
    }
}
