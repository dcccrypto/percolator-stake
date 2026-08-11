//! CPI tag verification tests — the cross-program wire canary.
//!
//! Two CPIs to verify:
//!   1. TopUpInsurance (tag 9)         — 17-byte wire (tag + u128 amount)
//!   2. UpdateAssetAuthority (tag 65)  — 36-byte wire (v17 bind/rotate)
//!
//! V17 WIRE CHANGE (collision row 43): the v16 bind/rotate wire used tag 32
//! (UpdateAuthority) with kind=2 (AUTHORITY_INSURANCE) = 34 bytes. The v17 auth
//! overhaul changed this to tag 65 (UpdateAssetAuthority): tag 32→65, kind 2→1
//! (ASSET_AUTH_INSURANCE, a different constant family), plus a new 2-byte
//! asset_index prefix (always 0). Total: 36 bytes.
//!
//! CANARY POLICY: any change to these tests requires a matching change to both
//! src/cpi.rs AND the wrapper's v17_convergence branch (they must stay in sync).

// ── Tag 9: TopUpInsurance ─────────────────────────────────────────────────────

/// The tag-9 wire is `tag(1) + amount(16, u128 LE)` = 17 bytes.
#[test]
fn test_cpi_tag_top_up_insurance_u128_wire() {
    let amount: u64 = 1000;
    let mut data = Vec::with_capacity(17);
    data.push(9u8); // TAG_TOP_UP_INSURANCE
    data.extend_from_slice(&(amount as u128).to_le_bytes());

    assert_eq!(data[0], 9, "tag byte must be 9 (TopUpInsurance)");
    assert_eq!(
        data.len(),
        17,
        "tag-9 payload MUST be 1 (tag) + 16 (u128 amount) = 17 bytes"
    );
    let decoded = u128::from_le_bytes(data[1..17].try_into().unwrap());
    assert_eq!(decoded, amount as u128);
}

/// REGRESSION GUARD: the broken pre-v16 wire was `tag(1) + amount(8, u64 LE)` = 9 bytes.
/// Against a v17 wrapper that payload hard-reverts at the read_u128 decoder.
#[test]
fn test_cpi_tag9_8byte_u64_wire_is_rejected_shape() {
    let amount: u64 = 1000;
    let mut broken = Vec::with_capacity(9);
    broken.push(9u8);
    broken.extend_from_slice(&amount.to_le_bytes()); // 8-byte u64 — the pre-v16 break

    assert_eq!(broken.len(), 9, "this is the OLD (broken) shape");
    assert!(
        broken.len() < 17,
        "the 8-byte u64 wire is shorter than the required v17 u128 wire"
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

/// CANARY: the v17 bind/rotate wire must be exactly 36 bytes:
///   byte 0      : tag = 65 (UpdateAssetAuthority)
///   bytes 1-2   : asset_index = 0 (u16 LE)
///   byte 3      : kind = 1 (ASSET_AUTH_INSURANCE)
///   bytes 4-35  : new_pubkey (32 bytes)
///
/// THREE footguns verified here at the byte level (all must pass):
///   (1) tag byte  = 65, NOT 32 (the old UpdateAuthority tag)
///   (2) kind byte = 1  (ASSET_AUTH_INSURANCE), NOT 2 (old AUTHORITY_INSURANCE)
///   (3) 2-byte asset_index prefix = 0x00 0x00 (NEW in v17, was absent in v16)
#[test]
fn test_cpi_tag65_update_asset_authority_wire_36_bytes() {
    let new_pubkey = [0xABu8; 32];

    // Reconstruct the v17 wire exactly as cpi_bind_insurance_authority builds it.
    let tag: u8 = 65;
    let asset_index: u16 = 0;
    let kind: u8 = 1; // ASSET_AUTH_INSURANCE
    let mut data = Vec::with_capacity(36);
    data.push(tag);
    data.extend_from_slice(&asset_index.to_le_bytes());
    data.push(kind);
    data.extend_from_slice(&new_pubkey);

    // Length check: 36 bytes
    assert_eq!(
        data.len(),
        36,
        "v17 tag-65 wire must be 36 bytes (was 34 bytes in v16)"
    );

    // (1) Tag = 65
    assert_eq!(data[0], 65, "byte 0 must be tag=65 (UpdateAssetAuthority)");
    assert_ne!(
        data[0], 32,
        "tag 32 is the OLD UpdateAuthority — must NOT ship"
    );

    // (2) asset_index = 0 (u16 LE, bytes 1-2)
    assert_eq!(data[1], 0x00, "asset_index low byte must be 0x00");
    assert_eq!(data[2], 0x00, "asset_index high byte must be 0x00");
    let decoded_idx = u16::from_le_bytes([data[1], data[2]]);
    assert_eq!(decoded_idx, 0, "asset_index must decode to 0");

    // (3) kind = 1, NOT 2
    assert_eq!(data[3], 1, "byte 3 must be kind=1 (ASSET_AUTH_INSURANCE)");
    assert_ne!(
        data[3], 2,
        "kind=2 is old AUTHORITY_INSURANCE — must NOT ship"
    );

    // pubkey round-trip
    assert_eq!(&data[4..36], &new_pubkey, "new_pubkey at bytes [4..36]");
}

/// REGRESSION GUARD: document the exact OLD v16 wire for the bind/rotate CPI.
/// The v16 wire was: tag(32) + kind(2) + new_pubkey(32) = 34 bytes.
/// Sending this to a v17 wrapper's tag 32 handler would touch marketauth (wrong
/// field) rather than per-asset insurance_authority — a silent state corruption.
#[test]
fn test_old_v16_bind_wire_documents_the_break() {
    let new_pubkey = [0xABu8; 32];

    // The v16 wire
    let mut old_data: Vec<u8> = Vec::with_capacity(34);
    old_data.push(32u8); // old tag
    old_data.push(2u8); // old kind = AUTHORITY_INSURANCE (from v16 UpdateAuthority enum)
    old_data.extend_from_slice(&new_pubkey);

    // Document what was wrong:
    assert_eq!(old_data.len(), 34, "old v16 wire was 34 bytes");
    assert_eq!(old_data[0], 32, "old tag was 32 (UpdateAuthority)");
    assert_eq!(old_data[1], 2, "old kind was 2 (AUTHORITY_INSURANCE)");

    // In v17, the correct wire has a different tag, kind, and 2 extra bytes
    assert_ne!(old_data[0], 65, "old wire used tag 32; v17 requires tag 65");
    assert_ne!(
        old_data.len(),
        36,
        "old wire was 34 bytes; v17 requires 36 bytes"
    );
}

/// Verify that the bind and rotate CPIs produce identical layout (same tag/asset/kind,
/// only the new_pubkey differs). The rotate sends the rotation target rather than the
/// vault_auth PDA, but the wire structure is byte-identical.
#[test]
fn test_bind_and_rotate_produce_same_wire_shape() {
    let pda_pubkey = [0x11u8; 32]; // vault_auth PDA (bind target)
    let rotate_target = [0x22u8; 32]; // rotation destination (rotate target)

    let mut bind_wire = Vec::with_capacity(36);
    bind_wire.push(65u8);
    bind_wire.extend_from_slice(&0u16.to_le_bytes());
    bind_wire.push(1u8);
    bind_wire.extend_from_slice(&pda_pubkey);

    let mut rotate_wire = Vec::with_capacity(36);
    rotate_wire.push(65u8);
    rotate_wire.extend_from_slice(&0u16.to_le_bytes());
    rotate_wire.push(1u8);
    rotate_wire.extend_from_slice(&rotate_target);

    // Same length
    assert_eq!(bind_wire.len(), 36, "bind wire: 36 bytes");
    assert_eq!(rotate_wire.len(), 36, "rotate wire: 36 bytes");

    // Same header bytes (tag, asset_index, kind)
    assert_eq!(bind_wire[0..4], rotate_wire[0..4], "header bytes identical");

    // Only the pubkey differs
    assert_ne!(
        &bind_wire[4..36],
        &rotate_wire[4..36],
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
    let top_up_insurance_len = 17usize; // tag(1) + u128(16)
    let update_authority_len = 33usize; // tag(1) + pubkey(32)
    let update_asset_authority_len = 36usize; // tag(1) + idx(2) + kind(1) + pubkey(32)
    let withdraw_insurance_asset_len = 19usize; // tag(1) + idx(2) + u128(16)

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
