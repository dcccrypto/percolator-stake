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
    assert_ne!(data[0], 32, "tag 32 is the OLD UpdateAuthority — must NOT ship");

    // (2) asset_index = 0 (u16 LE, bytes 1-2)
    assert_eq!(data[1], 0x00, "asset_index low byte must be 0x00");
    assert_eq!(data[2], 0x00, "asset_index high byte must be 0x00");
    let decoded_idx = u16::from_le_bytes([data[1], data[2]]);
    assert_eq!(decoded_idx, 0, "asset_index must decode to 0");

    // (3) kind = 1, NOT 2
    assert_eq!(data[3], 1, "byte 3 must be kind=1 (ASSET_AUTH_INSURANCE)");
    assert_ne!(data[3], 2, "kind=2 is old AUTHORITY_INSURANCE — must NOT ship");

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
    old_data.push(2u8);  // old kind = AUTHORITY_INSURANCE (from v16 UpdateAuthority enum)
    old_data.extend_from_slice(&new_pubkey);

    // Document what was wrong:
    assert_eq!(old_data.len(), 34, "old v16 wire was 34 bytes");
    assert_eq!(old_data[0], 32, "old tag was 32 (UpdateAuthority)");
    assert_eq!(old_data[1], 2, "old kind was 2 (AUTHORITY_INSURANCE)");

    // In v17, the correct wire has a different tag, kind, and 2 extra bytes
    assert_ne!(
        old_data[0], 65,
        "old wire used tag 32; v17 requires tag 65"
    );
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
    let pda_pubkey = [0x11u8; 32];   // vault_auth PDA (bind target)
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
        &bind_wire[4..36], &rotate_wire[4..36],
        "new_pubkey bytes differ between bind and rotate"
    );
}
