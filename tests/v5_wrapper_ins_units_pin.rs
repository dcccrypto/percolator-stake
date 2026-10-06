//! v5 CROSS-PROGRAM PIN (Phase 4 item 6): stake reads the wrapper's `InsuranceUnitsV20` RAW.
//!
//! The wrapper const-asserts every offset of its own struct (`percolator-prog`
//! `src/v16_program.rs`, `const _: () = assert!(core::mem::offset_of!(InsuranceUnitsV20, ..)`).
//! This test pins stake's mirror (`state::WRAPPER_INS_UNITS_OFF_*`) to those asserts, read from
//! the sibling checkout's SOURCE, so a wrapper-side move fails HERE (stake CI checks the wrapper
//! out as `../percolator-prog`) instead of mispricing deployed insurance on chain. The two
//! programs deploy together (stake v5 + wrapper v2.2). A missing sibling is a hard failure, not
//! a skip: the stake#301 INFO precedent.

use percolator_stake::state;

fn wrapper_source() -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../percolator-prog/src/v16_program.rs");
    std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "v5 pin needs the wrapper sibling at {} ({e}); stake v5 and wrapper v2.2 (feat/v22-wave-d) deploy together",
            p.display()
        )
    })
}

fn wrapper_offset(src: &str, field: &str) -> usize {
    let needle = format!("core::mem::offset_of!(InsuranceUnitsV20, {field}) == ");
    let i = src
        .find(&needle)
        .unwrap_or_else(|| panic!("wrapper has no offset assert for InsuranceUnitsV20::{field} (version skew)"));
    src[i + needle.len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap()
}

#[test]
fn ins_units_layout_matches_the_wrapper() {
    let src = wrapper_source();
    let h = state::WRAPPER_HEADER_LEN;
    for (field, ours) in [
        ("units_total", state::WRAPPER_INS_UNITS_OFF_UNITS_TOTAL),
        ("units_stake", state::WRAPPER_INS_UNITS_OFF_UNITS_STAKE),
        ("units_creator", state::WRAPPER_INS_UNITS_OFF_UNITS_CREATOR),
        ("backstop_receivable_atoms", state::WRAPPER_INS_UNITS_OFF_RECEIVABLE),
        ("snap_insurance_mint_atoms", state::WRAPPER_INS_UNITS_OFF_SNAP_MINT),
        ("snap_insurance_free_atoms", state::WRAPPER_INS_UNITS_OFF_SNAP_FREE),
        ("snap_slot", state::WRAPPER_INS_UNITS_OFF_SNAP_SLOT),
        ("version", state::WRAPPER_INS_UNITS_OFF_VERSION),
        ("creator_paid_to_stake_atoms", state::WRAPPER_INS_UNITS_OFF_CREATOR_PAID),
    ] {
        assert_eq!(h + wrapper_offset(&src, field), ours, "InsuranceUnitsV20::{field}");
    }
    assert!(
        src.contains("assert!(core::mem::size_of::<InsuranceUnitsV20>() == 192)"),
        "wrapper record size must be 192 (stake reads 16 + 192)"
    );
    assert_eq!(state::WRAPPER_INS_UNITS_LEN, h + 192);
    // W-2 G9 fields follow `creator_paid_to_stake_atoms`; stake never reads them, but the record
    // must not shift under the offsets above.
    assert_eq!(wrapper_offset(&src, "g9_pending_slot"), 160);
    assert_eq!(wrapper_offset(&src, "g9_epoch_drawn_atoms"), 176);
    assert!(src.contains("pub const KIND_INSURANCE_UNITS: u8 = 13;"), "kind 13");
    assert_eq!(state::WRAPPER_KIND_INSURANCE_UNITS, 13);
    assert!(src.contains("pub const INS_UNITS_VERSION: u8 = 1;"), "record version 1");
    assert_eq!(state::WRAPPER_INS_UNITS_VERSION, 1);
    assert!(src.contains("pub const INS_UNITS_SEED: &[u8] = b\"ins_units\";"), "seed");
    assert_eq!(state::WRAPPER_INS_UNITS_SEED, b"ins_units");
    // ... and the wrapper pins THIS layout of the stake pool back (version 5, 480 B, risk_mode@408).
    assert!(src.contains("pub const STAKE_POOL_VERSION: u8 = 5;"));
    assert!(src.contains("pub const STAKE_POOL_LEN: usize = 480;"));
    assert!(src.contains("pub const STAKE_POOL_OFF_RISK_MODE: usize = 408;"));
    assert_eq!(state::StakePool::CURRENT_VERSION, 5);
    assert_eq!(state::STAKE_POOL_SIZE, 480);
}
