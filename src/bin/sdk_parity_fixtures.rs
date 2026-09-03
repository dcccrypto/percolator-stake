//! SDK parity fixture binary for percolator-stake.
//!
//! Emits the JSON that `percolator-sdk/scripts/check-parity-fixtures.mjs`
//! compares against `percolator-sdk/specs/stake-parity.json`.
//!
//!   cargo run --quiet --bin sdk_parity_fixtures
//!
//! #375: this binary did not exist, so the Parity Gate's `percolator-stake`
//! target failed with `cargo run failed` on every run since at least 2026-08-23.
//! ABI drift in stake had NO automated detection at all.
//!
//! ── WHY NOTHING HERE IS A LITERAL ────────────────────────────────────────────
//!
//! A fixture that restates the numbers the spec already holds compares a copy
//! against a copy and passes no matter what the program does. Two of this repo's
//! own defects are that exact shape (the `const_assert!`s in #160, the stale
//! `CYCLE_CAP` copy in percolator-keeper), so every value below is derived from
//! the thing it describes:
//!
//!   * TAGS come from `StakeInstruction::unpack` — the real dispatcher. Each tag
//!     byte is probed with candidate payload lengths and we record which variant
//!     comes back. Renumber a tag and this finds it at the new number.
//!
//!   * ALIASED OFFSETS are probed through the real setters. Most of the fields
//!     the SDK reads are not struct members at all: they are byte ranges inside
//!     `_reserved[64]`, addressed by hand-written accessors. `offset_of!` cannot
//!     see them. So we zero a pool, call the setter, and report which byte moved.
//!     Hardcoding `_reserved + 9` would restate the accessor's own literal.
//!
//!     That aliasing is not incidental: PERC-313's HWM fields and #242's cooldown
//!     timelock overlap the SAME `_reserved` bytes (see the comment at
//!     `state.rs:167`). A probe reports where the setter ACTUALLY writes, which is
//!     the only honest answer when two features share a range.
//!
//!   * SIZES and the DISCRIMINATOR come from the exported constants.
//!
//! No serde: this crate builds an on-chain program and the shape is small and
//! fixed, so the JSON is emitted directly rather than adding a dependency to the
//! program's graph for a dev-only binary.

use bytemuck::Zeroable;
use core::mem::offset_of;
use percolator_stake::instruction::StakeInstruction;
use percolator_stake::state::{
    StakeDeposit, StakePool, STAKE_DEPOSIT_SIZE, STAKE_POOL_DISCRIMINATOR, STAKE_POOL_SIZE,
};

/// Absolute byte offset a setter writes to, found by watching a zeroed pool.
///
/// Starts from all-zero and reports the FIRST byte the closure changed. Each
/// setter writes only its own field, so that byte is the field's offset. Values
/// passed by the caller always have a non-zero low byte, so a little-endian
/// multi-byte write still reports its base rather than skipping into the middle.
fn probe_offset<F: FnOnce(&mut StakePool)>(field: &str, write: F) -> usize {
    let mut pool = StakePool::zeroed();
    write(&mut pool);
    let bytes = bytemuck::bytes_of(&pool);
    bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or_else(|| panic!("setter for `{field}` wrote nothing — it cannot be probed"))
}

/// The variant's name. This is the ONLY hand-written mapping in the file, and it
/// is deliberately not the part that drifts: the tag->variant binding comes from
/// `unpack` above, so renumbering is caught even though the names are spelled out
/// here. A renamed variant fails to compile, which is its own alarm.
fn variant_name(ix: &StakeInstruction) -> &'static str {
    match ix {
        StakeInstruction::InitPool { .. } => "InitPool",
        StakeInstruction::Deposit { .. } => "Deposit",
        StakeInstruction::Withdraw { .. } => "Withdraw",
        StakeInstruction::FlushToInsurance { .. } => "FlushToInsurance",
        StakeInstruction::UpdateConfig { .. } => "UpdateConfig",
        StakeInstruction::ProposeAdmin { .. } => "ProposeAdmin",
        StakeInstruction::AcceptAdmin => "AcceptAdmin",
        StakeInstruction::ProposeCooldownIncrease { .. } => "ProposeCooldownIncrease",
        StakeInstruction::CommitCooldownIncrease => "CommitCooldownIncrease",
        StakeInstruction::CancelCooldownIncrease => "CancelCooldownIncrease",
        StakeInstruction::ReturnInsurance { .. } => "ReturnInsurance",
        StakeInstruction::AccrueFees => "AccrueFees",
        StakeInstruction::InitTradingPool { .. } => "InitTradingPool",
        StakeInstruction::AdminSetHwmConfig { .. } => "AdminSetHwmConfig",
        StakeInstruction::AdminSetTrancheConfig { .. } => "AdminSetTrancheConfig",
        StakeInstruction::DepositJunior { .. } => "DepositJunior",
        StakeInstruction::SetMarketResolved => "SetMarketResolved",
        StakeInstruction::BindInsuranceAuthority => "BindInsuranceAuthority",
        StakeInstruction::RotateInsuranceAuthority => "RotateInsuranceAuthority",
        StakeInstruction::BurnAssetAdmin => "BurnAssetAdmin",
        StakeInstruction::RotateInsuranceOperator => "RotateInsuranceOperator",
        StakeInstruction::RecoverFlushedInsurance { .. } => "RecoverFlushedInsurance",
        StakeInstruction::AdminResolveMarket => "AdminResolveMarket",
        StakeInstruction::AdminUpdateFeeSplit { .. } => "AdminUpdateFeeSplit",
        StakeInstruction::AdminUpdateMaintenanceFeePerSlot { .. } => {
            "AdminUpdateMaintenanceFeePerSlot"
        }
        StakeInstruction::AdminUpdateBackingFeePolicy { .. } => "AdminUpdateBackingFeePolicy",
        StakeInstruction::AdminUpdateTradeFeePolicy { .. } => "AdminUpdateTradeFeePolicy",
    }
}

/// Highest tag byte probed. Well above the live range so a tag appended at the
/// tail is picked up without editing this file.
const MAX_TAG: u8 = 63;
/// Payload lengths tried per tag. Covers every `rest.len()` the parser checks
/// (0, 2, 3, 6, 8, 16, 18, 32) with room to spare; a new arm wanting some other
/// length is still found as long as it is <= 40.
const MAX_PAYLOAD: usize = 40;

fn main() {
    // ── tags: ask the real dispatcher ────────────────────────────────────────
    let mut live: Vec<(u8, &'static str)> = Vec::new();
    let mut removed: Vec<u8> = Vec::new();

    for tag in 0..=MAX_TAG {
        let mut found: Option<&'static str> = None;
        for len in 0..=MAX_PAYLOAD {
            let mut data = vec![0u8; len + 1];
            data[0] = tag;
            if let Ok(ix) = StakeInstruction::unpack(&data) {
                found = Some(variant_name(&ix));
                break;
            }
        }
        match found {
            Some(name) => live.push((tag, name)),
            // Only gaps BELOW the highest live tag are "removed" — everything
            // above the tail is simply unallocated and would otherwise report
            // dozens of meaningless holes.
            None => removed.push(tag),
        }
    }
    let highest_live = live.last().map(|(t, _)| *t).unwrap_or(0);
    removed.retain(|t| *t < highest_live);

    // ── offsets: ask the real accessors ──────────────────────────────────────
    let reserved_start = offset_of!(StakePool, _reserved);
    let mut offsets: Vec<(&str, usize)> = vec![
        (
            "epoch_high_water_tvl",
            probe_offset("epoch_high_water_tvl", |p| p.set_epoch_high_water_tvl(1)),
        ),
        (
            "hwm_enabled",
            probe_offset("hwm_enabled", |p| p.set_hwm_enabled(true)),
        ),
        (
            "hwm_floor_bps",
            probe_offset("hwm_floor_bps", |p| p.set_hwm_floor_bps(1)),
        ),
        (
            "hwm_last_epoch",
            probe_offset("hwm_last_epoch", |p| p.set_hwm_last_epoch(1)),
        ),
        (
            "junior_balance",
            probe_offset("junior_balance", |p| p.set_junior_balance(1)),
        ),
        (
            "junior_fee_mult_bps",
            probe_offset("junior_fee_mult_bps", |p| p.set_junior_fee_mult_bps(1)),
        ),
        (
            "junior_total_lp",
            probe_offset("junior_total_lp", |p| p.set_junior_total_lp(1)),
        ),
        (
            "market_resolved",
            probe_offset("market_resolved", |p| p.set_market_resolved(true)),
        ),
        // A REAL struct field, so read it the direct way. Kept alongside the
        // probed ones because the SDK reads it the same way it reads them.
        (
            "total_recovered_from_wrapper",
            offset_of!(StakePool, total_recovered_from_wrapper),
        ),
        (
            "tranche_enabled",
            probe_offset("tranche_enabled", |p| p.set_tranche_enabled(true)),
        ),
    ];
    offsets.sort_by_key(|(name, _)| *name);

    // ── emit ─────────────────────────────────────────────────────────────────
    let mut out = String::from("{\n  \"layout\": {\n    \"offsets\": {\n");
    for (i, (name, off)) in offsets.iter().enumerate() {
        let comma = if i + 1 == offsets.len() { "" } else { "," };
        out.push_str(&format!("      \"{name}\": {off}{comma}\n"));
    }
    out.push_str("    },\n");
    out.push_str(&format!("    \"reserved_start\": {reserved_start}\n"));
    out.push_str("  },\n  \"live_tags\": [\n");
    for (i, (tag, name)) in live.iter().enumerate() {
        let comma = if i + 1 == live.len() { "" } else { "," };
        out.push_str(&format!(
            "    {{\n      \"name\": \"{name}\",\n      \"tag\": {tag}\n    }}{comma}\n"
        ));
    }
    out.push_str("  ],\n");
    out.push_str("  \"program\": \"percolator-stake\",\n");
    out.push_str("  \"removed_tags\": [\n");
    for (i, tag) in removed.iter().enumerate() {
        let comma = if i + 1 == removed.len() { "" } else { "," };
        out.push_str(&format!("    {tag}{comma}\n"));
    }
    out.push_str("  ],\n");
    out.push_str(&format!("  \"stake_deposit_size\": {STAKE_DEPOSIT_SIZE},\n"));
    out.push_str("  \"stake_pool_discriminator\": [\n");
    for (i, b) in STAKE_POOL_DISCRIMINATOR.iter().enumerate() {
        let comma = if i + 1 == STAKE_POOL_DISCRIMINATOR.len() {
            ""
        } else {
            ","
        };
        out.push_str(&format!("    {b}{comma}\n"));
    }
    out.push_str("  ],\n");
    out.push_str(&format!("  \"stake_pool_size\": {STAKE_POOL_SIZE}\n"));
    out.push_str("}\n");

    // Proof of life: a silent empty emit would look like "parity OK" forever.
    assert!(!live.is_empty(), "no live tags found — the probe is broken");
    assert_eq!(
        STAKE_POOL_SIZE,
        core::mem::size_of::<StakePool>(),
        "size constant disagrees with the struct"
    );
    let _ = core::mem::size_of::<StakeDeposit>();

    print!("{out}");
}
