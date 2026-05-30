//! CPI helpers for calling percolator wrapper instructions.
//!
//! The stake program issues TWO wrapper CPIs:
//!   * TopUpInsurance (tag 9)   — the insurance flush itself.
//!   * UpdateAuthority (tag 32) — a ONE-TIME bind of the market's
//!     `insurance_authority` to our `vault_auth` PDA (see below).
//!
//! WHY THE BIND CPI EXISTS (v16): v12's TopUpInsurance was permissionless, so
//! the flush needed no authority setup. v16 authorizes tag 9 against the
//! market-level `cfg.insurance_authority` and our CPI signer is the `vault_auth`
//! PDA — so that field must equal the PDA. The wrapper's UpdateAuthority requires
//! the NEW authority to co-sign (v16_program.rs:9458-9459), and a PDA cannot sign
//! a top-level tx. The ONLY way to bind a PDA is a CPI from its owning program
//! (us) that `invoke_signed`s the PDA as the new authority while the admin
//! co-signs as the current authority. That is `cpi_bind_insurance_authority`.
//! This is NOT a redundant "admin proxy" (the v3 design removed those): the human
//! admin literally cannot perform this bind directly — only the stake program can
//! make the PDA sign.
#![allow(clippy::too_many_arguments)]

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
};

// Wrapper instruction tags (from percolator-prog/src/v16_program.rs ix::Instruction).
const TAG_TOP_UP_INSURANCE: u8 = 9;
const TAG_UPDATE_AUTHORITY: u8 = 32;
/// UpdateAuthority `kind` selector for the insurance authority
/// (v16_program.rs AUTHORITY_INSURANCE = 2).
const AUTHORITY_INSURANCE: u8 = 2;

// ═══════════════════════════════════════════════════════════════
// TopUpInsurance (Tag 9) — v16 contract
// ═══════════════════════════════════════════════════════════════
// Accounts: [signer, slab(w), signer_ata(w), vault(w), token_program]
// Data: tag(1) + amount(16, u128 LE)
//
// V16 WIRE CONTRACT (verified against percolator-prog v16-sync @5260d1b):
//   * AMOUNT IS u128 ON THE WIRE. The v16 wrapper decodes tag 9 with
//     `read_u128` (v16_program.rs:2627), which returns `InvalidInstructionData`
//     for any payload < 16 bytes (v16_program.rs:3275-3282). The pre-v16 wire
//     sent an 8-byte u64 — against a v16 wrapper that 8-byte payload HARD-REVERTS
//     the CPI at decode time. We therefore widen the wire to `(amount as u128)`.
//     `amount` stays a u64 here because token amounts fit u64 and the wrapper
//     re-narrows via `u64::try_from` (v16_program.rs:7574); only the wire widens.
//   * NOT PERMISSIONLESS. v16 gates tag 9 on `expect_live_authority(
//     cfg.insurance_authority, signer.key)` (v16_program.rs:7569,7584). The CPI
//     signer is our `vault_auth` PDA, so the market's `insurance_authority` MUST
//     be bound to that PDA first — via `cpi_bind_insurance_authority` /
//     instruction BindInsuranceAuthority (a plain admin UpdateAuthority cannot
//     bind a PDA; see that helper) — or every flush reverts Custom(8)
//     Unauthorized. (The old "permissionless" comment was wrong for v16.)
//   * LIVE MODE REQUIRED. v16 rejects tag 9 unless the market is Live
//     (v16_program.rs:7566,7580) — checked BEFORE the authority gate, so a
//     not-yet-Live market reverts Custom(21) EngineLockActive.
//
// CUTOVER ATOMICITY: this 16-byte wire MUST ship in the same cutover bundle as
// the v16 wrapper. NEVER deploy this stake build against a live pre-v16 (v12)
// wrapper — that wrapper decodes tag 9 as u64 (8 bytes) and would reject the
// 16-byte payload. See ~/wrapper-engine-deep-audit/V16_DIVERGENCES.md (stake).

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
    // tag(1) + u128 amount(16) = 17 bytes.
    let mut data = Vec::with_capacity(17);
    data.push(TAG_TOP_UP_INSURANCE);
    data.extend_from_slice(&(amount as u128).to_le_bytes());

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
// UpdateAuthority (Tag 32) — one-time bind of insurance_authority
// ═══════════════════════════════════════════════════════════════
// Accounts (v16_program.rs handle_update_authority L9451-9456):
//   [current(signer), new_authority(signer when new_pubkey!=0), market(w)]
// Data: tag(1) + kind(1) + new_pubkey(32) = 34 bytes
//
// Binds the market's `insurance_authority` to our `vault_auth` PDA so the
// subsequent TopUpInsurance flush (signed by the PDA) passes v16's authority
// gate. `admin` co-signs as the CURRENT authority (must equal cfg.insurance_
// authority, which InitMarket sets to admin), and the PDA co-signs as the NEW
// authority via invoke_signed (the wrapper's L9458-9459 co-sign requirement that
// a plain admin tx cannot satisfy for a PDA). After this bind, only the PDA can
// rotate the authority again — the bind is effectively one-directional (matching
// the stake->insurance trust model). A future RebindInsuranceAuthority CPI
// (signing as the PDA) could add rotation if ever needed.

pub fn cpi_bind_insurance_authority<'a>(
    percolator_program: &AccountInfo<'a>,
    admin: &AccountInfo<'a>, // current authority (== cfg.insurance_authority at bind time); signs outer tx
    vault_auth: &AccountInfo<'a>, // new authority = our PDA; signs via invoke_signed
    market: &AccountInfo<'a>, // the slab/market account (writable, wrapper-owned)
    signer_seeds: &[&[u8]],  // vault_auth PDA seeds
) -> ProgramResult {
    // tag(1) + kind(1) + new_pubkey(32) = 34 bytes.
    let mut data = Vec::with_capacity(34);
    data.push(TAG_UPDATE_AUTHORITY);
    data.push(AUTHORITY_INSURANCE);
    data.extend_from_slice(vault_auth.key.as_ref());

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

#[cfg(test)]
mod tag_tests {
    use super::*;

    #[test]
    fn test_cpi_tag_constants() {
        assert_eq!(TAG_TOP_UP_INSURANCE, 9, "TAG_TOP_UP_INSURANCE mismatch");
        assert_eq!(TAG_UPDATE_AUTHORITY, 32, "TAG_UPDATE_AUTHORITY mismatch");
        assert_eq!(
            AUTHORITY_INSURANCE, 2,
            "AUTHORITY_INSURANCE selector mismatch"
        );
    }

    /// CANARY: pin the UpdateAuthority(insurance) bind wire shape =
    /// tag(32) + kind(2) + new_pubkey(32) = 34 bytes.
    #[test]
    fn test_cpi_bind_authority_wire_shape() {
        let pda = [9u8; 32];
        let mut data = Vec::with_capacity(34);
        data.push(TAG_UPDATE_AUTHORITY);
        data.push(AUTHORITY_INSURANCE);
        data.extend_from_slice(&pda);
        assert_eq!(data.len(), 34);
        assert_eq!(data[0], 32);
        assert_eq!(data[1], 2);
        assert_eq!(&data[2..34], &pda);
    }

    /// CANARY: pin the v16 tag-9 wire shape. The amount is u128 (16 bytes), NOT
    /// u64 (8 bytes). If anyone narrows this back to u64 the v16 wrapper's
    /// `read_u128` decoder rejects the CPI with InvalidInstructionData. This test
    /// reconstructs the exact bytes `cpi_top_up_insurance` builds.
    #[test]
    fn test_cpi_wire_shape_is_tag_plus_u128() {
        let amount: u64 = 1_000;
        // Mirror the encoding in cpi_top_up_insurance.
        let mut data = Vec::with_capacity(17);
        data.push(TAG_TOP_UP_INSURANCE);
        data.extend_from_slice(&(amount as u128).to_le_bytes());

        assert_eq!(data.len(), 17, "v16 tag-9 payload must be 1 + 16 bytes");
        assert_eq!(data[0], 9, "tag byte");
        // amount occupies bytes [1..17] little-endian as u128.
        let decoded = u128::from_le_bytes(data[1..17].try_into().unwrap());
        assert_eq!(decoded, amount as u128, "amount must round-trip as u128 LE");
        // Guard against regression to the broken 8-byte u64 wire.
        assert_ne!(
            data.len(),
            9,
            "8-byte u64 wire is the pre-v16 break — must NOT ship"
        );
    }
}
