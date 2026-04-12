//! CPI helpers for calling percolator wrapper instructions.
//!
//! The stake program only needs ONE CPI: TopUpInsurance (permissionless).
//! All admin operations are handled by the human admin directly on the wrapper.
#![allow(clippy::too_many_arguments)]

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
};

// Wrapper instruction tag (from percolator-prog/src/percolator.rs)
const TAG_TOP_UP_INSURANCE: u8 = 9;

// ═══════════════════════════════════════════════════════════════
// TopUpInsurance (Tag 9) — permissionless, anyone can top up
// ═══════════════════════════════════════════════════════════════
// Accounts: [signer, slab(w), signer_ata, vault, token_program]
// Data: tag(1) + amount(8)

pub fn cpi_top_up_insurance<'a>(
    percolator_program: &AccountInfo<'a>,
    signer: &AccountInfo<'a>, // vault_auth PDA (we sign)
    slab: &AccountInfo<'a>,
    signer_ata: &AccountInfo<'a>, // stake vault (owned by vault_auth)
    wrapper_vault: &AccountInfo<'a>,
    token_program: &AccountInfo<'a>,
    amount: u64,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    let mut data = Vec::with_capacity(9);
    data.push(TAG_TOP_UP_INSURANCE);
    data.extend_from_slice(&amount.to_le_bytes());

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

#[cfg(test)]
mod tag_tests {
    use super::*;

    #[test]
    fn test_cpi_tag_constants() {
        assert_eq!(TAG_TOP_UP_INSURANCE, 9, "TAG_TOP_UP_INSURANCE mismatch");
    }
}
