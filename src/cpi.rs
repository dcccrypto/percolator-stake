//! CPI helpers for calling percolator wrapper instructions.
//!
//! We construct raw instruction data manually since we don't depend on percolator-prog.
//! Instruction tags match the wrapper's Instruction::decode() in percolator.rs.

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke_signed,
    pubkey::Pubkey,
};

// ═══════════════════════════════════════════════════════════════
// Wrapper instruction tags (from percolator-prog/src/percolator.rs)
// ═══════════════════════════════════════════════════════════════

const TAG_TOP_UP_INSURANCE: u8 = 9;
const TAG_SET_RISK_THRESHOLD: u8 = 11;
const TAG_UPDATE_ADMIN: u8 = 12;
const TAG_SET_MAINTENANCE_FEE: u8 = 15;
const TAG_SET_ORACLE_AUTHORITY: u8 = 16;
const TAG_SET_ORACLE_PRICE_CAP: u8 = 18;
const TAG_RESOLVE_MARKET: u8 = 19;
const TAG_WITHDRAW_INSURANCE: u8 = 20;
// Tag 21 = AdminForceCloseAccount (not used by stake program)
const TAG_SET_INSURANCE_WITHDRAW_POLICY: u8 = 22; // Was incorrectly 21!
const TAG_WITHDRAW_INSURANCE_LIMITED: u8 = 23;     // Was incorrectly 22!

// ═══════════════════════════════════════════════════════════════
// TopUpInsurance (Tag 9) — permissionless, anyone can top up
// ═══════════════════════════════════════════════════════════════
// Accounts: [signer, slab(w), signer_ata, vault, token_program]
// Data: tag(1) + amount(8)

pub fn cpi_top_up_insurance<'a>(
    percolator_program: &AccountInfo<'a>,
    signer: &AccountInfo<'a>,       // vault_auth PDA (we sign)
    slab: &AccountInfo<'a>,
    signer_ata: &AccountInfo<'a>,    // stake vault (owned by vault_auth)
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

// ═══════════════════════════════════════════════════════════════
// UpdateAdmin (Tag 12) — current admin transfers to new admin
// ═══════════════════════════════════════════════════════════════
// Accounts: [admin(signer), slab(w)]
// Data: tag(1) + new_admin(32)
// Note: For TransferAdmin, the CURRENT admin (human) signs, not pool PDA.

pub fn cpi_update_admin<'a>(
    percolator_program: &AccountInfo<'a>,
    current_admin: &AccountInfo<'a>,
    slab: &AccountInfo<'a>,
    new_admin: &Pubkey,
) -> ProgramResult {
    let mut data = Vec::with_capacity(33);
    data.push(TAG_UPDATE_ADMIN);
    data.extend_from_slice(new_admin.as_ref());

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*current_admin.key, true),
            AccountMeta::new(*slab.key, false),
        ],
        data,
    };

    // No invoke_signed — current admin (human) is the signer of the outer tx
    solana_program::program::invoke(
        &ix,
        &[current_admin.clone(), slab.clone()],
    )
}

// ═══════════════════════════════════════════════════════════════
// SetOracleAuthority (Tag 16) — admin only
// ═══════════════════════════════════════════════════════════════
// Accounts: [admin(signer), slab(w)]
// Data: tag(1) + new_authority(32)

pub fn cpi_set_oracle_authority<'a>(
    percolator_program: &AccountInfo<'a>,
    admin_pda: &AccountInfo<'a>,
    slab: &AccountInfo<'a>,
    new_authority: &Pubkey,
    admin_seeds: &[&[u8]],
) -> ProgramResult {
    let mut data = Vec::with_capacity(33);
    data.push(TAG_SET_ORACLE_AUTHORITY);
    data.extend_from_slice(new_authority.as_ref());

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*admin_pda.key, true),
            AccountMeta::new(*slab.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[admin_pda.clone(), slab.clone()],
        &[admin_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// SetRiskThreshold (Tag 11) — admin only
// ═══════════════════════════════════════════════════════════════
// Accounts: [admin(signer), slab(w)]
// Data: tag(1) + new_threshold(16)

pub fn cpi_set_risk_threshold<'a>(
    percolator_program: &AccountInfo<'a>,
    admin_pda: &AccountInfo<'a>,
    slab: &AccountInfo<'a>,
    new_threshold: u128,
    admin_seeds: &[&[u8]],
) -> ProgramResult {
    let mut data = Vec::with_capacity(17);
    data.push(TAG_SET_RISK_THRESHOLD);
    data.extend_from_slice(&new_threshold.to_le_bytes());

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*admin_pda.key, true),
            AccountMeta::new(*slab.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[admin_pda.clone(), slab.clone()],
        &[admin_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// SetMaintenanceFee (Tag 15) — admin only
// ═══════════════════════════════════════════════════════════════
// Accounts: [admin(signer), slab(w)]
// Data: tag(1) + new_fee(16)

pub fn cpi_set_maintenance_fee<'a>(
    percolator_program: &AccountInfo<'a>,
    admin_pda: &AccountInfo<'a>,
    slab: &AccountInfo<'a>,
    new_fee: u128,
    admin_seeds: &[&[u8]],
) -> ProgramResult {
    let mut data = Vec::with_capacity(17);
    data.push(TAG_SET_MAINTENANCE_FEE);
    data.extend_from_slice(&new_fee.to_le_bytes());

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*admin_pda.key, true),
            AccountMeta::new(*slab.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[admin_pda.clone(), slab.clone()],
        &[admin_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// SetOraclePriceCap (Tag 18) — admin only
// ═══════════════════════════════════════════════════════════════
// Accounts: [admin(signer), slab(w)]
// Data: tag(1) + max_change_e2bps(8)

pub fn cpi_set_oracle_price_cap<'a>(
    percolator_program: &AccountInfo<'a>,
    admin_pda: &AccountInfo<'a>,
    slab: &AccountInfo<'a>,
    max_change_e2bps: u64,
    admin_seeds: &[&[u8]],
) -> ProgramResult {
    let mut data = Vec::with_capacity(9);
    data.push(TAG_SET_ORACLE_PRICE_CAP);
    data.extend_from_slice(&max_change_e2bps.to_le_bytes());

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*admin_pda.key, true),
            AccountMeta::new(*slab.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[admin_pda.clone(), slab.clone()],
        &[admin_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// ResolveMarket (Tag 19) — admin only, ends market
// ═══════════════════════════════════════════════════════════════
// Accounts: [admin(signer), slab(w)]
// Data: tag(1)

pub fn cpi_resolve_market<'a>(
    percolator_program: &AccountInfo<'a>,
    admin_pda: &AccountInfo<'a>,
    slab: &AccountInfo<'a>,
    admin_seeds: &[&[u8]],
) -> ProgramResult {
    let data = vec![TAG_RESOLVE_MARKET];

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*admin_pda.key, true),
            AccountMeta::new(*slab.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[admin_pda.clone(), slab.clone()],
        &[admin_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// WithdrawInsurance (Tag 20) — admin only, requires RESOLVED
// ═══════════════════════════════════════════════════════════════
// Accounts: [admin(signer), slab(w), admin_ata(w), vault(w), token_program, vault_pda]
// Data: tag(1)

pub fn cpi_withdraw_insurance<'a>(
    percolator_program: &AccountInfo<'a>,
    admin_pda: &AccountInfo<'a>,
    slab: &AccountInfo<'a>,
    admin_ata: &AccountInfo<'a>,     // ATA owned by admin PDA to receive insurance
    wrapper_vault: &AccountInfo<'a>,
    token_program: &AccountInfo<'a>,
    vault_authority: &AccountInfo<'a>, // wrapper's vault authority PDA
    admin_seeds: &[&[u8]],
) -> ProgramResult {
    let data = vec![TAG_WITHDRAW_INSURANCE];

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*admin_pda.key, true),
            AccountMeta::new(*slab.key, false),
            AccountMeta::new(*admin_ata.key, false),
            AccountMeta::new(*wrapper_vault.key, false),
            AccountMeta::new_readonly(*token_program.key, false),
            AccountMeta::new_readonly(*vault_authority.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            admin_pda.clone(),
            slab.clone(),
            admin_ata.clone(),
            wrapper_vault.clone(),
            token_program.clone(),
            vault_authority.clone(),
        ],
        &[admin_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// SetInsuranceWithdrawPolicy (Tag 21) — admin only, requires RESOLVED
// ═══════════════════════════════════════════════════════════════
// Accounts: [admin(signer), slab(w)]
// Data: tag(1) + authority(32) + min_withdraw_base(8) + max_withdraw_bps(2) + cooldown_slots(8)

pub fn cpi_set_insurance_withdraw_policy<'a>(
    percolator_program: &AccountInfo<'a>,
    admin_pda: &AccountInfo<'a>,
    slab: &AccountInfo<'a>,
    authority: &Pubkey,
    min_withdraw_base: u64,
    max_withdraw_bps: u16,
    cooldown_slots: u64,
    admin_seeds: &[&[u8]],
) -> ProgramResult {
    let mut data = Vec::with_capacity(51);
    data.push(TAG_SET_INSURANCE_WITHDRAW_POLICY);
    data.extend_from_slice(authority.as_ref());
    data.extend_from_slice(&min_withdraw_base.to_le_bytes());
    data.extend_from_slice(&max_withdraw_bps.to_le_bytes());
    data.extend_from_slice(&cooldown_slots.to_le_bytes());

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*admin_pda.key, true),
            AccountMeta::new(*slab.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[admin_pda.clone(), slab.clone()],
        &[admin_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// WithdrawInsuranceLimited (Tag 22) — policy authority, requires RESOLVED
// ═══════════════════════════════════════════════════════════════
// Accounts (7): [authority(signer), slab(w), authority_ata(w), vault(w),
//                token_program, vault_pda, clock]
// Data: tag(1) + amount(8)
//
// KEY: authority_ata must be a token account owned by authority.
// We set vault_auth as the policy authority (via SetInsuranceWithdrawPolicy),
// so vault_auth signs here and stake_vault (owned by vault_auth) is authority_ata.
pub fn cpi_withdraw_insurance_limited<'a>(
    percolator_program: &AccountInfo<'a>,
    vault_auth: &AccountInfo<'a>,        // policy authority (signer via PDA seeds)
    slab: &AccountInfo<'a>,
    stake_vault: &AccountInfo<'a>,       // authority_ata — owned by vault_auth ✓
    wrapper_vault: &AccountInfo<'a>,     // insurance vault (writable)
    token_program: &AccountInfo<'a>,
    wrapper_vault_pda: &AccountInfo<'a>, // wrapper's vault PDA authority
    clock: &AccountInfo<'a>,
    amount: u64,
    vault_auth_seeds: &[&[u8]],          // [b"vault_auth", pool_pda_key, bump_byte]
) -> ProgramResult {
    let mut data = Vec::with_capacity(9);
    data.push(TAG_WITHDRAW_INSURANCE_LIMITED);
    data.extend_from_slice(&amount.to_le_bytes());

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*vault_auth.key, true),    // authority (signer via PDA)
            AccountMeta::new(*slab.key, false),                  // slab (writable, NOT signer)
            AccountMeta::new(*stake_vault.key, false),           // authority_ata (writable, NOT signer)
            AccountMeta::new(*wrapper_vault.key, false),         // insurance vault (writable, NOT signer)
            AccountMeta::new_readonly(*token_program.key, false),
            AccountMeta::new_readonly(*wrapper_vault_pda.key, false),
            AccountMeta::new_readonly(*clock.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            vault_auth.clone(),
            slab.clone(),
            stake_vault.clone(),
            wrapper_vault.clone(),
            token_program.clone(),
            wrapper_vault_pda.clone(),
            clock.clone(),
        ],
        &[vault_auth_seeds],
    )
}
