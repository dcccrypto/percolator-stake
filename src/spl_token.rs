//! Minimal SPL Token instruction builder — replaces spl-token crate dependency.
//!
//! We build instructions manually using pinocchio_token's program ID constant
//! and raw SPL Token instruction wire format to avoid version conflicts between
//! spl-token 6.0 and solana-program 2.2.1.
//!
//! Wire format is stable (SPL Token is a deployed program; layout never changes).

use solana_program::{
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
};

/// SPL Token program ID (re-exported from pinocchio-token).
pub use pinocchio_token::ID as SPL_TOKEN_PROGRAM_ID;

// Instruction tags from the SPL Token spec.
const IX_INITIALIZE_MINT: u8 = 0;
const IX_INITIALIZE_ACCOUNT: u8 = 1;
const IX_TRANSFER: u8 = 3;
const IX_MINT_TO: u8 = 7;
const IX_BURN: u8 = 8;
// IX_INITIALIZE_MINT2 (tag 20) not used in stake — kept in percolator-prog module

/// SPL Token program ID as a solana-program `Pubkey`.
///
/// Hard-coded from the known stable program ID to avoid any runtime cost.
/// This is the same key as `pinocchio_token::ID`.
#[inline(always)]
pub fn program_id() -> Pubkey {
    solana_program::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
}

/// Build an `InitializeMint` instruction (tag 0).
///
/// Accounts: [WRITE] mint, [READONLY] Rent sysvar.
pub fn initialize_mint(
    mint: &Pubkey,
    mint_authority: &Pubkey,
    freeze_authority: Option<&Pubkey>,
    decimals: u8,
) -> Result<Instruction, ProgramError> {
    // Layout: tag(1) + decimals(1) + mint_authority(32) + freeze_option(1) [+ freeze_authority(32)]
    let mut data = Vec::with_capacity(67);
    data.push(IX_INITIALIZE_MINT);
    data.push(decimals);
    data.extend_from_slice(mint_authority.as_ref());
    match freeze_authority {
        Some(auth) => {
            data.push(1);
            data.extend_from_slice(auth.as_ref());
        }
        None => {
            data.push(0);
            data.extend_from_slice(&[0u8; 32]);
        }
    }
    Ok(Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new_readonly(solana_program::sysvar::rent::id(), false),
        ],
        data,
    })
}

/// Build an `InitializeAccount` instruction (tag 1).
///
/// Accounts: [WRITE] account, [READONLY] mint, [READONLY] owner, [READONLY] Rent sysvar.
pub fn initialize_account(
    account: &Pubkey,
    mint: &Pubkey,
    owner: &Pubkey,
) -> Result<Instruction, ProgramError> {
    Ok(Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(solana_program::sysvar::rent::id(), false),
        ],
        data: vec![IX_INITIALIZE_ACCOUNT],
    })
}

/// Build a `Transfer` instruction (tag 3).
///
/// Accounts: [WRITE] source, [WRITE] dest, [SIGNER] authority.
pub fn transfer(
    source: &Pubkey,
    dest: &Pubkey,
    authority: &Pubkey,
    amount: u64,
) -> Result<Instruction, ProgramError> {
    let mut data = Vec::with_capacity(9);
    data.push(IX_TRANSFER);
    data.extend_from_slice(&amount.to_le_bytes());
    Ok(Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new(*dest, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    })
}

/// Build a `MintTo` instruction (tag 7).
///
/// Accounts: [WRITE] mint, [WRITE] destination, [SIGNER] authority.
pub fn mint_to(
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
) -> Result<Instruction, ProgramError> {
    let mut data = Vec::with_capacity(9);
    data.push(IX_MINT_TO);
    data.extend_from_slice(&amount.to_le_bytes());
    Ok(Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    })
}

/// Build a `Burn` instruction (tag 8).
///
/// Accounts: [WRITE] account, [WRITE] mint, [SIGNER] authority.
pub fn burn(
    account: &Pubkey,
    mint: &Pubkey,
    authority: &Pubkey,
    amount: u64,
) -> Result<Instruction, ProgramError> {
    let mut data = Vec::with_capacity(9);
    data.push(IX_BURN);
    data.extend_from_slice(&amount.to_le_bytes());
    Ok(Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new(*mint, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    })
}

// ═══════════════════════════════════════════════════════════════
// State parsing (zero-copy via pinocchio-token state structs)
// ═══════════════════════════════════════════════════════════════

/// Parse a token account's amount from raw account data.
///
/// Uses pinocchio-token's zero-copy `TokenAccount` layout (same wire format as spl-token).
/// Validates length only; caller must verify account owner is SPL Token program.
///
/// # Safety
/// `data` must be exactly `pinocchio_token::state::TokenAccount::LEN` bytes of valid token
/// account data (same invariant as `spl_token::state::Account::unpack`).
#[inline]
pub fn token_account_amount(data: &[u8]) -> Result<u64, ProgramError> {
    use pinocchio_token::state::TokenAccount;
    if data.len() != TokenAccount::LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    // SAFETY: length verified above; alignment is 1 byte.
    let account = unsafe { TokenAccount::from_bytes_unchecked(data) };
    Ok(account.amount())
}
