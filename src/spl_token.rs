//! Minimal SPL Token helpers for percolator-stake.
//!
//! Replaces the spl-token 6.0 crate dependency with raw wire-format builders and
//! byte-level state parsers. Wire format is stable: SPL Token is a frozen deployed program.
//!
//! Pattern mirrors percolator-prog/src/spl_token.rs — byte-for-byte identical wire format.

use solana_program::{
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
};

/// SPL Token program ID.
#[inline(always)]
pub fn id() -> Pubkey {
    solana_program::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
}

// ─── Instruction tags ────────────────────────────────────────────────────────

const IX_INITIALIZE_MINT: u8 = 0;
const IX_INITIALIZE_ACCOUNT: u8 = 1;
const IX_TRANSFER: u8 = 3;
const IX_MINT_TO: u8 = 7;
const IX_BURN: u8 = 8;

// ─── CPI instruction builders ────────────────────────────────────────────────

/// `InitializeMint` (tag 0).  Accounts: [WRITE] mint, [RO] Rent sysvar.
///
/// Wire layout (freeze=Some): tag(1) + decimals(1) + mint_authority(32) + option(1) + freeze(32) = 67 bytes
/// Wire layout (freeze=None): tag(1) + decimals(1) + mint_authority(32) + option(1)              = 35 bytes
pub fn initialize_mint(
    _program_id: &Pubkey,
    mint: &Pubkey,
    mint_authority: &Pubkey,
    freeze_authority: Option<&Pubkey>,
    decimals: u8,
) -> Result<Instruction, ProgramError> {
    let data = match freeze_authority {
        None => {
            let mut d = [0u8; 35];
            d[0] = IX_INITIALIZE_MINT;
            d[1] = decimals;
            d[2..34].copy_from_slice(mint_authority.as_ref());
            // d[34] = 0 (freeze absent) — already zero
            d.to_vec()
        }
        Some(auth) => {
            let mut d = [0u8; 67];
            d[0] = IX_INITIALIZE_MINT;
            d[1] = decimals;
            d[2..34].copy_from_slice(mint_authority.as_ref());
            d[34] = 1;
            d[35..67].copy_from_slice(auth.as_ref());
            d.to_vec()
        }
    };
    Ok(Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new_readonly(solana_program::sysvar::rent::id(), false),
        ],
        data,
    })
}

/// `InitializeAccount` (tag 1).  Accounts: [WRITE] account, [RO] mint, [RO] owner, [RO] Rent sysvar.
pub fn initialize_account(
    _program_id: &Pubkey,
    account: &Pubkey,
    mint: &Pubkey,
    owner: &Pubkey,
) -> Result<Instruction, ProgramError> {
    Ok(Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(solana_program::sysvar::rent::id(), false),
        ],
        data: vec![IX_INITIALIZE_ACCOUNT],
    })
}

/// `Transfer` (tag 3).  Accounts: [WRITE] source, [WRITE] dest, [SIGNER] authority.
pub fn transfer(
    _program_id: &Pubkey,
    source: &Pubkey,
    dest: &Pubkey,
    authority: &Pubkey,
    _multisigners: &[&Pubkey],
    amount: u64,
) -> Result<Instruction, ProgramError> {
    let mut data = [0u8; 9];
    data[0] = IX_TRANSFER;
    data[1..9].copy_from_slice(&amount.to_le_bytes());
    Ok(Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(*source, false),
            AccountMeta::new(*dest, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data: data.to_vec(),
    })
}

/// `MintTo` (tag 7).  Accounts: [WRITE] mint, [WRITE] destination, [SIGNER] authority.
pub fn mint_to(
    _program_id: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    _multisigners: &[&Pubkey],
    amount: u64,
) -> Result<Instruction, ProgramError> {
    let mut data = [0u8; 9];
    data[0] = IX_MINT_TO;
    data[1..9].copy_from_slice(&amount.to_le_bytes());
    Ok(Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(*mint, false),
            AccountMeta::new(*destination, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data: data.to_vec(),
    })
}

/// `Burn` (tag 8).  Accounts: [WRITE] account, [WRITE] mint, [SIGNER] authority.
pub fn burn(
    _program_id: &Pubkey,
    account: &Pubkey,
    mint: &Pubkey,
    authority: &Pubkey,
    _multisigners: &[&Pubkey],
    amount: u64,
) -> Result<Instruction, ProgramError> {
    let mut data = [0u8; 9];
    data[0] = IX_BURN;
    data[1..9].copy_from_slice(&amount.to_le_bytes());
    Ok(Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(*account, false),
            AccountMeta::new(*mint, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data: data.to_vec(),
    })
}

// ─── State parsing ────────────────────────────────────────────────────────────

pub mod state {
    use solana_program::program_error::ProgramError;

    // Re-export AccountState from pinocchio-token — same enum discriminants as spl-token 6.0.
    pub use pinocchio_token::state::AccountState;

    /// spl_token::state::Account::LEN = 165
    pub const ACCOUNT_LEN: usize = 165;

    // Token account layout (matches spl-token 6.0 and pinocchio-token 0.5.0):
    //   [0..32]   mint (Pubkey)
    //   [32..64]  owner (Pubkey)
    //   [64..72]  amount (u64 LE)
    //   [72..76]  delegate_option (u32 LE)
    //   [76..108] delegate (Pubkey)
    //   [108]     state (u8: 0=uninit, 1=initialized, 2=frozen)
    //   ... (remaining fields unused by percolator-stake)

    pub struct Account {
        pub amount: u64,
        pub state: AccountState,
    }

    impl Account {
        /// Equivalent to `spl_token::state::Account::unpack`.
        pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
            if data.len() < ACCOUNT_LEN {
                return Err(ProgramError::InvalidAccountData);
            }
            let amount = u64::from_le_bytes(
                data[64..72]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidAccountData)?,
            );
            let state = match data[108] {
                0 => AccountState::Uninitialized,
                1 => AccountState::Initialized,
                2 => AccountState::Frozen,
                _ => return Err(ProgramError::InvalidAccountData),
            };
            Ok(Self { amount, state })
        }
    }
}
