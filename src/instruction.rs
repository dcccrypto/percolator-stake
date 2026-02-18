use solana_program::{program_error::ProgramError, pubkey::Pubkey};

/// Instructions for the Percolator Insurance LP Staking program (v2 — PDA Admin).
#[derive(Debug)]
pub enum StakeInstruction {
    /// Initialize a stake pool for a slab (market).
    /// Creates the pool PDA, LP mint, and collateral vault.
    ///
    /// Accounts:
    ///   0. `[signer, writable]` Admin (pays rent, becomes pool admin)
    ///   1. `[]` Slab account (the percolator market)
    ///   2. `[writable]` Pool PDA (stake_pool, to be created)
    ///   3. `[writable]` LP Mint (to be created, authority = vault_auth PDA)
    ///   4. `[writable]` Vault token account (to be created, authority = vault_auth PDA)
    ///   5. `[]` Vault authority PDA
    ///   6. `[]` Collateral mint (must match slab's collateral mint)
    ///   7. `[]` Percolator program ID
    ///   8. `[]` Token program
    ///   9. `[]` System program
    ///  10. `[]` Rent sysvar
    InitPool {
        cooldown_slots: u64,
        deposit_cap: u64,
    },

    /// Deposit collateral into the stake vault. Mints LP tokens pro-rata.
    ///
    /// Accounts:
    ///   0. `[signer]` User depositing
    ///   1. `[writable]` Pool PDA
    ///   2. `[writable]` User's collateral token account (source)
    ///   3. `[writable]` Pool vault token account (destination)
    ///   4. `[writable]` LP mint (to mint LP tokens)
    ///   5. `[writable]` User's LP token account (receives LP tokens)
    ///   6. `[]` Vault authority PDA (mint authority)
    ///   7. `[writable]` Deposit PDA (per-user, created if needed)
    ///   8. `[]` Token program
    ///   9. `[]` Clock sysvar
    ///  10. `[]` System program
    Deposit { amount: u64 },

    /// Withdraw collateral by burning LP tokens. Subject to cooldown.
    /// Withdrawal limited by vault balance (buffer). If insurance has been
    /// flushed, user may need to wait for market resolution to get full value.
    ///
    /// Accounts:
    ///   0. `[signer]` User withdrawing
    ///   1. `[writable]` Pool PDA
    ///   2. `[writable]` User's LP token account (source, tokens burned)
    ///   3. `[writable]` LP mint (to burn)
    ///   4. `[writable]` Pool vault token account (source of collateral)
    ///   5. `[writable]` User's collateral token account (destination)
    ///   6. `[]` Vault authority PDA (transfer authority)
    ///   7. `[writable]` Deposit PDA (per-user, cooldown check)
    ///   8. `[]` Token program
    ///   9. `[]` Clock sysvar
    Withdraw { lp_amount: u64 },

    /// CPI into percolator wrapper's TopUpInsurance to move collateral from
    /// stake vault → wrapper insurance fund. Permissionless trigger.
    ///
    /// The vault_auth PDA signs as the TopUpInsurance "signer" — the wrapper
    /// verifies the signer's ATA (our vault) and transfers to wrapper vault.
    ///
    /// Accounts:
    ///   0. `[signer]` Caller (permissionless, just pays tx fee)
    ///   1. `[writable]` Pool PDA
    ///   2. `[writable]` Pool vault token account (source — "signer_ata" for CPI)
    ///   3. `[]` Vault authority PDA (signs CPI as TopUpInsurance signer)
    ///   4. `[writable]` Slab account (percolator market, writable for CPI)
    ///   5. `[writable]` Wrapper vault token account (destination)
    ///   6. `[]` Percolator program
    ///   7. `[]` Token program
    FlushToInsurance { amount: u64 },

    /// Admin updates pool configuration.
    ///
    /// Accounts:
    ///   0. `[signer]` Admin
    ///   1. `[writable]` Pool PDA
    UpdateConfig {
        new_cooldown_slots: Option<u64>,
        new_deposit_cap: Option<u64>,
    },

    /// Transfer wrapper slab admin authority to the pool PDA.
    /// One-time setup — the current wrapper admin (human) must sign.
    /// After this, the pool PDA IS the admin and can CPI admin instructions.
    ///
    /// Accounts:
    ///   0. `[signer]` Current wrapper admin (human)
    ///   1. `[writable]` Pool PDA (admin_transferred flag updated)
    ///   2. `[writable]` Slab account (wrapper, admin field updated via CPI)
    ///   3. `[]` Percolator program
    TransferAdmin,

    /// Pool admin forwards SetOracleAuthority to wrapper via CPI.
    /// Pool PDA signs as wrapper admin.
    ///
    /// Accounts:
    ///   0. `[signer]` Pool admin (human who controls this pool)
    ///   1. `[]` Pool PDA (wrapper admin, signs CPI)
    ///   2. `[writable]` Slab account
    ///   3. `[]` Percolator program
    AdminSetOracleAuthority { new_authority: Pubkey },

    /// Pool admin forwards SetRiskThreshold to wrapper via CPI.
    ///
    /// Accounts:
    ///   0. `[signer]` Pool admin
    ///   1. `[]` Pool PDA (wrapper admin, signs CPI)
    ///   2. `[writable]` Slab account
    ///   3. `[]` Percolator program
    AdminSetRiskThreshold { new_threshold: u128 },

    /// Pool admin forwards SetMaintenanceFee to wrapper via CPI.
    ///
    /// Accounts:
    ///   0. `[signer]` Pool admin
    ///   1. `[]` Pool PDA (wrapper admin, signs CPI)
    ///   2. `[writable]` Slab account
    ///   3. `[]` Percolator program
    AdminSetMaintenanceFee { new_fee: u128 },

    /// Pool admin resolves the market (end of epoch). Wrapper enters withdraw-only mode.
    ///
    /// Accounts:
    ///   0. `[signer]` Pool admin
    ///   1. `[]` Pool PDA (wrapper admin, signs CPI)
    ///   2. `[writable]` Slab account
    ///   3. `[]` Percolator program
    AdminResolveMarket,

    /// Pool admin withdraws insurance fund after market resolution.
    /// Tokens go to pool vault (via vault_auth ATA), then available for LP holder withdrawals.
    ///
    /// Accounts:
    ///   0. `[signer]` Pool admin
    ///   1. `[writable]` Pool PDA (wrapper admin, signs CPI; state updated)
    ///   2. `[writable]` Slab account
    ///   3. `[writable]` Pool vault token account (receives insurance — "admin_ata" for CPI)
    ///   4. `[]` Vault authority PDA (owner of pool vault)
    ///   5. `[writable]` Wrapper vault token account (source)
    ///   6. `[]` Wrapper vault authority PDA
    ///   7. `[]` Percolator program
    ///   8. `[]` Token program
    /// 10: AdminWithdrawInsurance — calls WithdrawInsuranceLimited via vault_auth PDA.
    /// Requires market RESOLVED and SetInsuranceWithdrawPolicy called with vault_auth as authority.
    AdminWithdrawInsurance { amount: u64 },

    /// Pool admin sets insurance withdrawal policy on wrapper.
    ///
    /// Accounts:
    ///   0. `[signer]` Pool admin
    ///   1. `[]` Pool PDA (wrapper admin, signs CPI)
    ///   2. `[writable]` Slab account
    ///   3. `[]` Percolator program
    AdminSetInsurancePolicy {
        authority: Pubkey,
        min_withdraw_base: u64,
        max_withdraw_bps: u16,
        cooldown_slots: u64,
    },
}

impl StakeInstruction {
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        let (&tag, rest) = data.split_first().ok_or(ProgramError::InvalidInstructionData)?;

        match tag {
            0 => {
                // InitPool: cooldown_slots(8) + deposit_cap(8)
                if rest.len() < 16 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let cooldown_slots = u64::from_le_bytes(rest[0..8].try_into().unwrap());
                let deposit_cap = u64::from_le_bytes(rest[8..16].try_into().unwrap());
                Ok(Self::InitPool { cooldown_slots, deposit_cap })
            }
            1 => {
                if rest.len() < 8 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let amount = u64::from_le_bytes(rest[0..8].try_into().unwrap());
                Ok(Self::Deposit { amount })
            }
            2 => {
                if rest.len() < 8 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let lp_amount = u64::from_le_bytes(rest[0..8].try_into().unwrap());
                Ok(Self::Withdraw { lp_amount })
            }
            3 => {
                if rest.len() < 8 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let amount = u64::from_le_bytes(rest[0..8].try_into().unwrap());
                Ok(Self::FlushToInsurance { amount })
            }
            4 => {
                if rest.len() < 18 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let has_cooldown = rest[0] != 0;
                let cooldown = u64::from_le_bytes(rest[1..9].try_into().unwrap());
                let has_cap = rest[9] != 0;
                let cap = u64::from_le_bytes(rest[10..18].try_into().unwrap());
                Ok(Self::UpdateConfig {
                    new_cooldown_slots: if has_cooldown { Some(cooldown) } else { None },
                    new_deposit_cap: if has_cap { Some(cap) } else { None },
                })
            }
            5 => Ok(Self::TransferAdmin),
            6 => {
                if rest.len() < 32 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let new_authority = Pubkey::try_from(&rest[0..32])
                    .map_err(|_| ProgramError::InvalidInstructionData)?;
                Ok(Self::AdminSetOracleAuthority { new_authority })
            }
            7 => {
                if rest.len() < 16 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let new_threshold = u128::from_le_bytes(rest[0..16].try_into().unwrap());
                Ok(Self::AdminSetRiskThreshold { new_threshold })
            }
            8 => {
                if rest.len() < 16 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let new_fee = u128::from_le_bytes(rest[0..16].try_into().unwrap());
                Ok(Self::AdminSetMaintenanceFee { new_fee })
            }
            9 => Ok(Self::AdminResolveMarket),
            10 => {
                if rest.len() < 8 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let amount = u64::from_le_bytes(rest[0..8].try_into().unwrap());
                Ok(Self::AdminWithdrawInsurance { amount })
            }
            11 => {
                if rest.len() < 50 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let authority = Pubkey::try_from(&rest[0..32])
                    .map_err(|_| ProgramError::InvalidInstructionData)?;
                let min_withdraw_base = u64::from_le_bytes(rest[32..40].try_into().unwrap());
                let max_withdraw_bps = u16::from_le_bytes(rest[40..42].try_into().unwrap());
                let cooldown_slots = u64::from_le_bytes(rest[42..50].try_into().unwrap());
                Ok(Self::AdminSetInsurancePolicy {
                    authority,
                    min_withdraw_base,
                    max_withdraw_bps,
                    cooldown_slots,
                })
            }
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}
