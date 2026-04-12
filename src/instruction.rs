use solana_program::program_error::ProgramError;

/// Instructions for the Percolator Insurance LP Staking program (v3 — no admin proxy).
///
/// The stake program handles deposits, withdrawals, LP math, insurance flush/return,
/// fee accrual, HWM, and tranches. All wrapper admin operations (ResolveMarket,
/// SetOracleAuthority, WithdrawInsurance, etc.) are called directly by the human
/// admin wallet on the wrapper program.
#[derive(Debug)]
pub enum StakeInstruction {
    /// 0: Initialize a stake pool for a slab (market).
    ///
    /// Accounts:
    ///   0. `[signer, writable]` Admin (pays rent, becomes pool admin)
    ///   1. `[]` Slab account (the percolator market)
    ///   2. `[writable]` Pool PDA (stake_pool, to be created)
    ///   3. `[writable]` LP Mint (to be created, authority = vault_auth PDA)
    ///   4. `[writable]` Vault token account (to be created, authority = vault_auth PDA)
    ///   5. `[]` Vault authority PDA
    ///   6. `[]` Collateral mint
    ///   7. `[]` Percolator program ID
    ///   8. `[]` Token program
    ///   9. `[]` System program
    ///  10. `[]` Rent sysvar
    InitPool {
        cooldown_slots: u64,
        deposit_cap: u64,
    },

    /// 1: Deposit collateral into the stake vault. Mints LP tokens pro-rata.
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

    /// 2: Withdraw collateral by burning LP tokens. Subject to cooldown.
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

    /// 3: CPI into percolator wrapper's TopUpInsurance to move collateral from
    /// stake vault → wrapper insurance fund.
    ///
    /// Accounts:
    ///   0. `[signer]` Caller (admin-only per C10 fix)
    ///   1. `[writable]` Pool PDA
    ///   2. `[writable]` Pool vault token account (source)
    ///   3. `[]` Vault authority PDA (signs CPI)
    ///   4. `[writable]` Slab account
    ///   5. `[writable]` Wrapper vault token account (destination)
    ///   6. `[]` Percolator program
    ///   7. `[]` Token program
    FlushToInsurance { amount: u64 },

    /// 4: Admin updates pool configuration.
    ///
    /// Accounts:
    ///   0. `[signer]` Admin
    ///   1. `[writable]` Pool PDA
    UpdateConfig {
        new_cooldown_slots: Option<u64>,
        new_deposit_cap: Option<u64>,
    },

    // Tags 5-9, 11 removed: were admin CPI proxies (TransferAdmin, SetOracleAuthority,
    // SetRiskThreshold, SetMaintenanceFee, ResolveMarket, SetInsurancePolicy).
    // Human admin now calls wrapper directly.

    /// 10: Return insurance funds to the pool vault.
    /// Admin calls WithdrawInsurance on the wrapper directly (gets USDC to admin ATA),
    /// then calls this to transfer from admin ATA to pool vault and update accounting.
    ///
    /// Accounts:
    ///   0. `[signer]` Admin
    ///   1. `[writable]` Pool PDA
    ///   2. `[writable]` Admin's collateral token account (source)
    ///   3. `[writable]` Pool vault token account (destination)
    ///   4. `[]` Token program
    ReturnInsurance { amount: u64 },

    /// 12: Accrue trading fees from percolator engine to LP vault.
    /// Permissionless — anyone can trigger.
    ///
    /// Accounts:
    ///   0. `[signer]` Caller (permissionless)
    ///   1. `[writable]` Pool PDA
    ///   2. `[]` Pool vault token account (read balance)
    ///   3. `[]` Clock sysvar
    AccrueFees,

    /// 13: Initialize pool in trading LP mode (pool_mode = 1).
    ///
    /// Accounts: same as InitPool
    InitTradingPool {
        cooldown_slots: u64,
        deposit_cap: u64,
    },

    /// 14: Set high-water mark configuration.
    ///
    /// Accounts:
    ///   0. `[signer]` Admin
    ///   1. `[writable]` Pool PDA
    AdminSetHwmConfig {
        enabled: bool,
        hwm_floor_bps: u16,
    },

    /// 15: Enable/configure senior-junior LP tranches.
    ///
    /// Accounts:
    ///   0. `[signer]` Admin
    ///   1. `[writable]` Pool PDA
    AdminSetTrancheConfig { junior_fee_mult_bps: u16 },

    /// 16: Deposit into the junior (first-loss) tranche.
    ///
    /// Accounts: same as Deposit
    DepositJunior { amount: u64 },

    /// 18: Admin marks the pool as market-resolved (blocks new deposits).
    /// Call this after resolving the market on the wrapper directly.
    ///
    /// Accounts:
    ///   0. `[signer]` Admin
    ///   1. `[writable]` Pool PDA
    SetMarketResolved,
}

impl StakeInstruction {
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        let (&tag, rest) = data
            .split_first()
            .ok_or(ProgramError::InvalidInstructionData)?;

        match tag {
            0 => {
                if rest.len() < 16 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let cooldown_slots = u64::from_le_bytes(rest[0..8].try_into().unwrap());
                let deposit_cap = u64::from_le_bytes(rest[8..16].try_into().unwrap());
                Ok(Self::InitPool {
                    cooldown_slots,
                    deposit_cap,
                })
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
            // Tags 5-9, 11 tombstoned — were admin CPI proxies, now removed.
            10 => {
                if rest.len() < 8 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let amount = u64::from_le_bytes(rest[0..8].try_into().unwrap());
                Ok(Self::ReturnInsurance { amount })
            }
            12 => Ok(Self::AccrueFees),
            13 => {
                if rest.len() < 16 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let cooldown_slots = u64::from_le_bytes(rest[0..8].try_into().unwrap());
                let deposit_cap = u64::from_le_bytes(rest[8..16].try_into().unwrap());
                Ok(Self::InitTradingPool {
                    cooldown_slots,
                    deposit_cap,
                })
            }
            14 => {
                if rest.len() < 3 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let enabled = rest[0] != 0;
                let hwm_floor_bps = u16::from_le_bytes(rest[1..3].try_into().unwrap());
                Ok(Self::AdminSetHwmConfig {
                    enabled,
                    hwm_floor_bps,
                })
            }
            15 => {
                if rest.len() < 2 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let junior_fee_mult_bps = u16::from_le_bytes(rest[0..2].try_into().unwrap());
                Ok(Self::AdminSetTrancheConfig {
                    junior_fee_mult_bps,
                })
            }
            16 => {
                if rest.len() < 8 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let amount = u64::from_le_bytes(rest[0..8].try_into().unwrap());
                Ok(Self::DepositJunior { amount })
            }
            18 => Ok(Self::SetMarketResolved),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unpack_init_pool() {
        let mut data = vec![0u8];
        data.extend_from_slice(&100u64.to_le_bytes());
        data.extend_from_slice(&5000u64.to_le_bytes());
        match StakeInstruction::unpack(&data).unwrap() {
            StakeInstruction::InitPool { cooldown_slots, deposit_cap } => {
                assert_eq!(cooldown_slots, 100);
                assert_eq!(deposit_cap, 5000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_unpack_deposit() {
        let mut data = vec![1u8];
        data.extend_from_slice(&42u64.to_le_bytes());
        match StakeInstruction::unpack(&data).unwrap() {
            StakeInstruction::Deposit { amount } => assert_eq!(amount, 42),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_unpack_withdraw() {
        let mut data = vec![2u8];
        data.extend_from_slice(&999u64.to_le_bytes());
        match StakeInstruction::unpack(&data).unwrap() {
            StakeInstruction::Withdraw { lp_amount } => assert_eq!(lp_amount, 999),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_unpack_return_insurance() {
        let mut data = vec![10u8];
        data.extend_from_slice(&1234u64.to_le_bytes());
        match StakeInstruction::unpack(&data).unwrap() {
            StakeInstruction::ReturnInsurance { amount } => assert_eq!(amount, 1234),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_unpack_set_market_resolved() {
        let data = vec![18u8];
        match StakeInstruction::unpack(&data).unwrap() {
            StakeInstruction::SetMarketResolved => {}
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_tombstoned_tags_rejected() {
        // Tags 5-9, 11, 17 should all return InvalidInstructionData
        for tag in [5u8, 6, 7, 8, 9, 11, 17] {
            let data = vec![tag];
            assert!(
                StakeInstruction::unpack(&data).is_err(),
                "tag {} should be rejected",
                tag
            );
        }
    }

    #[test]
    fn test_unpack_invalid_tag() {
        assert!(StakeInstruction::unpack(&[255u8]).is_err());
    }

    #[test]
    fn test_unpack_empty() {
        assert!(StakeInstruction::unpack(&[]).is_err());
    }
}
