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

    /// 19: BindInsuranceAuthority — ONE-TIME bind of the v16 market's
    /// `insurance_authority` to our `vault_auth` PDA, so FlushToInsurance (which
    /// signs as that PDA) passes v16's authority gate. CPIs the wrapper's
    /// UpdateAuthority(INSURANCE, vault_auth_pda): the admin co-signs as the
    /// current authority and the PDA co-signs via invoke_signed as the new
    /// authority — the only way to bind a PDA (a plain admin tx can't, because the
    /// wrapper requires the new authority to sign and a PDA cannot sign directly).
    /// Must be called once after market creation, before the first flush. Fails
    /// (wrapper Unauthorized) if the admin is no longer the current authority
    /// (i.e. already bound), making it naturally single-use.
    ///
    /// Accounts:
    ///   0. `[signer]` Admin (current insurance_authority; must equal pool.admin)
    ///   1. `[]` Pool PDA
    ///   2. `[]` Vault authority PDA (the new authority; signed via CPI)
    ///   3. `[writable]` Slab / market account (wrapper-owned)
    ///   4. `[]` Percolator program
    BindInsuranceAuthority,

    /// 20: RotateInsuranceAuthority — admin-gated migration/incident primitive
    /// that moves the market's `insurance_authority` OFF our `vault_auth` PDA to an
    /// admin-specified `new_target`. CPIs UpdateAuthority(INSURANCE, new_target)
    /// with the PDA signing as the CURRENT authority (invoke_signed) and new_target
    /// co-signing the outer tx as the NEW authority. This is the ESCAPE from the
    /// otherwise-permanent bind: without it, a stake redeploy to a new program id
    /// would orphan insurance_authority on the dead program and brick the flush.
    /// Migration: rotate to the admin wallet from the OLD program before
    /// decommissioning it, then re-bind from the NEW program before BurnAssetAdmin.
    /// Only works while the PDA is the current authority and before the final burn.
    ///
    /// Accounts:
    ///   0. `[signer]` Admin (must equal pool.admin — the stake-side gate)
    ///   1. `[]` Pool PDA
    ///   2. `[]` Vault authority PDA (the CURRENT authority; signed via CPI)
    ///   3. `[signer]` New target authority (the successor; co-signs the outer tx)
    ///   4. `[writable]` Slab / market account (wrapper-owned)
    ///   5. `[]` Percolator program
    RotateInsuranceAuthority,

    /// 21: BurnAssetAdmin — irrevocably remove the admin's rotate-back capability.
    /// Calls UpdateAssetAuthority(kind=0, new_pubkey=[0;32]) to burn asset_admin to
    /// zero. After this, no key can rotate any per-asset authority (insurance,
    /// operator, backing, oracle) back to an admin-controlled key through stake.
    /// Stake also records the burn and disables its PDA-signed rotate escapes.
    ///
    /// IRREVERSIBLE. Only call this after BindInsuranceAuthority has completed.
    /// Must NOT be called again if asset_admin is already zero (causes Unauthorized).
    ///
    /// Accounts:
    ///   0. `[signer]` Admin (current asset_admin == pool.admin)
    ///   1. `[writable]` Pool PDA
    ///   2. `[]` Vault authority PDA (placeholder new_authority slot — not checked for burn)
    ///   3. `[writable]` Slab / market account (wrapper-owned)
    ///   4. `[]` Percolator program
    BurnAssetAdmin,

    /// 22: RotateInsuranceOperator — admin-gated migration escape for the
    /// insurance_operator. Analogous to RotateInsuranceAuthority (tag 20) but for
    /// kind=2 (ASSET_AUTH_INSURANCE_OPERATOR). The vault_auth PDA signs as the
    /// CURRENT operator (invoke_signed); new_target co-signs the outer tx.
    ///
    /// Part of the full no-lockout migration sequence, before final burn:
    ///   1. RotateInsuranceAuthority (tag 20): authority PDA → admin wallet
    ///   2. RotateInsuranceOperator  (tag 22): operator  PDA → admin wallet
    ///   3. Re-bind from NEW program (BindInsuranceAuthority, tag 19)
    ///   4. BurnAssetAdmin (tag 21) when the new bind is final
    ///
    /// Accounts:
    ///   0. `[signer]` Admin (must equal pool.admin — the stake-side gate)
    ///   1. `[]` Pool PDA
    ///   2. `[]` Vault authority PDA (the CURRENT operator; signed via CPI)
    ///   3. `[signer]` New target operator (co-signs the outer tx)
    ///   4. `[writable]` Slab / market account (wrapper-owned)
    ///   5. `[]` Percolator program
    RotateInsuranceOperator,

    /// 4: Admin updates pool configuration.
    ///
    /// Accounts:
    ///   0. `[signer]` Admin
    ///   1. `[writable]` Pool PDA
    UpdateConfig {
        new_cooldown_slots: Option<u64>,
        new_deposit_cap: Option<u64>,
    },

    /// 5: ProposeAdmin — step 1 of two-step admin rotation. The CURRENT admin
    /// proposes a new admin, written to pool.pending_admin. The proposed admin
    /// does not gain any authority until they call AcceptAdmin (step 2).
    /// Proposing the zero pubkey CANCELS an outstanding proposal.
    ///
    /// This safe ownership-transfer idiom (propose + accept) prevents handing the
    /// pool to a key nobody controls (a one-step transfer to a typo'd address
    /// would permanently brick admin operations on a real-money insurance vault).
    ///
    /// Accounts:
    ///   0. `[signer]` Current admin
    ///   1. `[writable]` Pool PDA
    ProposeAdmin { new_admin: [u8; 32] },

    /// 6: AcceptAdmin — step 2 of two-step admin rotation. The PENDING admin
    /// (the proposed new admin) signs to take ownership: pool.admin =
    /// pool.pending_admin, then pending_admin is cleared. Requires an outstanding
    /// proposal (pending_admin != 0) and the signer to equal pending_admin.
    ///
    /// Accounts:
    ///   0. `[signer]` Pending admin (the proposed new admin)
    ///   1. `[writable]` Pool PDA
    AcceptAdmin,

    // Tags 7-9, 11 removed: were admin CPI proxies (SetOracleAuthority,
    // SetRiskThreshold, SetMaintenanceFee, ResolveMarket, SetInsurancePolicy).
    // Human admin now calls wrapper directly. Tags 5/6 reclaimed for admin rotation.
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
    AdminSetHwmConfig { enabled: bool, hwm_floor_bps: u16 },

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
                let cooldown_slots = u64::from_le_bytes(
                    rest[0..8]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                let deposit_cap = u64::from_le_bytes(
                    rest[8..16]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                Ok(Self::InitPool {
                    cooldown_slots,
                    deposit_cap,
                })
            }
            1 => {
                if rest.len() < 8 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let amount = u64::from_le_bytes(
                    rest[0..8]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                Ok(Self::Deposit { amount })
            }
            2 => {
                if rest.len() < 8 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let lp_amount = u64::from_le_bytes(
                    rest[0..8]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                Ok(Self::Withdraw { lp_amount })
            }
            3 => {
                if rest.len() < 8 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let amount = u64::from_le_bytes(
                    rest[0..8]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                Ok(Self::FlushToInsurance { amount })
            }
            4 => {
                if rest.len() < 18 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let has_cooldown = rest[0] != 0;
                let cooldown = u64::from_le_bytes(
                    rest[1..9]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                let has_cap = rest[9] != 0;
                let cap = u64::from_le_bytes(
                    rest[10..18]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                Ok(Self::UpdateConfig {
                    new_cooldown_slots: if has_cooldown { Some(cooldown) } else { None },
                    new_deposit_cap: if has_cap { Some(cap) } else { None },
                })
            }
            5 => {
                if rest.len() < 32 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let new_admin: [u8; 32] = rest[0..32]
                    .try_into()
                    .map_err(|_| ProgramError::InvalidInstructionData)?;
                Ok(Self::ProposeAdmin { new_admin })
            }
            6 => Ok(Self::AcceptAdmin),
            // Tags 7-9, 11 tombstoned — were admin CPI proxies, now removed.
            19 => Ok(Self::BindInsuranceAuthority),
            20 => Ok(Self::RotateInsuranceAuthority),
            21 => Ok(Self::BurnAssetAdmin),
            22 => Ok(Self::RotateInsuranceOperator),
            10 => {
                if rest.len() < 8 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let amount = u64::from_le_bytes(
                    rest[0..8]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                Ok(Self::ReturnInsurance { amount })
            }
            12 => Ok(Self::AccrueFees),
            13 => {
                if rest.len() < 16 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let cooldown_slots = u64::from_le_bytes(
                    rest[0..8]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                let deposit_cap = u64::from_le_bytes(
                    rest[8..16]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
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
                let hwm_floor_bps = u16::from_le_bytes(
                    rest[1..3]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                Ok(Self::AdminSetHwmConfig {
                    enabled,
                    hwm_floor_bps,
                })
            }
            15 => {
                if rest.len() < 2 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let junior_fee_mult_bps = u16::from_le_bytes(
                    rest[0..2]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
                Ok(Self::AdminSetTrancheConfig {
                    junior_fee_mult_bps,
                })
            }
            16 => {
                if rest.len() < 8 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let amount = u64::from_le_bytes(
                    rest[0..8]
                        .try_into()
                        .map_err(|_| ProgramError::InvalidInstructionData)?,
                );
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
            StakeInstruction::InitPool {
                cooldown_slots,
                deposit_cap,
            } => {
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
        // Tags 7-9, 11, 17 remain tombstoned (5/6 reclaimed for admin rotation).
        for tag in [7u8, 8, 9, 11, 17] {
            let data = vec![tag];
            assert!(
                StakeInstruction::unpack(&data).is_err(),
                "tag {} should be rejected",
                tag
            );
        }
    }

    #[test]
    fn test_unpack_propose_admin() {
        let new_admin = [7u8; 32];
        let mut data = vec![5u8];
        data.extend_from_slice(&new_admin);
        match StakeInstruction::unpack(&data).unwrap() {
            StakeInstruction::ProposeAdmin { new_admin: got } => assert_eq!(got, new_admin),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_unpack_propose_admin_truncated_rejected() {
        // tag 5 with < 32 payload bytes must error gracefully, not panic.
        let mut data = vec![5u8];
        data.extend_from_slice(&[0u8; 31]); // one byte short
        assert!(StakeInstruction::unpack(&data).is_err());
        // tag-only (no payload) also rejects.
        assert!(StakeInstruction::unpack(&[5u8]).is_err());
    }

    #[test]
    fn test_unpack_accept_admin() {
        match StakeInstruction::unpack(&[6u8]).unwrap() {
            StakeInstruction::AcceptAdmin => {}
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_unpack_bind_insurance_authority() {
        match StakeInstruction::unpack(&[19u8]).unwrap() {
            StakeInstruction::BindInsuranceAuthority => {}
            _ => panic!("wrong variant"),
        }
        // trailing bytes are ignored (no payload); still decodes.
        match StakeInstruction::unpack(&[19u8, 0, 0]).unwrap() {
            StakeInstruction::BindInsuranceAuthority => {}
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_unpack_rotate_insurance_authority() {
        match StakeInstruction::unpack(&[20u8]).unwrap() {
            StakeInstruction::RotateInsuranceAuthority => {}
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_propose_admin_zero_pubkey_cancel_sentinel_unpacks() {
        // Proposing the zero pubkey is the documented "cancel" sentinel; unpack
        // must accept it (the processor interprets zero as cancel).
        let mut data = vec![5u8];
        data.extend_from_slice(&[0u8; 32]);
        match StakeInstruction::unpack(&data).unwrap() {
            StakeInstruction::ProposeAdmin { new_admin } => assert_eq!(new_admin, [0u8; 32]),
            _ => panic!("wrong variant"),
        }
    }

    /// S-5: every byte-reading tag must reject a truncated payload gracefully
    /// (Err, never panic). Feeds one byte short of each tag's required length.
    #[test]
    fn test_truncated_payloads_never_panic() {
        // (tag, required_payload_len)
        let cases: &[(u8, usize)] = &[
            (0, 16),
            (1, 8),
            (2, 8),
            (3, 8),
            (4, 18),
            (5, 32),
            (10, 8),
            (13, 16),
            (14, 3),
            (15, 2),
            (16, 8),
        ];
        for &(tag, need) in cases {
            for short_len in 0..need {
                let mut data = vec![tag];
                data.extend_from_slice(&vec![0u8; short_len]);
                let res = StakeInstruction::unpack(&data);
                assert!(
                    res.is_err(),
                    "tag {} with {} payload bytes (need {}) must Err, not panic",
                    tag,
                    short_len,
                    need
                );
            }
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
