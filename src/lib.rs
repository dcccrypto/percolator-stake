//! Percolator Insurance LP Staking Program
//!
//! Manages insurance fund LP staking for Percolator markets.
//! Users deposit collateral, receive LP tokens, and earn yield from insurance operations.
//!
//! DOC CORRECTION (security review C-1, issue #6 lineage): this file previously
//! claimed the human admin wallet "remains the wrapper slab admin" and that admin
//! operations (ResolveMarket, WithdrawInsurance, SetOracleAuthority, etc.) "are
//! called directly on the wrapper — no CPI proxy needed." That is FALSE once
//! marketauth rotation lands: `InitPool` now CPIs the wrapper's `UpdateAuthority`
//! (tag 32) to irreversibly rotate `cfg.marketauth` from the human admin to this
//! program's pool PDA (ported from the deployed `percolator-vault@eb3ebe8`, see
//! `cpi::cpi_update_authority`). After that rotation a PDA — not the human admin
//! — is the wrapper's admin, and a PDA cannot sign a top-level transaction, so
//! EVERY marketauth-gated wrapper instruction must be proxied through a CPI this
//! program issues via `invoke_signed`. `ResolveMarket` (wrapper tag 19) is proxied
//! as `AdminResolveMarket` (tag 24, see `processor::process_admin_resolve_market`)
//! — without it, every InitPool market would be permanently stuck in Live mode.
//! Per-asset authorities (`insurance_authority` / `insurance_operator` /
//! `asset_admin`) have their own, separate Bind/Rotate/Burn proxies (tags 19-22
//! below) and were already correctly proxied before this fix.
//!
//! Instructions:
//!   0  - InitPool:            Create stake pool for a slab, LP mint, vault
//!                              (also rotates wrapper marketauth to the pool PDA)
//!   1  - Deposit:             Deposit collateral → vault, receive LP tokens
//!   2  - Withdraw:            Burn LP tokens → withdraw from vault (after cooldown)
//!   3  - FlushToInsurance:    CPI TopUpInsurance — vault → wrapper insurance fund
//!   4  - UpdateConfig:        Admin updates cooldown, caps, etc.
//!  10  - ReturnInsurance:     Admin returns insurance funds to pool vault
//!  12  - AccrueFees:          Accrue trading fees to LP vault (permissionless)
//!  13  - InitTradingPool:     Initialize pool in trading LP mode
//!  14  - AdminSetHwmConfig:   Set high-water mark configuration
//!  15  - AdminSetTrancheConfig: Configure senior/junior tranches
//!  16  - DepositJunior:       Deposit into junior (first-loss) tranche
//!  18  - SetMarketResolved:   Admin marks pool as resolved (blocks deposits);
//!                              gated on total_flushed <= total_returned (H-1)
//!  19  - BindInsuranceAuthority: one-time bind of insurance_authority to our PDA
//!  20  - RotateInsuranceAuthority: migration escape for insurance_authority
//!  21  - BurnAssetAdmin:      irrevocably burn asset_admin
//!  22  - RotateInsuranceOperator: migration escape for insurance_operator
//!  23  - RecoverFlushedInsurance: PDA-signed recovery of flushed insurance
//!  24  - AdminResolveMarket:  CPI proxy for wrapper ResolveMarket (tag 19) — C-1
//!                              fix; required because marketauth is now the pool
//!                              PDA. Gated on total_flushed <= total_returned (H-1).
//!  25  - AdminUpdateFeeSplit: CPI proxy for wrapper UpdateFeeSplit (tag 86).
//!                              GROUP A — marketauth-gated, POOL PDA signs.
//!  26  - AdminUpdateMaintenanceFeePerSlot: CPI proxy for wrapper tag 88.
//!                              GROUP A — marketauth-gated, POOL PDA signs.
//!                              Payload is u128 (wrapper decodes read_u128).
//!  27  - AdminUpdateBackingFeePolicy: CPI proxy for wrapper tag 51.
//!                              GROUP B — insurance_authority-gated, VAULT_AUTH
//!                              PDA signs. Sets backing_trade_fee_bps; without
//!                              it a staked market's backing fee is unsettable.
//!  28  - AdminUpdateTradeFeePolicy: CPI proxy for wrapper tag 55.
//!                              GROUP B — insurance_authority-gated, VAULT_AUTH
//!                              PDA signs.
//!
//! Wrapper tag 69 (RestartAssetOracle) is deliberately NOT proxied: it is gated
//! on asset_admin, which this program only ever burns to [0;32] (tag 21), and
//! the wrapper's expect_live_authority rejects a zero authority for every
//! signer. See instruction.rs's module doc for the full argument.

// ════════════════════════════════════════════════════════════════════════════
// CANONICAL PROGRAM ID
//
// The percolator wrapper's tag-87 handler (`WithdrawInsuranceReserveToStake`)
// used to recover "the stake program" from `*pool_ai.owner` — an account the
// CALLER supplies — and then validate everything else self-consistently
// against that attacker-chosen program. It now PINS the id instead, and this
// `declare_id!` is the authoritative source that pin mirrors.
//
// Until this existed the wrapper explicitly refused to hardcode an id because
// "percolator-stake has no `declare_id!`, and the candidate ids in this tree
// disagree with each other". This resolves that: the id below is the DEPLOYED
// devnet program, lineage-verified 2026-07-20 by rebuild-and-compare
// (`--features devnet`, at the canonical repo path — the build is
// path-dependent via the root crate's `-C metadata` hash, and building
// elsewhere yields a function-reordered ELF that will NOT match):
//
//   on-chain `solana program dump` (ELF true length, 222624 bytes)
//     sha256 0e9c25725615c3f11fa4db0cd53a3220f8d7d6f24fc4631bc9975c8970fd6e9c
//   local build of percolator-stake@1e08d35 --features devnet
//     sha256 0e9c25725615c3f11fa4db0cd53a3220f8d7d6f24fc4631bc9975c8970fd6e9c
//                                                                      MATCH
//
// CLUSTER GATING (mirrors `processor.rs`'s `PERCOLATOR_MAINNET` /
// `PERCOLATOR_DEVNET` allowlist, and its N-3 rationale): the devnet id is
// gated behind the `devnet` feature so it CANNOT compile into a mainnet
// binary. If the devnet deploy keypair is ever compromised, an attacker who
// deploys a malicious binary at that address on mainnet must not thereby
// inherit any authority a mainnet build grants.
//
// There is deliberately NO mainnet id: v17 percolator-stake has no mainnet
// deployment. Do not invent one. A non-devnet build simply has no `ID`, and
// the wrapper's tag 87 fails closed on that build (see
// `PercolatorError::StakeProgramNotPinned`). When a mainnet deploy happens,
// add the mainnet arm here and in the wrapper's `STAKE_PROGRAM_ID` together.
// ════════════════════════════════════════════════════════════════════════════
#[cfg(feature = "devnet")]
solana_program::declare_id!("GCHhcgwPyrai8SWHEVWw3odedguFXEtJobNnWSfWBCU3");

pub mod cpi;
pub mod error;
pub mod instruction;
pub mod math;
pub mod processor;
pub mod spl_token;
pub mod state;

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint;
