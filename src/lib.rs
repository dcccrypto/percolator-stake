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

pub mod cpi;
pub mod error;
pub mod instruction;
pub mod math;
pub mod processor;
pub mod spl_token;
pub mod state;

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint;
