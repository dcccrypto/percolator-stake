//! Percolator Insurance LP Staking Program (v3 — no admin proxy)
//!
//! Manages insurance fund LP staking for Percolator markets.
//! Users deposit collateral, receive LP tokens, and earn yield from insurance operations.
//!
//! The human admin wallet remains the wrapper slab admin.
//! Admin operations (ResolveMarket, WithdrawInsurance, SetOracleAuthority, etc.)
//! are called directly on the wrapper — no CPI proxy needed.
//!
//! Instructions:
//!   0  - InitPool:            Create stake pool for a slab, LP mint, vault
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
//!  18  - SetMarketResolved:   Admin marks pool as resolved (blocks deposits)

pub mod cpi;
pub mod error;
pub mod instruction;
pub mod math;
pub mod processor;
pub mod spl_token;
pub mod state;

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint;
