//! Percolator Insurance LP Staking Program (v2 — PDA Admin Architecture)
//!
//! Separate program that manages insurance fund LP staking for Percolator markets.
//! Per Toly's architecture: "Some external program is the admin key via the PDA,
//! and implements staking and all the reward APIs, and can create new markets and
//! can withdraw insurance and rewards via some policy that is 'safe'. But it's just
//! a PDA admin on the thin wrapper. So security audits and changes can be isolated."
//!
//! Architecture:
//! - The stake_pool PDA (per slab) becomes the ADMIN of the percolator wrapper slab
//! - Users deposit collateral → stake vault (liquidity buffer)
//! - LP tokens represent proportional ownership of pool (vault + flushed to insurance)
//! - FlushToInsurance: CPI into wrapper's TopUpInsurance to fund insurance
//! - Admin operations (set oracle, risk thresholds) forwarded via CPI with PDA signature
//! - Wrapper stays thin (pure perp math) — policy logic lives here
//! - Security audits isolated: audit wrapper for math, audit this for policy
//!
//! Instructions:
//!   0 - InitPool:              Create stake pool for a slab, LP mint, vault
//!   1 - Deposit:               Deposit collateral → vault, receive LP tokens
//!   2 - Withdraw:              Burn LP tokens → withdraw from vault (after cooldown)
//!   3 - FlushToInsurance:      CPI TopUpInsurance — vault → wrapper insurance fund
//!   4 - UpdateConfig:          Admin updates cooldown, caps, etc.
//!   5 - TransferAdmin:         Transfer wrapper slab admin to pool PDA (one-time setup)
//!   6 - AdminSetOracleAuth:    CPI SetOracleAuthority on wrapper (pool PDA signs as admin)
//!   7 - AdminSetRiskThreshold: CPI SetRiskThreshold on wrapper (pool PDA signs as admin)
//!   8 - AdminSetMaintenanceFee: CPI SetMaintenanceFee on wrapper
//!   9 - AdminResolveMarket:    CPI ResolveMarket on wrapper (end-of-epoch)
//!  10 - AdminWithdrawInsurance: CPI WithdrawInsurance → distribute to LP holders
//!  11 - AdminSetInsurancePolicy: CPI SetInsuranceWithdrawPolicy on wrapper

pub mod error;
pub mod instruction;
pub mod math;
pub mod processor;
pub mod state;
pub mod cpi;

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint;
