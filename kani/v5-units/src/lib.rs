//! ST-3 cross-crate proofs (design rev 2 R2.3 / rev 2.1): the stake program's v5 expected-units
//! helpers equal the wrapper's insurance-unit ledger functions. Every module below is the
//! PRODUCTION source file, path-included; only `shim_consts` is local (pinned by tests).
#![allow(dead_code, unused_imports)]

#[path = "shim_consts.rs"]
mod shim_consts;

/// Stake parent-crate item read by `math.rs` (`crate::state::MINIMUM_LIQUIDITY`).
pub mod state {
    pub use crate::shim_consts::MINIMUM_LIQUIDITY;
}
/// Wrapper parent-crate items read by `p4_rescue_ins.rs`.
pub mod constants {
    pub use crate::shim_consts::G9_ALLOWLIST_TIMELOCK_SLOTS;
}
pub mod oracle_v16 {
    pub use crate::shim_consts::{CL_OFF_FEED_OWNER, SB_OFF_FEED_AUTHORITY};
}

#[path = "../../../src/math.rs"]
pub mod math;

#[path = "../../../../percolator-prog/src/vault_lp_v18.rs"]
pub mod vault_lp_v18;
#[path = "../../../../percolator-prog/src/growth_v19.rs"]
pub mod growth_v19;
#[path = "../../../../percolator-prog/src/p4_rescue_ins.rs"]
pub mod p4_rescue_ins;

#[cfg(kani)]
mod proofs;
