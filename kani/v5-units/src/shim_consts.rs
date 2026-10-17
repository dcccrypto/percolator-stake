// The four constants the path-included production files read from their parent crates.
// Pinned by ordinary cargo tests that include! this file and compare with the real values:
// stake `tests/kani_shim_pin.rs` (MINIMUM_LIQUIDITY); the wrapper-side pin of the other three
// is a wrapper test (owed by the wrapper proof commit).
pub const MINIMUM_LIQUIDITY: u64 = 1_000;
pub const G9_ALLOWLIST_TIMELOCK_SLOTS: u64 = 216_000;
pub const CL_OFF_FEED_OWNER: usize = 10;
pub const SB_OFF_FEED_AUTHORITY: usize = 8 + 2_048;
