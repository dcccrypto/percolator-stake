//! Regression for the two competing insurance-recovery cap fixes (#262 / #270).
//!
//! Both PRs unified `ReturnInsurance` and `RecoverFlushedInsurance` onto a single
//! formula, in OPPOSITE directions, and each kept one live defect:
//!
//!   #262  cap = flushed − returned + realized_junior_loss  -> never converges
//!   #270  cap = flushed − returned                         -> H-1 gate unsatisfiable
//!
//! The deployed v3 program shipped BOTH formulas at once — ReturnInsurance used the
//! first, RecoverFlushedInsurance the second — so the same quantity was capped two
//! different ways (1000 vs 700 for the scenario below).
//!
//! The fix measures against `total_recovered_from_wrapper` (monotonic, bumped only
//! after the tag-57 CPI, bounded by `total_flushed`) and nets out
//! `realized_junior_loss`, which is forfeited capital that must stay in the wrapper.

use percolator_stake::state::StakePool;

/// Mirrors the mutations `process_recover_flushed_insurance` performs on success.
fn recover(p: &mut StakePool, amount: u64) {
    p.total_returned += amount;
    p.total_recovered_from_wrapper += amount;
}

fn seed(flushed: u64, returned: u64, rjl: u64) -> StakePool {
    let mut p: StakePool = bytemuck::Zeroable::zeroed();
    p.set_discriminator();
    p.total_flushed = flushed;
    p.total_returned = returned;
    p.set_realized_junior_loss(rjl);
    p
}

/// #262's defect: the cap must strictly decrease and reach zero.
/// Under `flushed − returned + rjl` it parked at `rjl` forever, and because
/// RecoverFlushedInsurance is permissionless post-burn that is an unbounded drain.
#[test]
fn recover_cap_converges_to_zero() {
    let mut p = seed(1000, 300, 300);
    let mut drawn = 0u64;
    let mut last = u64::MAX;
    for _ in 0..64 {
        let cap = p.wrapper_recoverable();
        assert!(
            cap < last,
            "cap must strictly decrease (got {cap} then {last})"
        );
        last = cap;
        if cap == 0 {
            break;
        }
        recover(&mut p, cap);
        drawn += cap;
    }
    assert_eq!(p.wrapper_recoverable(), 0, "cap must reach zero");
    assert_eq!(
        drawn, 700,
        "must draw exactly flushed − realized_junior_loss"
    );
    assert!(
        p.total_recovered_from_wrapper <= p.total_flushed,
        "must never pull more than was flushed (got {} > {})",
        p.total_recovered_from_wrapper,
        p.total_flushed
    );
}

/// #270's defect (and the deployed code's): after the #161 phantom settlement moves
/// `total_returned`, the H-1 resolve gate could never be satisfied and the market was
/// permanently unresolvable.
#[test]
fn resolve_gate_is_reachable_after_full_recovery() {
    let mut p = seed(1000, 300, 300);
    assert!(!p.wrapper_fully_recovered(), "gate must start closed");
    while p.wrapper_recoverable() > 0 {
        let cap = p.wrapper_recoverable();
        recover(&mut p, cap);
    }
    assert!(p.wrapper_fully_recovered(), "market must become resolvable");
}

/// Recovery must not lift pool value above what senior is owed. The forfeited junior
/// capital stays in the wrapper rather than being pulled back and paid to senior.
#[test]
fn full_recovery_does_not_windfall_senior() {
    // Junior 300 + senior 700 deposited; 300 flushed and fully absorbed by junior,
    // who then exits at a zero payout (phantom `total_returned += 300`).
    let mut p = seed(300, 300, 300);
    p.total_deposited = 1000;
    p.total_withdrawn = 0;
    let before = p.total_pool_value().unwrap();
    assert_eq!(before, 700, "senior principal");

    while p.wrapper_recoverable() > 0 {
        let cap = p.wrapper_recoverable();
        recover(&mut p, cap);
    }

    assert_eq!(
        p.total_pool_value().unwrap(),
        700,
        "recovery must leave senior at principal, not windfall it the forfeited 300"
    );
    assert!(
        p.wrapper_fully_recovered(),
        "and resolution must still be reachable"
    );
}

/// With no forfeited capital the cap is simply the un-recovered flush, and the full
/// amount is recoverable.
#[test]
fn no_junior_loss_recovers_everything() {
    let mut p = seed(1000, 0, 0);
    assert_eq!(p.wrapper_recoverable(), 1000);
    recover(&mut p, 1000);
    assert_eq!(p.wrapper_recoverable(), 0);
    assert!(p.wrapper_fully_recovered());
}

/// A fully-settled or never-flushed pool yields zero, and the gate is open.
#[test]
fn degenerate_pools_are_zero_and_resolvable() {
    assert_eq!(seed(0, 0, 0).wrapper_recoverable(), 0);
    assert!(seed(0, 0, 0).wrapper_fully_recovered());
    // realized_junior_loss exceeding total_flushed must saturate, not underflow.
    let p = seed(100, 100, 500);
    assert_eq!(p.wrapper_recoverable(), 0);
    assert!(p.wrapper_fully_recovered());
}

/// The saturating arithmetic must hold at the extremes.
#[test]
fn saturates_at_u64_bounds() {
    let mut p = seed(u64::MAX, 0, 0);
    p.total_recovered_from_wrapper = u64::MAX;
    assert_eq!(p.wrapper_recoverable(), 0);

    let p = seed(u64::MAX, 0, u64::MAX);
    assert_eq!(p.wrapper_recoverable(), 0);
}
