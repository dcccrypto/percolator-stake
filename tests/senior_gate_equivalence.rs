//! A-H3 — proves the new senior gate is a SAFE REPLACEMENT for the #159 predicate.
//!
//! `process_deposit`'s tranche arm previously gated on
//! `net_loss > junior_balance()` (#159, `682fb4b`). A-H3 replaces that with
//! `senior_recovery_exposure() > 0`. Replacing a shipped security gate needs a
//! stronger argument than "the suite is still green", because the suite does not
//! cover the states where the two predicates differ. These two tests characterise
//! the difference exhaustively over a bounded grid, and pin both halves of the
//! claim that makes the replacement safe:
//!
//!   1. **Nothing is unblocked.** There is no state in which #159 blocks and the
//!      replacement opens. The new predicate is a strict superset, so no
//!      protection that shipped in #159 is lost.
//!
//!   2. **Existing pools are unaffected.** On any pool that has never taken an
//!      unmatched `ReturnInsurance`, the two predicates are not merely similar —
//!      they are IDENTICAL. Proof: `total_returned == total_recovered_from_wrapper
//!      + admin_returns + realized_junior_loss`, so with `admin_returns == 0` we
//!      get `wrapper_recoverable() == net_loss`, hence `above == 0` and
//!      `below == max(net_loss - junior_balance, 0)`, hence
//!      `exposure > 0  <=>  net_loss > junior_balance` — exactly #159.
//!
//! Together these say the entire behavioural delta is `above == admin_returns`:
//! the gate now also closes when an admin has paid into the vault while the
//! wrapper still holds the flush, which is precisely the A-H3 state. Every other
//! pool sees byte-identical behaviour.
//!
//! If someone later "simplifies" `senior_recovery_exposure()` — most temptingly
//! back to the blunt `wrapper_recoverable() > 0` that the non-tranche arm uses —
//! `equivalent_when_no_unmatched_return` fails, because that form over-blocks the
//! junior-absorbed case.

use bytemuck::Zeroable;
use percolator_stake::state::StakePool;

/// Build a pool whose counters satisfy the accounting identity
/// `total_returned = total_recovered_from_wrapper + admin_returns + realized_junior_loss`.
fn pool_with(
    flushed: u64,
    recovered_from_wrapper: u64,
    realized_junior_loss: u64,
    admin_returns: u64,
    junior_balance: u64,
) -> StakePool {
    let mut p = StakePool::zeroed();
    p.set_discriminator();
    // Large enough that total_pool_value() never underflows for the grid below.
    p.total_deposited = 10_000_000;
    p.total_flushed = flushed;
    p.total_returned = recovered_from_wrapper + admin_returns + realized_junior_loss;
    p.total_recovered_from_wrapper = recovered_from_wrapper;
    p.set_realized_junior_loss(realized_junior_loss);
    p.set_junior_balance(junior_balance);
    p.set_tranche_enabled(true);
    p
}

/// The predicate this change replaces (#159, `processor.rs` tranche arm).
fn old_gate_blocks(p: &StakePool) -> bool {
    p.total_flushed.saturating_sub(p.total_returned) > p.junior_balance()
}

/// The predicate this change introduces.
fn new_gate_blocks(p: &StakePool) -> bool {
    p.senior_recovery_exposure() > 0
}

const STEP: u64 = 7_000;
const MAX: u64 = 70_000;

/// No state exists where #159 blocks and the replacement opens.
#[test]
fn replacement_never_unblocks_what_159_blocked() {
    let mut checked = 0u64;
    let mut regressions = 0u64;

    for flushed in (0..=MAX).step_by(STEP as usize) {
        for rfw in (0..=flushed).step_by(STEP as usize) {
            for rjl in (0..=(flushed - rfw)).step_by(STEP as usize) {
                for admin_returns in (0..=MAX).step_by(STEP as usize) {
                    for jb in (0..=MAX).step_by(STEP as usize) {
                        let p = pool_with(flushed, rfw, rjl, admin_returns, jb);
                        checked += 1;
                        if old_gate_blocks(&p) && !new_gate_blocks(&p) {
                            regressions += 1;
                        }
                    }
                }
            }
        }
    }

    assert!(checked > 30_000, "grid collapsed: only {checked} states");
    assert_eq!(
        regressions, 0,
        "REGRESSION: {regressions}/{checked} states are blocked by #159 but opened by the \
         replacement — shipped protection would be lost"
    );
}

/// On any pool with no unmatched `ReturnInsurance`, the two predicates agree exactly.
/// This is what makes the change a no-op for every pool that has not hit the A-H3 state.
#[test]
fn equivalent_when_no_unmatched_return() {
    let mut checked = 0u64;
    let mut disagreements = 0u64;

    for flushed in (0..=MAX).step_by(STEP as usize) {
        for rfw in (0..=flushed).step_by(STEP as usize) {
            for rjl in (0..=(flushed - rfw)).step_by(STEP as usize) {
                for jb in (0..=MAX).step_by(STEP as usize) {
                    // admin_returns == 0: the wrapper is the only source of returns.
                    let p = pool_with(flushed, rfw, rjl, 0, jb);
                    checked += 1;
                    if old_gate_blocks(&p) != new_gate_blocks(&p) {
                        disagreements += 1;
                    }
                }
            }
        }
    }

    assert!(checked > 1_000, "grid collapsed: only {checked} states");
    assert_eq!(
        disagreements, 0,
        "{disagreements}/{checked} states change behaviour on a pool that never took an \
         unmatched ReturnInsurance — the replacement must be a no-op for those pools"
    );
}

/// The whole behavioural delta is the unmatched admin return, and nothing else.
/// Pins the `above` term's meaning so a refactor cannot quietly widen it.
#[test]
fn the_only_delta_is_the_unmatched_admin_return() {
    // Junior-absorbed loss (net_loss <= junior_balance): #159 opens, and so must the
    // replacement — this is the liveness case the blunt `wrapper_recoverable() > 0`
    // form gets wrong.
    let absorbed = pool_with(30_000, 0, 0, 0, 50_000);
    assert!(!old_gate_blocks(&absorbed));
    assert!(
        !new_gate_blocks(&absorbed),
        "junior-absorbed loss must NOT gate senior deposits: a recovery raises \
         effective_junior_balance() by the same amount it raises total_pool_value(), so \
         senior_balance() is invariant and there is nothing to snipe"
    );
    assert_eq!(absorbed.senior_recovery_exposure(), 0);

    // Same pool, plus an unmatched admin ReturnInsurance: now a recovery WOULD raise
    // senior_balance(), and only the replacement catches it.
    let with_return = pool_with(30_000, 0, 0, 30_000, 50_000);
    assert!(
        !old_gate_blocks(&with_return),
        "#159 reads net_loss == 0 here and opens — this is the A-H3 hole"
    );
    assert!(new_gate_blocks(&with_return), "replacement must close it");
    assert_eq!(
        with_return.senior_recovery_exposure(),
        30_000,
        "exposure is exactly the unmatched admin return"
    );

    // Loss spilled past junior: both gates block (the #159 case, preserved).
    let spilled = pool_with(60_000, 0, 0, 0, 10_000);
    assert!(old_gate_blocks(&spilled));
    assert!(new_gate_blocks(&spilled));
}
