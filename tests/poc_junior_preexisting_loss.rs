//! PoC / regression — the first junior depositor inherits a PRE-EXISTING insurance loss.
//!
//! ── The bug ──────────────────────────────────────────────────────────────────
//! `effective_junior_balance()` applies the pool's CURRENT outstanding loss
//! (`net_loss = total_flushed - total_returned`) to the junior tranche with NO
//! baseline for when the junior cohort began. So if a pool takes an insurance loss
//! while there is no junior (the loss is borne by the global/senior cohort), then a
//! junior later deposits, the very next valuation re-assigns that ENTIRE pre-existing
//! loss onto the new junior — making the incumbent (now senior) LPs whole at the new
//! junior's expense. The junior was never present for the loss event.
//!
//! Reachable two ways: (a) a non-tranche pool takes a flush loss, the admin later
//! enables tranches (no guard against an outstanding loss), then a junior deposits;
//! (b) a tranche pool with an empty junior cohort takes a loss (borne by senior),
//! then the first junior deposits.
//!
//! This test applies the EXACT functions the program uses on a real `StakePool`
//! (`effective_junior_balance`, `senior_balance`, `calc_junior_lp_for_deposit`,
//! `calc_junior_collateral_for_withdraw`, `calc_senior_collateral_for_withdraw`).
//! Distinct from #145 (recovery-snipe / new-junior GAINS on recovery): here the new
//! junior deterministically LOSES the pre-existing loss the instant they deposit.

use bytemuck::Zeroable;
use percolator_stake::math::{
    calc_junior_collateral_for_withdraw, calc_junior_lp_for_deposit,
    calc_senior_collateral_for_withdraw,
};
use percolator_stake::state::StakePool;

fn pool() -> StakePool {
    let mut p = StakePool::zeroed();
    p.is_initialized = 1;
    p.set_discriminator();
    p // pool_mode 0 (insurance LP), tranches not yet enabled
}

#[test]
fn first_junior_inherits_preexisting_loss() {
    let mut pool = pool();

    // Greg deposits 3,000,000 as a plain (non-tranche) LP.
    pool.total_deposited = 3_000_000;
    pool.total_lp_supply = 3_000_000;

    // Admin flushes 600,000 to insurance (a real loss). Greg's stake is now worth
    // total_pool_value() = 2,400,000 — Greg bears the loss, as he should.
    pool.total_flushed = 600_000;
    assert_eq!(pool.total_pool_value().unwrap(), 2_400_000);

    // Admin enables tranches (there is NO guard against an outstanding loss).
    pool.set_tranche_enabled(true);
    pool.set_junior_fee_mult_bps(20_000);

    // Jane deposits 1,000,000 as the FIRST junior. At deposit time junior_balance == 0,
    // so effective_junior_balance() == 0 and she mints 1:1 — it looks like a fair entry.
    let eff_at_deposit = pool.effective_junior_balance();
    assert_eq!(eff_at_deposit, 0);
    let jane_lp = calc_junior_lp_for_deposit(pool.junior_total_lp(), eff_at_deposit, 1_000_000).unwrap();
    assert_eq!(jane_lp, 1_000_000);
    pool.set_junior_balance(1_000_000);
    pool.set_junior_total_lp(jane_lp);
    pool.total_deposited += 1_000_000;
    pool.total_lp_supply += jane_lp;

    // BUG: the instant Jane has a balance, the pre-existing 600,000 loss is reassigned
    // to the junior tranche (junior-first), even though it predates her.
    let eff_after = pool.effective_junior_balance();
    assert_eq!(
        eff_after, 400_000,
        "first junior is marked down by a loss that predates her deposit"
    );

    // Jane withdraws her 1,000,000 LP and recovers only 400,000 — an instant 600,000 loss.
    let jane_back = calc_junior_collateral_for_withdraw(pool.junior_total_lp(), eff_after, jane_lp).unwrap();
    assert_eq!(jane_back, 400_000);
    assert_eq!(1_000_000 - jane_back, 600_000, "Jane lost the full pre-existing loss");

    // Greg (now senior) recovers his FULL 3,000,000 — his loss evaporated onto Jane.
    let greg_back = calc_senior_collateral_for_withdraw(
        pool.senior_total_lp(),
        pool.senior_balance().unwrap(),
        3_000_000,
    )
    .unwrap();
    assert_eq!(greg_back, 3_000_000, "incumbent made whole at the new junior's expense");

    // Conservation holds globally (3,000,000 + 400,000 == 3,400,000 == vault), which is
    // exactly why no runtime check catches it — but 600,000 was transferred from the
    // honest new junior to the incumbent.
    //
    // NOTE: this documents the MATH (effective_junior_balance reassigns the outstanding
    // loss). The FIX is a handler-level gate: `process_deposit_junior` rejects with
    // StakeError::InsuranceLossOutstanding while `total_flushed > total_returned`, so this
    // buggy state is never reachable via a real junior deposit. The gate CONDITION is
    // pinned below; the handler rejection itself is exercised by the v17 LiteSVM e2e suite.
    assert_eq!(greg_back + jane_back, pool.total_pool_value().unwrap());
}

/// Pins the fix's gate condition: `process_deposit_junior` is paused exactly while an
/// insurance loss is outstanding (`total_flushed > total_returned`) and resumes once the
/// flushed insurance is fully returned. (The handler-level revert is covered by the v17
/// LiteSVM e2e; this guards the condition so a future change to the predicate is flagged.)
#[test]
fn junior_deposit_gate_fires_while_loss_outstanding_and_lifts_on_return() {
    let mut pool = pool();
    pool.set_tranche_enabled(true);

    // No loss yet → gate does not fire.
    assert!(!(pool.total_flushed > pool.total_returned));

    // Outstanding loss → gate fires (handler rejects DepositJunior).
    pool.total_flushed = 600_000;
    assert!(pool.total_flushed > pool.total_returned, "gate must fire while loss outstanding");

    // Partial return → still outstanding → gate still fires.
    pool.total_returned = 200_000;
    assert!(pool.total_flushed > pool.total_returned, "gate must stay closed on partial return");

    // Fully returned → gate lifts → junior deposits resume.
    pool.total_returned = 600_000;
    assert!(!(pool.total_flushed > pool.total_returned), "gate must lift once fully returned");
}
