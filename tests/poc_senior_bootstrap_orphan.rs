//! Regression test for the senior-tranche bootstrap C9-bypass.
//!
//! ── The regression (in the first cut of the senior sub-pool pricing fix) ───────
//! The senior deposit path special-cased `senior_total_lp() == 0` into an
//! UNCONDITIONAL 1:1 bootstrap (`if senior_lp == 0 { lp_to_mint = amount }`),
//! intending to seed the first senior depositor. But that branch never consulted
//! the orphaned-value (C9) guard that the global/junior paths use. The exact C9
//! state — all LP withdrawn (`total_lp_supply == 0`) after insurance was returned
//! (`total_returned > 0`, so `total_pool_value() > 0`) — yields `senior_total_lp()
//! == 0` *with* `senior_balance() > 0`. In a tranche pool that routed into the
//! unguarded bootstrap, so a 1-token deposit minted 1 senior LP against the whole
//! orphaned balance and redeemed it: direct theft of returned insurance.
//!
//! (On the merged code this was additionally gated by the `market_resolved` deposit
//! check, making it latent rather than live; this guard removes the dependence on
//! that single unrelated control and restores the C9 invariant the proofs certify.)
//!
//! ── The fix ──────────────────────────────────────────────────────────────────
//! `process_deposit` no longer special-cases `senior_total_lp() == 0`. It ALWAYS
//! calls `calc_senior_lp_for_deposit(senior_total_lp(), senior_balance(), amount)`,
//! which delegates to `calc_lp_for_deposit` and therefore inherits C9: a TRUE first
//! senior (`senior_balance == 0`) mints 1:1, while ORPHANED senior value
//! (`senior_balance > 0` with no senior LP) returns `None` → the deposit is rejected
//! exactly as the non-tranche path rejects it.
//!
//! State/math-level, no Solana runtime — exercises the exact functions the processor
//! calls, mirroring `tests/integration.rs` and `poc_senior_deposit_mispricing.rs`.

use bytemuck::Zeroable;
use percolator_stake::math::{calc_senior_collateral_for_withdraw, calc_senior_lp_for_deposit};
use percolator_stake::state::StakePool;

fn initialized_pool() -> StakePool {
    let mut pool = StakePool::zeroed();
    pool.is_initialized = 1;
    pool.bump = 255;
    pool.vault_authority_bump = 254;
    pool.admin_transferred = 1;
    pool.set_discriminator();
    pool
}

/// A tranche pool holding 500k ORPHANED value with zero LP outstanding.
///
/// Reached by: senior deposited 1M → 500k flushed to insurance → senior fully
/// exited (withdrew the remaining 500k, `total_lp_supply → 0`) → 500k insurance
/// returned post-resolution (`total_returned += 500k`). Net pool value is 500k but
/// no LP token has a claim on it.
fn orphan_pool() -> StakePool {
    let mut pool = initialized_pool();
    pool.set_tranche_enabled(true);
    pool.total_deposited = 1_000_000;
    pool.total_withdrawn = 500_000;
    pool.total_flushed = 500_000;
    pool.total_returned = 500_000;
    // total_lp_supply / junior_balance / junior_total_lp stay 0 (zeroed defaults).
    pool
}

#[test]
fn orphan_state_is_well_formed() {
    let pool = orphan_pool();
    assert_eq!(pool.total_lp_supply, 0, "all LP exited");
    assert_eq!(pool.senior_total_lp(), 0, "no senior LP");
    assert_eq!(pool.effective_junior_balance(), 0, "no junior; net_loss == 0");
    assert_eq!(pool.total_pool_value().unwrap(), 500_000, "orphaned value present");
    assert_eq!(
        pool.senior_balance().unwrap(),
        500_000,
        "senior_total_lp == 0 while senior_balance > 0 — the orphan signature"
    );
}

#[test]
fn unconditional_bootstrap_was_a_c9_bypass() {
    // Documents the regression: the OLD `if senior_lp == 0 { amount }` bootstrap.
    let mut pool = orphan_pool();
    let attacker_dep = 1u64;

    // OLD behavior: seed 1:1 regardless of the 500k orphan sitting in the pool.
    let minted_lp = attacker_dep;
    pool.total_deposited += attacker_dep;
    pool.total_lp_supply += minted_lp;

    // Attacker is now the SOLE senior LP, valued against the whole senior sub-pool.
    let coll = calc_senior_collateral_for_withdraw(
        pool.senior_total_lp(),
        pool.senior_balance().unwrap(),
        minted_lp,
    )
    .expect("senior withdraw");

    assert_eq!(coll, 500_001, "redeems the orphan plus the 1-token deposit");
    assert_eq!(
        coll - attacker_dep,
        500_000,
        "REGRESSION: a 1-token deposit drains the entire orphaned balance"
    );
}

#[test]
fn c9_guard_rejects_senior_deposit_into_orphan() {
    // FIX: process_deposit now ALWAYS routes through calc_senior_lp_for_deposit,
    // which returns None for the orphan state — the deposit is rejected (Overflow).
    let pool = orphan_pool();

    assert_eq!(
        calc_senior_lp_for_deposit(pool.senior_total_lp(), pool.senior_balance().unwrap(), 1),
        None,
        "FIX: dust deposit into an orphan must be rejected (C9), not bootstrapped 1:1"
    );
    // It is the STATE that is blocked, not a size threshold — any amount is rejected.
    assert_eq!(
        calc_senior_lp_for_deposit(pool.senior_total_lp(), pool.senior_balance().unwrap(), 1_000_000),
        None,
        "FIX: a large deposit into an orphan is rejected too"
    );
}

#[test]
fn first_senior_deposit_into_empty_pool_mints_1_to_1() {
    // No-brick guard: a TRUE first senior (empty pool, senior_balance == 0) must
    // still mint 1:1 — the C9 guard only fires when senior_balance > 0.
    let mut pool = initialized_pool();
    pool.set_tranche_enabled(true);
    assert_eq!(pool.senior_total_lp(), 0);
    assert_eq!(pool.senior_balance().unwrap(), 0);

    let lp = calc_senior_lp_for_deposit(pool.senior_total_lp(), pool.senior_balance().unwrap(), 750_000)
        .expect("FIX: true first senior into an empty pool must succeed");
    assert_eq!(lp, 750_000, "true first senior mints 1:1");
}

#[test]
fn first_senior_after_junior_only_mints_1_to_1() {
    // No-brick guard: junior deposited first, no senior yet. In mode 0 (and mode 1,
    // where junior captures 100% of fees) this leaves senior_balance == 0, so the
    // first senior still mints 1:1 — NOT rejected, NOT bypassed.
    let mut pool = initialized_pool();
    pool.set_tranche_enabled(true);
    pool.set_junior_balance(1_000_000);
    pool.set_junior_total_lp(1_000_000);
    pool.total_deposited = 1_000_000;
    pool.total_lp_supply = 1_000_000;
    assert_eq!(pool.senior_total_lp(), 0);
    assert_eq!(
        pool.senior_balance().unwrap(),
        0,
        "junior-first leaves senior_balance == 0 (not an orphan)"
    );

    let lp = calc_senior_lp_for_deposit(pool.senior_total_lp(), pool.senior_balance().unwrap(), 500_000)
        .expect("FIX: first senior after junior-only must succeed");
    assert_eq!(lp, 500_000, "first senior mints 1:1");
}

#[test]
fn junior_only_with_partial_loss_first_senior_not_bricked() {
    // The subtle case: a junior-only pool that took a loss WITH an intervening junior
    // withdrawal, then a partial recovery. Because no senior ever deposited,
    // gross_senior = (total_deposited - total_withdrawn) - junior_balance stays 0, so
    // the junior absorbs 100% of net_loss (senior_loss == 0) and senior_balance stays
    // exactly 0 throughout. The first senior therefore still mints 1:1 — NOT rejected.
    // (And even if some exotic state produced a phantom senior_balance > 0 with no
    // senior LP, the fix would REJECT it — fail-safe, never a mint-orphan/theft.)
    //
    // State: junior deposited 1M, withdrew 200k (1:1, pre-loss), then 300k flushed,
    // then 100k returned -> net_loss = 200k (<= junior_balance 800k).
    let mut pool = initialized_pool();
    pool.set_tranche_enabled(true);
    pool.set_junior_balance(800_000); // 1M deposited - 200k withdrawn
    pool.set_junior_total_lp(800_000);
    pool.total_deposited = 1_000_000;
    pool.total_withdrawn = 200_000;
    pool.total_flushed = 300_000;
    pool.total_returned = 100_000;
    pool.total_lp_supply = 800_000; // all junior

    assert_eq!(pool.senior_total_lp(), 0);
    assert_eq!(pool.effective_junior_balance(), 600_000, "junior absorbs all net_loss");
    assert_eq!(pool.total_pool_value().unwrap(), 600_000);
    assert_eq!(
        pool.senior_balance().unwrap(),
        0,
        "junior-only (gross_senior == 0) keeps senior_balance == 0 through loss + recovery"
    );

    let lp = calc_senior_lp_for_deposit(pool.senior_total_lp(), pool.senior_balance().unwrap(), 400_000)
        .expect("FIX: first senior into a junior-only-post-loss pool must succeed 1:1");
    assert_eq!(lp, 400_000, "first senior mints 1:1 (not bricked by a phantom senior_balance)");
}
