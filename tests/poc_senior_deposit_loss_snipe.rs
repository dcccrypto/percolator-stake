//! PoC — Senior-deposit recovery-snipe (the senior half of #145, left open by #150).
//!
//! ── The bug ──────────────────────────────────────────────────────────────────
//! #150 paused JUNIOR deposits while an insurance loss is outstanding
//! (total_flushed > total_returned), closing the junior side of the recovery-snipe
//! described in #145. But #145 explicitly noted "senior is the same once a loss
//! spills past junior" — and the SENIOR deposit path (process_deposit, tranche
//! branch) was never gated.
//!
//! When a flushed loss Φ EXCEEDS the junior balance J, junior is wiped and the
//! senior sub-pool is marked down by Φ − J (distribute_loss: senior_loss > 0 iff
//! net_loss > junior_balance). senior_balance() is depressed during the open-loss
//! window. A late senior depositor mints cheap against the depressed senior_balance,
//! then — once the admin returns the insurance — redeems at the restored price,
//! capturing a pro-rata slice of the recovery from the incumbent seniors who
//! actually bore the loss. Conservation-exact, unprivileged value transfer.
//!
//! Uses the real calc_senior_lp_for_deposit / calc_senior_collateral_for_withdraw
//! + StakePool::senior_balance / effective_junior_balance / total_pool_value.

use bytemuck::Zeroable;
use percolator_stake::math::{
    calc_junior_collateral_for_withdraw, calc_senior_collateral_for_withdraw,
    calc_senior_lp_for_deposit,
};
use percolator_stake::state::StakePool;

fn tranche_pool() -> StakePool {
    let mut p = StakePool::zeroed();
    p.is_initialized = 1;
    p.set_discriminator();
    p.set_tranche_enabled(true);
    p
}

/// senior is marked down (the snipe is live) iff net_loss > junior_balance.
fn senior_marked_down(p: &StakePool) -> bool {
    p.total_flushed.saturating_sub(p.total_returned) > p.junior_balance()
}

#[test]
fn senior_deposit_during_loss_snipes_recovery() {
    let mut pool = tranche_pool();

    // Incumbent senior Greg deposits 900k; junior Jane deposits 100k.
    pool.total_deposited = 1_000_000;
    pool.total_lp_supply = 1_000_000;
    pool.set_junior_balance(100_000);
    pool.set_junior_total_lp(100_000);
    assert_eq!(pool.senior_total_lp(), 900_000);
    assert_eq!(pool.senior_balance().unwrap(), 900_000);

    // Admin flushes 600k (> junior 100k): junior wiped, senior marked down by 500k.
    pool.total_flushed = 600_000;
    assert_eq!(pool.effective_junior_balance(), 0);
    assert_eq!(pool.total_pool_value().unwrap(), 400_000);
    assert_eq!(pool.senior_balance().unwrap(), 400_000, "senior depressed during the loss");
    assert!(senior_marked_down(&pool));

    // Eve deposits 400k senior at the depressed price (UNGATED today).
    let eve_lp =
        calc_senior_lp_for_deposit(pool.senior_total_lp(), pool.senior_balance().unwrap(), 400_000)
            .unwrap();
    assert_eq!(eve_lp, 900_000, "400k * 900k / 400k");
    pool.total_deposited += 400_000;
    pool.total_lp_supply += eve_lp;
    assert_eq!(pool.senior_total_lp(), 1_800_000);

    // Admin returns 600k. net_loss -> 0; senior_balance restored over the inflated supply.
    pool.total_returned = 600_000;
    assert_eq!(pool.effective_junior_balance(), 100_000);
    assert_eq!(pool.total_pool_value().unwrap(), 1_400_000);
    assert_eq!(pool.senior_balance().unwrap(), 1_300_000);

    // Eve withdraws her 900k senior LP.
    let eve_out =
        calc_senior_collateral_for_withdraw(pool.senior_total_lp(), pool.senior_balance().unwrap(), eve_lp)
            .unwrap();
    assert_eq!(eve_out, 650_000, "900k * 1.3M / 1.8M");
    assert_eq!(eve_out - 400_000, 250_000, "Eve nets +250k on a 400k deposit she never put at risk");
    pool.total_withdrawn += eve_out;
    pool.total_lp_supply -= eve_lp;

    // Greg (incumbent senior) withdraws his 900k senior LP.
    let greg_out =
        calc_senior_collateral_for_withdraw(pool.senior_total_lp(), pool.senior_balance().unwrap(), 900_000)
            .unwrap();
    assert_eq!(greg_out, 650_000, "deposited 900k, recovers only 650k");
    assert_eq!(900_000 - greg_out, eve_out - 400_000, "Greg's -250k == Eve's +250k (clean transfer)");
    // Without Eve, after the return senior_balance would be 900k over 900k LP -> Greg whole.
}

#[test]
fn gate_blocks_snipe_only_while_senior_marked_down() {
    // The fix gates senior deposits exactly when senior is marked down
    // (net_loss > junior_balance) — and NOT when the loss is fully junior-absorbed.

    // (a) Loss > junior: senior marked down -> gate fires, snipe deposit rejected.
    let mut p = tranche_pool();
    p.total_deposited = 1_000_000;
    p.total_lp_supply = 1_000_000;
    p.set_junior_balance(100_000);
    p.set_junior_total_lp(100_000);
    p.total_flushed = 600_000; // > junior 100k
    assert!(senior_marked_down(&p), "loss spilled past junior -> senior deposits paused");

    // (b) Loss <= junior: senior fully protected (unchanged) -> senior deposits stay OPEN.
    let mut p2 = tranche_pool();
    p2.total_deposited = 1_000_000;
    p2.total_lp_supply = 1_000_000;
    p2.set_junior_balance(100_000);
    p2.set_junior_total_lp(100_000);
    p2.total_flushed = 80_000; // < junior 100k: junior absorbs, senior NOT marked down
    assert_eq!(p2.senior_balance().unwrap(), 900_000, "senior unchanged when loss <= junior");
    assert!(!senior_marked_down(&p2), "no snipe possible -> senior deposits remain allowed");

    // (c) After the insurance is returned, the gate lifts.
    p.total_returned = 600_000;
    assert!(!senior_marked_down(&p), "gate lifts once the loss is recovered");
}

/// The crux that picks the PRECISE gate over both the simple-symmetric gate and a
/// "persisted accumulator": a junior PARTIAL exit during a junior-ABSORBED loss must NOT
/// false-trigger the gate. The senior-balance markdown is a pure function of CURRENT state
/// (senior_loss > 0 IFF net_loss > junior_balance(now)), and the junior-withdraw path
/// decrements raw junior_balance by the loss-ADJUSTED withdrawal amount (not a proportional
/// raw share), so junior_balance stays above net_loss and senior remains undepressed.
#[test]
fn precise_gate_no_false_fire_on_junior_partial_exit() {
    let mut pool = tranche_pool();
    // senior 900k, junior 400k.
    pool.total_deposited = 1_300_000;
    pool.total_lp_supply = 1_300_000;
    pool.set_junior_balance(400_000);
    pool.set_junior_total_lp(400_000);

    // Flush 300k — junior-ABSORBED (300k <= 400k): senior NOT marked down.
    pool.total_flushed = 300_000;
    assert_eq!(pool.effective_junior_balance(), 100_000);
    assert_eq!(pool.senior_balance().unwrap(), 900_000, "senior untouched by a junior-absorbed loss");
    assert!(!senior_marked_down(&pool));

    // A junior burns 390k of 400k LP. Valued against effective_junior (100k):
    // withdrawal_amount = 390k * 100k / 400k = 97_500. Raw junior_balance drops by that.
    let wd = calc_junior_collateral_for_withdraw(400_000, pool.effective_junior_balance(), 390_000).unwrap();
    assert_eq!(wd, 97_500);
    pool.total_withdrawn += wd;
    pool.set_junior_balance(pool.junior_balance() - wd); // 400_000 - 97_500 = 302_500
    pool.set_junior_total_lp(400_000 - 390_000); // 10_000
    assert_eq!(pool.junior_balance(), 302_500);

    // net_loss (300k) is still <= junior_balance (302_500): gate stays OPEN, and senior is
    // STILL undepressed — so a senior deposit here is fair and must be allowed.
    assert!(!senior_marked_down(&pool), "precise gate does NOT false-fire on junior partial exit");
    assert_eq!(pool.senior_balance().unwrap(), 900_000, "senior still whole after junior's partial exit");
}
