//! PoC / regression — HWM floor + an insurance loss freezes ALL withdrawals until epoch.
//!
//! ── The bug ──────────────────────────────────────────────────────────────────
//! The high-water-mark (HWM) withdrawal floor blocks withdrawals that would drop TVL
//! below `epoch_high_water_tvl * hwm_floor_bps / 10000` (anti-drain protection).
//! `refresh_hwm` is called on deposit/withdraw/deposit_junior and, within an epoch,
//! ONLY RAISES the mark (never lowers it). `process_flush_to_insurance` — which
//! LOWERS TVL (an insurance loss) — does NOT call `refresh_hwm` at all.
//!
//! So after a flush loss, `epoch_high_water_tvl` stays pegged at the pre-loss peak
//! while actual TVL has dropped. If the loss pushes TVL below the floor, the next
//! withdrawal check blocks EVERY withdrawal (even a 1-token / zero-size one), because
//! current TVL is already under the stale floor. LPs are frozen out of a pool that
//! just LOST money, until the Solana epoch rolls over (refresh_hwm resets the mark to
//! current TVL on a new epoch) or the admin disables HWM / returns the insurance.
//!
//! Uses the real `StakePool::refresh_hwm` + `math::hwm_withdrawal_allowed`.

use bytemuck::Zeroable;
use percolator_stake::math::hwm_withdrawal_allowed;
use percolator_stake::state::StakePool;

fn hwm_pool() -> StakePool {
    let mut p = StakePool::zeroed();
    p.is_initialized = 1;
    p.set_discriminator();
    p.set_hwm_enabled(true);
    p.set_hwm_floor_bps(5000); // 50% floor
    p
}

#[test]
fn hwm_freeze_after_loss_blocks_all_withdrawals() {
    let mut pool = hwm_pool();

    // Peak TVL 1,000,000 in epoch 5 → mark ratchets to 1,000,000.
    pool.total_deposited = 1_000_000;
    pool.refresh_hwm(5, 1_000_000);
    assert_eq!(pool.epoch_high_water_tvl(), 1_000_000);

    // Admin flushes 600,000 to insurance (a real loss). TVL drops to 400,000.
    // FlushToInsurance does NOT call refresh_hwm, so the mark is untouched.
    pool.total_flushed = 600_000;
    assert_eq!(pool.total_pool_value().unwrap(), 400_000);

    // A withdraw calls refresh_hwm(5, 400_000): same epoch, 400k < mark, so the mark is
    // NOT lowered (it only raises). Floor stays 50% of the stale 1,000,000 peak = 500,000.
    let mark = pool.refresh_hwm(5, 400_000);
    assert_eq!(mark, 1_000_000, "mark stays pegged to the pre-loss peak (the bug)");

    // Current TVL (400,000) is already below the 500,000 floor, so EVERY withdrawal —
    // even a zero-size one (post_tvl == current TVL) — is blocked.
    assert!(
        !hwm_withdrawal_allowed(400_000, mark, 5000),
        "ALL withdrawals frozen after the loss, until the epoch rolls over"
    );
}

#[test]
fn rebaselining_hwm_on_flush_unfreezes_withdrawals() {
    // Fix direction: a flush (a legitimate loss, not a drain) lowers the high-water mark
    // alongside TVL, so the floor tracks the loss rather than freezing exits. The
    // anti-drain protection (floor vs. the loss-adjusted mark) stays intact.
    let mut pool = hwm_pool();
    pool.total_deposited = 1_000_000;
    pool.refresh_hwm(5, 1_000_000);

    // Flush 600,000 AND lower the mark by the flushed amount (the fix).
    pool.total_flushed = 600_000;
    pool.set_epoch_high_water_tvl(pool.epoch_high_water_tvl().saturating_sub(600_000)); // -> 400,000

    let mark = pool.refresh_hwm(5, 400_000);
    assert_eq!(mark, 400_000, "mark tracks the legitimate loss");

    // Floor = 50% of 400,000 = 200,000. Withdrawals down to the loss-adjusted floor resume.
    assert!(hwm_withdrawal_allowed(400_000, mark, 5000), "withdrawals resume after re-baseline");
    assert!(hwm_withdrawal_allowed(200_000, mark, 5000), "allowed down to the loss-adjusted floor");
    assert!(!hwm_withdrawal_allowed(199_999, mark, 5000), "floor still enforced — anti-drain intact");
}

/// The crux that picks "lower the mark by the flushed amount" over "reset the mark to
/// post-flush TVL": a flush must reduce the protected peak by the LOSS only, never forgive
/// prior intra-epoch withdrawal drain. Peak 1,000,000; withdraw down to 800,000 (mark stays
/// 1,000,000 — withdrawals never lower it); then flush 600,000 → TVL 200,000.
///   lower-by-amount: mark 1,000,000 − 600,000 = 400,000, floor 200,000 → TVL already at
///   floor, no further withdrawal headroom (the prior 200,000 drain is "remembered").
///   reset-to-TVL (rejected): mark 200,000, floor 100,000 → re-opens 100,000 of post-loss
///   drain — exactly the bank-run the HWM exists to prevent.
#[test]
fn lower_by_amount_does_not_forgive_prior_drain() {
    let mut pool = hwm_pool();
    pool.total_deposited = 1_000_000;
    pool.refresh_hwm(5, 1_000_000); // mark 1,000,000

    // Withdrawals bring TVL to 800,000; the mark does NOT move (refresh only raises).
    pool.total_withdrawn = 200_000;
    let mark_after_withdraw = pool.refresh_hwm(5, 800_000);
    assert_eq!(mark_after_withdraw, 1_000_000, "withdrawals never lower the mark");

    // Flush 600,000 → TVL 200,000. The handler lowers the mark by the flushed amount.
    pool.total_flushed = 600_000;
    assert_eq!(pool.total_pool_value().unwrap(), 200_000);
    pool.set_epoch_high_water_tvl(pool.epoch_high_water_tvl().saturating_sub(600_000)); // -> 400,000
    let mark = pool.refresh_hwm(5, 200_000);
    assert_eq!(mark, 400_000, "lower by the LOSS only — not down to post-flush TVL");

    // Floor = 200,000. Post-flush TVL is already at the floor → no further drain allowed.
    assert!(hwm_withdrawal_allowed(200_000, mark, 5000), "exactly at the loss-adjusted floor");
    assert!(!hwm_withdrawal_allowed(199_999, mark, 5000), "prior drain remembered — no new headroom");
    // reset-to-TVL would have set mark=200,000, floor=100,000, wrongly allowing TVL→100,000.
    assert!(!hwm_withdrawal_allowed(100_000, mark, 5000), "reset-to-TVL would have allowed this — rejected");
}

/// Multiple flushes in an epoch compose: mark = peak − Σ flushed (saturating).
#[test]
fn multiple_flushes_compose() {
    let mut pool = hwm_pool();
    pool.total_deposited = 1_000_000;
    pool.refresh_hwm(5, 1_000_000);
    pool.set_epoch_high_water_tvl(pool.epoch_high_water_tvl().saturating_sub(300_000));
    pool.set_epoch_high_water_tvl(pool.epoch_high_water_tvl().saturating_sub(300_000));
    assert_eq!(pool.epoch_high_water_tvl(), 400_000, "two 300k flushes == one 600k flush");
}

/// A flush whose amount exceeds the (stale/zero) mark saturates to 0 — floor 0, no freeze.
#[test]
fn flush_exceeding_mark_saturates_to_zero() {
    let mut pool = hwm_pool();
    pool.set_epoch_high_water_tvl(100_000);
    pool.set_epoch_high_water_tvl(pool.epoch_high_water_tvl().saturating_sub(200_000));
    assert_eq!(pool.epoch_high_water_tvl(), 0, "saturates, no underflow/panic");
    assert!(hwm_withdrawal_allowed(0, 0, 5000), "floor 0 → no restriction");
}
