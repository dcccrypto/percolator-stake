//! PoC + regression for issue #198 — the inline `available` calc in
//! `process_flush_to_insurance` blocked a legitimate flush, AND over-counted the
//! flushable balance.
//!
//! ── The bug ──────────────────────────────────────────────────────────────────
//! `process_flush_to_insurance` computed the flushable balance with a u64
//! left-to-right checked chain (old code at processor.rs:1295-1300):
//!
//!     let available = total_deposited
//!         .checked_sub(total_withdrawn)
//!         .and_then(|v| v.checked_sub(total_flushed))   // <-- underflows when D-W < F
//!         .and_then(|v| v.checked_add(total_returned))
//!         .ok_or(StakeError::Overflow)?;
//!
//! Two defects:
//!  1. `(D - W) - F` underflows whenever `D - W < F` (== total_pool_value() <
//!     total_returned) -> None -> StakeError::Overflow, even though `D - W - F + R`
//!     is positive and tokens are in the vault.
//!  2. `D - W - F + R` over-counts the real vault balance. The #161 last-junior-exit
//!     booking raises `total_returned` by the forfeited loss WITHOUT moving tokens (a
//!     phantom return, recorded in `realized_junior_loss`). So the real vault balance
//!     is `D - W - F + R - realized_junior_loss` == `total_pool_value()`, and
//!     `D - W - F + R` exceeds it by `realized_junior_loss`.
//!
//! ── The fix ──────────────────────────────────────────────────────────────────
//! Use the canonical `StakePool::total_pool_value()` (i128-widened #169; subtracts
//! `realized_junior_loss` #161). For a mode-0 pool (the only mode flush is valid for)
//! fees are 0, so it equals `D - W - F + R - realized_junior_loss` — the exact balance
//! physically in the vault. It is never an over-count, so the admin can never be
//! admitted to flush tokens that aren't there.
//!
//! This test uses `total_pool_value()` (== physical vault) as ground truth.

use bytemuck::Zeroable;
use percolator_stake::state::StakePool;

fn pool() -> StakePool {
    let mut p = StakePool::zeroed();
    p.is_initialized = 1;
    p.set_discriminator();
    p // pool_mode 0 (insurance LP) — the only mode flush is valid for
}

/// VERBATIM reproduction of the OLD buggy inline chain (processor.rs:1295-1300).
/// Returns None exactly when the old code returned `Err(StakeError::Overflow)`.
fn old_inline_available(p: &StakePool) -> Option<u64> {
    p.total_deposited
        .checked_sub(p.total_withdrawn)
        .and_then(|v| v.checked_sub(p.total_flushed))
        .and_then(|v| v.checked_add(p.total_returned))
}

/// The naive reorder that was *also* considered: `D - W + R - F`. It fixes the
/// underflow but NOT the over-count — it equals the real vault balance plus
/// `realized_junior_loss`. Kept here only to demonstrate that divergence.
fn reorder_available(p: &StakePool) -> Option<u64> {
    p.total_deposited
        .checked_sub(p.total_withdrawn)
        .and_then(|v| v.checked_add(p.total_returned))
        .and_then(|v| v.checked_sub(p.total_flushed))
}

/// The IMPLEMENTED fix: `available = pool.total_pool_value()`.
fn fixed_available(p: &StakePool) -> Option<u64> {
    p.total_pool_value()
}

/// Real tokens physically in the vault. The #161 last-junior-exit booking raises
/// `total_returned` by the forfeited loss with NO token movement (recorded in
/// `realized_junior_loss`), so physically returned tokens == returned - realized_junior_loss.
fn physical_vault(p: &StakePool) -> i128 {
    p.total_deposited as i128 - p.total_withdrawn as i128 - p.total_flushed as i128
        + (p.total_returned as i128 - p.realized_junior_loss() as i128)
}

#[test]
fn flush_available_underflows_in_a_reachable_state_with_tokens_present() {
    // Reachable via: deposit 100 -> flush 100 -> ReturnInsurance 50 -> withdraw 30.
    //   D = 100, W = 30, F = 100, R = 50.  (no tranche forfeit -> realized_junior_loss = 0)
    let mut p = pool();
    p.total_deposited = 100;
    p.total_withdrawn = 30;
    p.total_flushed = 100;
    p.total_returned = 50;

    // Ground truth: the vault physically holds value.
    let tpv = p.total_pool_value().expect("tpv is a valid, positive u64");
    assert_eq!(tpv, 20, "the vault physically holds 20 collateral");
    assert_eq!(physical_vault(&p), 20);

    // Underflow precondition: D - W < F  <=>  total_pool_value() < total_returned.
    assert!(p.total_deposited - p.total_withdrawn < p.total_flushed, "D - W < F");
    assert!(tpv < p.total_returned, "equivalently, total_pool_value < total_returned");

    // BUG: the old inline calc underflows at `(D-W) - F` = (70 - 100) -> None,
    // so the old process_flush_to_insurance returned StakeError::Overflow.
    assert_eq!(
        old_inline_available(&p),
        None,
        "old inline calc underflows -> flush wrongly returned Overflow with 20 tokens present"
    );

    // FIX: total_pool_value() reports the true available (20 == physical vault), so a
    // legitimate flush of up to 20 is admitted.
    assert_eq!(fixed_available(&p), Some(20));
    assert_eq!(fixed_available(&p), Some(tpv));
}

#[test]
fn fix_does_not_overcount_flushable_balance_with_realized_junior_loss() {
    // Post-state of a flush(120) + loss spilling into senior + last-junior forfeit(50) +
    // ReturnInsurance(70): D=150, W=0, F=120, R=120, realized_junior_loss=50.
    // (R = 70 physical + 50 phantom from the #161 booking.)
    let mut p = pool();
    p.total_deposited = 150;
    p.total_withdrawn = 0;
    p.total_flushed = 120;
    p.total_returned = 120;
    p.set_realized_junior_loss(50);

    // Real tokens in the vault == total_pool_value == 100 (all of it senior's claim).
    assert_eq!(physical_vault(&p), 100);
    assert_eq!(p.total_pool_value().unwrap(), 100);

    // The naive reorder would report 150 (= physical vault + realized_junior_loss),
    // letting the admin be admitted to flush 50 tokens that are NOT in the vault.
    assert_eq!(reorder_available(&p), Some(150), "reorder over-counts by realized_junior_loss");

    // The implemented fix reports exactly the real balance (100) -> no over-count.
    assert_eq!(fixed_available(&p), Some(100));
    assert!(
        (fixed_available(&p).unwrap() as i128) <= physical_vault(&p),
        "fix can never admit a flush larger than what is physically in the vault"
    );
}

#[test]
fn no_regression_when_no_deficit_and_no_realized_junior_loss() {
    // With D - W >= F and realized_junior_loss == 0, all three formulas agree (common case).
    let mut p = pool();
    p.total_deposited = 1_000_000;
    p.total_withdrawn = 100_000;
    p.total_flushed = 200_000;
    p.total_returned = 50_000;
    let expected = p.total_pool_value().unwrap(); // 750_000
    assert_eq!(old_inline_available(&p), Some(expected));
    assert_eq!(reorder_available(&p), Some(expected));
    assert_eq!(fixed_available(&p), Some(expected));
}

#[test]
fn fix_still_blocks_flush_when_vault_truly_empty() {
    // Empty vault -> available 0 -> any positive flush still rejected by `amount > available`.
    let mut p = pool();
    p.total_deposited = 100;
    p.total_withdrawn = 100;
    p.total_flushed = 100;
    p.total_returned = 100;
    assert_eq!(p.total_pool_value().unwrap(), 0);
    assert_eq!(physical_vault(&p), 0);
    assert_eq!(fixed_available(&p), Some(0), "fix reports 0 -> any flush still blocked");
}
