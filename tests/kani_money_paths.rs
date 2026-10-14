//! Money paths 2026-10-14 (LP-audit item 9): stake S3 sync bound and insurance-unit math.
//! Run ONCE each on final code: `cargo kani --tests -Z stubbing --harness <name>`.
//!
//! The round-1 harnesses `kani_s3_sync_bounded_by_target_and_buffer` and
//! `kani_s3_units_mint_burn_no_dilution` (tests/kani.rs) had NO VERDICT at 1,500 s under CaDiCaL
//! and z3: each re-computed `floor(V * bps / 10_000)` (resp. four u128 divisions) in the harness, so
//! the solver had to prove two different multiplier circuits equal. Split here:
//!  * sync, FULL u64 width: `bps_of` / `bps_of_ceil` replaced by ANY-VALUE recording stubs (every
//!    sync property holds for EVERY target / band / buffer value, so this is a sound
//!    over-approximation and needs no arithmetic); the stubs also pin the wiring (both bps helpers
//!    are called on `V = liquid + deployed` with the right dial). What the three values ARE
//!    (`floor(V*t)`, `floor(V*hy)`, `ceil(V*b)`) is pinned by the REAL-helper harness at u8 V.
//!  * units: the REAL stake functions at u8 operands (one divider each); FULL width comes from the
//!    wrapper side (percolator-prog kani/money: the stake functions are proven EQUAL to the wrapper's
//!    `ins_units_*`, which are proven at full width with their primitives' contracts).
#![cfg(kani)]
use percolator_stake::math::{deployed_value, expected_recover_burn, expected_topup_units, sync_plan, SyncAction};

static mut CALLS: [(u64, u16, u64, bool); 4] = [(0, 0, 0, false); 4];
static mut NCALLS: usize = 0;

fn record(x: u64, bps: u16, ceil: bool) -> u64 {
    let r: u64 = kani::any();
    unsafe {
        let k = NCALLS;
        assert!(k < 4, "sync_plan calls the bps helpers at most 3 times");
        CALLS[k] = (x, bps, r, ceil);
        NCALLS = k + 1;
    }
    r
}
fn bps_of_any(x: u64, bps: u16) -> u64 {
    record(x, bps, false)
}
fn bps_of_ceil_any(x: u64, bps: u16) -> u64 {
    record(x, bps, true)
}

/// I-S4 sync bound at FULL u64 width for EVERY target / hysteresis / buffer value.
#[kani::proof]
#[kani::stub(percolator_stake::math::bps_of, bps_of_any)]
#[kani::stub(percolator_stake::math::bps_of_ceil, bps_of_ceil_any)]
#[kani::solver(z3)]
fn kani_mp_s3_sync_full_width_any_bps() {
    let liquid: u64 = kani::any();
    let deployed: u64 = kani::any();
    let t: u16 = kani::any();
    let b: u16 = kani::any();
    let hy: u16 = kani::any();
    let plan = sync_plan(liquid, deployed, t, b, hy);
    if t > 10_000 || b > 10_000 || hy > 10_000 {
        assert!(plan.is_none(), "out-of-range bps fail closed");
        kani::cover!(true, "COVER: fail-closed dials");
        return;
    }
    let Some(v) = liquid.checked_add(deployed) else {
        assert!(plan.is_none(), "V overflow fails closed");
        kani::cover!(true, "COVER: V overflow");
        return;
    };
    let plan = plan.expect("in-range dials and V always plan");
    let (calls, n) = unsafe { (CALLS, NCALLS) };
    assert!(n == 3, "target, band and buffer each computed once");
    // wiring: target = bps_of(V, t), h = bps_of(V, hy), buffer = bps_of_ceil(V, b)
    assert!(calls[0].0 == v && calls[0].1 == t && !calls[0].3, "target from V and the target dial");
    assert!(calls[1].0 == v && calls[1].1 == hy && !calls[1].3, "band from V and the hysteresis dial");
    assert!(calls[2].0 == v && calls[2].1 == b && calls[2].3, "buffer = CEIL of V and the buffer dial");
    let (target, h, buffer) = (calls[0].2 as u128, calls[1].2 as u128, calls[2].2 as u128);
    let (l, d) = (liquid as u128, deployed as u128);
    match plan {
        SyncAction::TopUp(a) => {
            let a = a as u128;
            assert!(a > 0);
            assert!(d + h < target, "only below the band");
            assert!(d + a <= target, "never above the target");
            assert!(a <= l && l - a >= buffer, "never below the liquid buffer");
            kani::cover!(d + a == target, "COVER: top-up to the target");
            kani::cover!(d + a < target && l - a == buffer, "COVER: top-up clipped by the buffer");
        }
        SyncAction::Recover(r) => {
            let r = r as u128;
            assert!(d > target + h, "only above the band");
            assert!(r <= d && d - r == target, "lands exactly on the target");
            kani::cover!(r > 0 && h > 0, "COVER: recovery with a hysteresis band");
        }
        SyncAction::None => {
            let in_band = d + h >= target && d <= target + h;
            let no_spare = d + h < target && l <= buffer;
            assert!(in_band || no_spare, "None only inside the band or with no spare liquidity");
            kani::cover!(in_band && v > 0, "COVER: inside the band");
            kani::cover!(no_spare && target > 0, "COVER: below target, buffer exhausted");
        }
    }
}

/// I-S4 with the REAL `bps_of` / `bps_of_ceil` (the round-1 statement verbatim, plus the exact
/// values of target / band / buffer), liquid and deployed narrowed to u8, every u16 dial. This
/// pins what the stubbed values above ARE; the helpers' bodies (`(x as u128 * bps) / 10_000`,
/// `div_ceil`) are width-independent (paper lift to u64: the u128 product < 2^78 never overflows).
#[kani::proof]
#[kani::solver(kissat)]
fn kani_mp_s3_sync_u8_real_helpers() {
    let liquid: u8 = kani::any();
    let deployed: u8 = kani::any();
    let t: u16 = kani::any();
    let b: u16 = kani::any();
    let hy: u16 = kani::any();
    let (l, d) = (liquid as u64, deployed as u64);
    let plan = sync_plan(l, d, t, b, hy);
    if t > 10_000 || b > 10_000 || hy > 10_000 {
        assert!(plan.is_none(), "out-of-range bps fail closed");
        return;
    }
    let v = (l + d) as u128;
    let target = v * t as u128 / 10_000;
    let h = v * hy as u128 / 10_000;
    let buffer = (v * b as u128).div_ceil(10_000);
    let (l, d) = (l as u128, d as u128);
    match plan.expect("in-range bps always plan") {
        SyncAction::TopUp(a) => {
            let a = a as u128;
            assert!(a > 0 && d + h < target && d + a <= target);
            assert!(a <= l && l - a >= buffer, "never below the buffer");
            assert!(a == (target - d).min(l - buffer), "tops up exactly min(room, spare)");
            kani::cover!(d + a == target, "COVER: top-up to the target");
            kani::cover!(d + a < target && l - a == buffer, "COVER: top-up clipped by the buffer");
        }
        SyncAction::Recover(r) => {
            let r = r as u128;
            assert!(d > target + h && r <= d && d - r == target);
            kani::cover!(r > 0 && h > 0, "COVER: recovery with a hysteresis band");
        }
        SyncAction::None => {
            let in_band = d + h >= target && d <= target + h;
            let no_spare = d + h < target && l <= buffer;
            assert!(in_band || no_spare);
            kani::cover!(in_band && v > 0, "COVER: inside the band");
            kani::cover!(no_spare && target > 0, "COVER: below target, buffer exhausted");
        }
    }
}

/// Stake `expected_topup_units` on the REAL function, u8 operands: genesis / reset arms 1:1, else
/// exact floor `m*I <= a*U < m*I + I` = (expanded) incumbents not diluted / new units worth <= paid.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_mp_s3_topup_units_floor_u8() {
    let a = kani::any::<u8>() as u64;
    let u = kani::any::<u8>() as u128;
    let i = kani::any::<u8>() as u128;
    let m = expected_topup_units(a, u, i);
    if u == 0 || i == 0 {
        assert!(m == Some(a as u128), "genesis / after reset: 1:1");
        kani::cover!(u > 0 && i == 0 && a > 0, "COVER: reset arm");
        return;
    }
    let m = m.unwrap();
    let p = a as u128 * u;
    assert!(m * i <= p && p < m * i + i, "exact floor of a*U/I");
    kani::cover!(m > 0 && p % i != 0, "COVER: mint with rounding dust");
    kani::cover!(m > 0 && p % i == 0, "COVER: exact mint");
}

/// Stake `expected_recover_burn` on the REAL function, u8 operands: refusals exact, else exact
/// ceil `b*I >= r*U > (b-1)*I` = (expanded) burned units worth >= paid out, stayers not diluted.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_mp_s3_recover_burn_ceil_u8() {
    let r = kani::any::<u8>() as u64;
    let u = kani::any::<u8>() as u128;
    let i = kani::any::<u8>() as u128;
    let b = expected_recover_burn(r, u, i);
    if u == 0 || i == 0 || r as u128 > i {
        assert!(b.is_none(), "nothing withdrawable / beyond the free insurance refused");
        kani::cover!(u > 0 && i > 0, "COVER: beyond the free insurance");
        return;
    }
    let b = b.unwrap();
    let p = r as u128 * u;
    assert!(b * i >= p, "burned units worth at least the payout");
    assert!(b == 0 || (b - 1) * i < p, "exact ceil: one unit less would not cover it");
    kani::cover!(b > 0 && p % i != 0, "COVER: burn rounded up");
    kani::cover!(b > 0 && p % i == 0, "COVER: exact burn");
}

/// Stake `deployed_value` on the REAL function, u8 operands: exact floor, never above the fund for
/// `Us <= U` (range fact), refusal of `Us > U`.
#[kani::proof]
#[kani::solver(cadical)]
fn kani_mp_s3_deployed_value_floor_u8() {
    let us = kani::any::<u8>() as u128;
    let u = kani::any::<u8>() as u128;
    let i = kani::any::<u8>() as u128;
    let v = deployed_value(us, u, i);
    if u == 0 {
        assert!(v == Some(0));
        return;
    }
    if us > u {
        assert!(v.is_none());
        kani::cover!(true, "COVER: more units than exist refused");
        return;
    }
    let v = v.unwrap() as u128;
    let p = us * i;
    assert!(v * u <= p && p < v * u + u, "exact floor of Us*I/U");
    assert!(v <= i, "the stake's units are never worth more than the whole fund");
    kani::cover!(v > 0 && v < i && p % u != 0, "COVER: partial holding, floored");
    kani::cover!(us == u && v == i && i > 0, "COVER: whole ledger = whole fund");
}

/// Losses are pro rata: a lower fund reading never raises the stake value (REAL function, called
/// twice, u8 operands).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_mp_s3_deployed_value_loss_monotone_u8() {
    let us = kani::any::<u8>() as u128;
    let u = kani::any::<u8>() as u128;
    let i = kani::any::<u8>() as u128;
    let i2 = kani::any::<u8>() as u128;
    kani::assume(us <= u && i2 <= i);
    let v = deployed_value(us, u, i).unwrap();
    let v2 = deployed_value(us, u, i2).unwrap();
    assert!(v2 <= v, "a loss never raises the stake value");
    kani::cover!(v2 < v, "COVER: loss lowers the stake value");
    kani::cover!(v2 == v && i2 < i && us > 0, "COVER: loss below one atom of the holding");
}
