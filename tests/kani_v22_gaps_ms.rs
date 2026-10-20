//! v22kani 2026-10-20, agent MS: stake gaps G5 (LP round trip / no dilution) and the S3 rows.
//! cfg(kani) only; every harness calls the REAL `percolator_stake` function.
//!
//! Method (see ~/wt-v22kani-1020/reports/MS.md): the round-trip / no-dilution claims chain two
//! 128-bit variable divisions, which every backend failed on (u8..u64, cadical/kissat/z3). Split:
//!  * STRUCTURAL at FULL production width (here): each money function returns EXACTLY the stated
//!    integer formula (floor / ceil of a u128 product over a u128 divisor), every refusal arm
//!    exact, and the u128 product never overflows. z3 decides these because the harness re-states
//!    the production expression and z3 hash-conses equal words.
//!  * ARITHMETIC over unbounded Int (`kani/int-lemmas/stake_lemmas.py`, z3, not Kani): from those
//!    formulas to the money claims (round trip <= deposit, no dilution, partial junior burn <=
//!    balance, unit mint/burn no dilution).
#![cfg(kani)]

use percolator_stake::math::{
    calc_collateral_for_withdraw, calc_junior_collateral_for_withdraw, calc_lp_for_deposit, calc_junior_lp_for_deposit, calc_senior_collateral_for_withdraw,
    calc_senior_lp_for_deposit, deployed_value, expected_recover_burn, expected_topup_units, sync_plan,
    SyncAction,
};

/// MS-S1: the mint is EXACTLY `floor(d*(S+1)/(V+1))` at full u64 width (global, junior and senior), with the
/// genesis / orphan / empty-value arms exact and the u128 product never overflowing.
#[kani::proof]
#[kani::solver(z3)]
fn ms_s1_mint_exact_floor_full_width() {
    let s: u64 = kani::any();
    let v: u64 = kani::any();
    let d: u64 = kani::any();
    let senior: bool = kani::any();
    let global: bool = kani::any();
    let r = if global {
        calc_lp_for_deposit(s, v, d)
    } else if senior {
        calc_senior_lp_for_deposit(s, v, d)
    } else {
        calc_junior_lp_for_deposit(s, v, d)
    };
    if s == 0 && v == 0 {
        assert!(r == Some(d), "genesis 1:1");
        kani::cover!(d > 0, "COVER: genesis");
        return;
    }
    if s == 0 || v == 0 {
        assert!(r.is_none(), "orphaned value / zero-value pool refused");
        kani::cover!(s == 0, "COVER: orphan refused");
        kani::cover!(v == 0, "COVER: zero value refused");
        return;
    }
    let num = (d as u128).checked_mul(s as u128 + 1);
    assert!(num.is_some(), "the u128 product never overflows at u64 operands");
    let q = (d as u128 * (s as u128 + 1)) / (v as u128 + 1);
    if q <= u64::MAX as u128 {
        assert!(r == Some(q as u64), "mint = floor(d*(S+1)/(V+1))");
        kani::cover!(q > 0 && q < d as u128, "COVER: share price > 1");
        kani::cover!(q == 0 && d > 0, "COVER: dust deposit mints 0");
        kani::cover!(senior && !global && q > d as u128, "COVER: senior, share price < 1");
        kani::cover!(global && q > 0, "COVER: global mint");
    } else {
        assert!(r.is_none(), "mint beyond u64 refused");
        kani::cover!(true, "COVER: mint beyond u64 refused");
    }
}

/// MS-S2: the burn is EXACTLY `floor(lp*(V+1)/(S+1))` at full u64 width; the junior full burn pays
/// exactly the junior balance; over-burn and zero supply refused.
#[kani::proof]
#[kani::solver(z3)]
fn ms_s2_burn_exact_floor_full_width() {
    let s: u64 = kani::any();
    let v: u64 = kani::any();
    let lp: u64 = kani::any();
    let senior_or_global: u8 = kani::any();
    // 0 = junior, 1 = senior, 2 = global (calc_collateral_for_withdraw); senior and global share the formula
    kani::assume(senior_or_global <= 2);
    let senior = senior_or_global != 0;
    let r = match senior_or_global {
        0 => calc_junior_collateral_for_withdraw(s, v, lp),
        1 => calc_senior_collateral_for_withdraw(s, v, lp),
        _ => calc_collateral_for_withdraw(s, v, lp),
    };
    if s == 0 {
        assert!(r.is_none(), "zero supply refused");
        kani::cover!(lp > 0, "COVER: zero supply");
        return;
    }
    if !senior && lp > s {
        assert!(r.is_none(), "junior over-burn refused");
        kani::cover!(true, "COVER: junior over-burn refused");
        return;
    }
    if !senior && lp == s {
        assert!(r == Some(v), "junior full burn pays exactly the junior balance");
        kani::cover!(v > s, "COVER: junior full burn with earned fees");
        return;
    }
    let num = (lp as u128).checked_mul(v as u128 + 1);
    assert!(num.is_some(), "the u128 product never overflows at u64 operands");
    let q = (lp as u128 * (v as u128 + 1)) / (s as u128 + 1);
    if q <= u64::MAX as u128 {
        assert!(r == Some(q as u64), "burn = floor(lp*(V+1)/(S+1))");
        kani::cover!(!senior && q > 0 && lp < s, "COVER: junior partial burn pays");
        kani::cover!(senior_or_global == 1 && q > 0 && lp < s, "COVER: senior partial burn pays");
        kani::cover!(senior_or_global == 2 && q > 0 && lp < s, "COVER: global partial burn pays");
        kani::cover!(senior && lp == s && q < v as u128, "COVER: senior full burn keeps the N7 residual");
    } else {
        assert!(r.is_none(), "payout beyond u64 refused");
        kani::cover!(senior, "COVER: senior over-burn beyond u64 refused");
    }
}

/// MS-S4: insurance-unit mirrors of the wrapper at full width: top-up mint = floor(a*U/I), recovery
/// burn = ceil(r*U/I), stake value = floor(Us*I/U); every refusal arm exact.
#[kani::proof]
#[kani::solver(z3)]
fn ms_s4_units_exact_full_width() {
    let a: u64 = kani::any();
    let u: u128 = kani::any();
    let i: u128 = kani::any();
    // mint
    let m = expected_topup_units(a, u, i);
    if u == 0 || i == 0 {
        assert!(m == Some(a as u128), "genesis / reset 1:1");
    } else {
        match (a as u128).checked_mul(u) {
            Some(p) => {
                assert!(m == Some(p / i), "mint = floor(a*U/I)");
                kani::cover!(p % i != 0 && p / i > 0, "COVER: mint with dust");
            }
            None => {
                assert!(m.is_none(), "mint overflow refused");
                kani::cover!(true, "COVER: mint overflow refused");
            }
        }
    }
    // recovery burn
    let r: u64 = kani::any();
    let b = expected_recover_burn(r, u, i);
    if u == 0 || i == 0 || r as u128 > i {
        assert!(b.is_none(), "nothing withdrawable / beyond the free insurance refused");
        kani::cover!(u > 0 && i > 0 && r as u128 > i, "COVER: beyond the free insurance");
    } else {
        match (r as u128).checked_mul(u) {
            Some(p) => {
                assert!(b == Some(p.div_ceil(i)), "burn = ceil(r*U/I)");
                kani::cover!(p % i != 0, "COVER: burn rounded up");
            }
            None => {
                assert!(b.is_none(), "burn overflow refused");
                kani::cover!(true, "COVER: burn overflow refused");
            }
        }
    }
    // stake value
    let us: u128 = kani::any();
    let dv = deployed_value(us, u, i);
    if u == 0 {
        assert!(dv == Some(0));
    } else if us > u {
        assert!(dv.is_none(), "more units than exist refused");
        kani::cover!(true, "COVER: more units than exist");
    } else {
        match us.checked_mul(i) {
            Some(p) => {
                let q = p / u;
                if q <= u64::MAX as u128 {
                    assert!(dv == Some(q as u64), "value = floor(Us*I/U)");
                    kani::cover!(q > 0 && us < u && p % u != 0, "COVER: partial holding, floored");
                } else {
                    assert!(dv.is_none(), "value beyond u64 refused");
                    kani::cover!(true, "COVER: value beyond u64");
                }
            }
            None => {
                assert!(dv.is_none(), "value overflow refused");
                kani::cover!(true, "COVER: value overflow refused");
            }
        }
    }
}

// ---- S3 sync (I-S4) -------------------------------------------------------------------------

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

/// MS-S5a: verbatim port of `kani_mp_s3_sync_full_width_any_bps` (kani/v22-money-paths-2026-10-14-stake
/// 584392c): I-S4 at FULL u64 width for EVERY target / hysteresis / buffer value (any-value recording
/// stubs of the bps helpers, which also pin the wiring).
#[kani::proof]
#[kani::stub(percolator_stake::math::bps_of, bps_of_any)]
#[kani::stub(percolator_stake::math::bps_of_ceil, bps_of_ceil_any)]
#[kani::solver(z3)]
fn ms_s5a_sync_full_width_any_bps() {
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

/// MS-S5b: round-1 `kani_s3_sync_bounded_by_target_and_buffer` statement on the REAL helpers at FULL
/// u64 liquid / deployed (the round-1 harness was u32 and had no verdict), every u16 dial, plus the
/// exact top-up amount.
#[kani::proof]
#[kani::solver(z3)]
fn ms_s5b_sync_full_width_real_helpers() {
    let l: u64 = kani::any();
    let d: u64 = kani::any();
    let t: u16 = kani::any();
    let b: u16 = kani::any();
    let hy: u16 = kani::any();
    let plan = sync_plan(l, d, t, b, hy);
    if t > 10_000 || b > 10_000 || hy > 10_000 {
        assert!(plan.is_none(), "out-of-range bps fail closed");
        kani::cover!(true, "COVER: fail-closed arm");
        return;
    }
    let Some(vv) = l.checked_add(d) else {
        assert!(plan.is_none(), "V overflow fails closed");
        return;
    };
    let v = vv as u128;
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

// ---- S3 admin flush (I-S1), split by concrete tag ---------------------------------------------

fn flush_refused(tag: u8) {
    let amount: u64 = kani::any();
    let mut data = [0u8; 9];
    data[0] = tag;
    data[1..9].copy_from_slice(&amount.to_le_bytes());
    let pid = solana_program::pubkey::Pubkey::new_from_array([7u8; 32]);
    let r = percolator_stake::processor::process(&pid, &[], &data);
    assert_eq!(
        r,
        Err(solana_program::program_error::ProgramError::Custom(
            percolator_stake::error::StakeError::DeprecatedV5 as u32
        ))
    );
    kani::cover!(amount > 0, "COVER: refused for a non-zero amount");
    kani::cover!(amount == u64::MAX, "COVER: refused for the largest amount");
}

/// MS-S6a: tag 3 (FlushToInsurance) is `Err(DeprecatedV5)` for ANY amount, before any account is read.
#[kani::proof]
fn ms_s6a_tag3_flush_refused() {
    flush_refused(3);
}

/// MS-S6b: tag 23 (RecoverFlushedInsurance) is `Err(DeprecatedV5)` for ANY amount, before any account is read.
#[kani::proof]
fn ms_s6b_tag23_recover_refused() {
    flush_refused(23);
}
