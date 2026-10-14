//! Kani review 2026-10-14 (stake lane, ~/wt-v22-kanirev/review/stake-sweep.md). ADDITIVE harnesses
//! only: no existing harness, assume, assert or bound is changed. Each one either adds a cover on the
//! asserted path of a PASS row, or decomposes / narrows a NO-VERDICT row so it can get a verdict.
//! Every harness runs the REAL production functions (`percolator_stake::math`, `StakePool`).
//! Run one: `cargo kani --tests --exact --harness <name>` (stake Kani lock, see the lane file).
#![cfg(kani)]

use percolator_stake::math::{
    calc_collateral_for_withdraw, calc_junior_collateral_for_withdraw, calc_junior_lp_for_deposit,
    calc_lp_for_deposit, calc_senior_collateral_for_withdraw, calc_senior_lp_for_deposit, pool_value,
    sync_plan, SyncAction,
};

fn u8v() -> u64 {
    let v: u8 = kani::any();
    v as u64
}

fn u16v() -> u64 {
    let v: u16 = kani::any();
    v as u64
}

/// RV-1 (cover add, `kani_proofs::proof_pool_value_none_iff_overdrawn`, PASS_NOCOVER): same
/// statement, full u64 width, plus a cover on EACH asserted branch.
#[kani::proof]
fn rv_pool_value_none_iff_overdrawn_covered() {
    let deposited: u64 = kani::any();
    let withdrawn: u64 = kani::any();
    let result = pool_value(deposited, withdrawn);
    if withdrawn > deposited {
        kani::cover!(result.is_none(), "overdrawn branch reached");
        assert!(result.is_none());
    } else {
        kani::cover!(result == Some(deposited - withdrawn) && withdrawn > 0, "solvent branch reached");
        assert_eq!(result, Some(deposited - withdrawn));
    }
}

/// RV-2 (decomposition of ST-5 `st5_last_junior_full_burn_pays_exactly_ejb`, NO-VERDICT 1803 s):
/// the FULL-BURN and REFUSAL arms only (no division on these paths), full u64 width. This is the
/// half that protects senior from the N7 last-junior residual windfall (mutant ST-M4). The partial
/// arm (an N7 mul-div) is RV-3.
#[kani::proof]
fn rv_st5a_full_burn_and_refusal_arms() {
    let supply: u64 = kani::any();
    let bal: u64 = kani::any();
    let lp: u64 = kani::any();
    kani::assume(supply == 0 || lp >= supply);
    let r = calc_junior_collateral_for_withdraw(supply, bal, lp);
    if supply == 0 || lp > supply {
        assert_eq!(r, None, "over-burn or zero supply refused");
    } else {
        assert_eq!(r, Some(bal), "full burn pays exactly the junior balance");
    }
    kani::cover!(supply > 0 && lp == supply && bal > supply, "full burn with earned fees (the old N7 residual case)");
    kani::cover!(supply > 0 && lp > supply && r.is_none(), "over-burn refused");
    kani::cover!(supply == 0 && r.is_none(), "zero supply refused");
}

/// RV-3 (ST-5 partial arm, u8 operands): a partial junior burn pays the N7 formula and never more
/// than the junior balance.
#[kani::proof]
#[kani::solver(z3)]
fn rv_st5b_partial_arm_u8() {
    let ps = u8v();
    let pb = u8v();
    let pl = u8v();
    kani::assume(ps > 0 && pl > 0 && pl < ps);
    let part = calc_junior_collateral_for_withdraw(ps, pb, pl);
    assert_eq!(part, calc_collateral_for_withdraw(ps, pb, pl), "partial burns keep the N7 formula");
    assert!(part.map_or(false, |v| v <= pb), "never more than the junior balance (and never refused at u8)");
    kani::cover!(part.is_some_and(|v| v > 0), "partial burn pays");
    kani::cover!(pb > ps && part.is_some_and(|v| v > pl), "share price > 1");
}

/// RV-4 (round-trip no-profit, the anti-inflation core; every Kani row stating it is NO-VERDICT:
/// `port_subpool_deposit_withdraw_no_profit`, `port_deposit_withdraw_no_inflation_inductive`,
/// `kani_proofs::proof_deposit_withdraw_no_inflation`). Same statement as the subpool port, u8
/// operands, every arm covered, NO early return before the assert on a reachable Some path.
#[kani::proof]
#[kani::solver(z3)]
fn rv_subpool_roundtrip_no_profit_u8() {
    let (sub_lp, sub_bal, dep) = (u8v(), u8v(), u8v());
    let senior: bool = kani::any();
    kani::assume(sub_lp > 0 && sub_bal > 0 && dep > 0);
    let lp = if senior {
        calc_senior_lp_for_deposit(sub_lp, sub_bal, dep)
    } else {
        calc_junior_lp_for_deposit(sub_lp, sub_bal, dep)
    };
    // u8 operands: the pro-rata branch never overflows, so the mint is always computed.
    let lp = lp.expect("pro-rata mint never refused at u8");
    if lp == 0 {
        kani::cover!(true, "zero-share mint (caller refuses ZeroSharesMinted)");
        return;
    }
    let back = if senior {
        calc_senior_collateral_for_withdraw(sub_lp + lp, sub_bal + dep, lp)
    } else {
        calc_junior_collateral_for_withdraw(sub_lp + lp, sub_bal + dep, lp)
    }
    .expect("redemption never refused at u8");
    kani::cover!(senior && back == dep, "senior round trip, exact");
    kani::cover!(!senior && back < dep, "junior round trip, rounding retained");
    kani::cover!(sub_bal > sub_lp && back + 1 < dep, "share price > 1, loss > 1 atom");
    assert!(back <= dep);
}

/// RV-5: RV-4 at u16 (the port's own domain) under z3 (word-level: the harness and production
/// multiplier terms collapse).
#[kani::proof]
#[kani::solver(z3)]
fn rv_subpool_roundtrip_no_profit_u16() {
    let (sub_lp, sub_bal, dep) = (u16v(), u16v(), u16v());
    let senior: bool = kani::any();
    kani::assume(sub_lp > 0 && sub_bal > 0 && dep > 0);
    let lp = if senior {
        calc_senior_lp_for_deposit(sub_lp, sub_bal, dep)
    } else {
        calc_junior_lp_for_deposit(sub_lp, sub_bal, dep)
    };
    let lp = lp.expect("pro-rata mint never refused at u16");
    if lp == 0 {
        return;
    }
    let back = if senior {
        calc_senior_collateral_for_withdraw(sub_lp + lp, sub_bal + dep, lp)
    } else {
        calc_junior_collateral_for_withdraw(sub_lp + lp, sub_bal + dep, lp)
    }
    .expect("redemption never refused at u16");
    kani::cover!(senior && back == dep, "senior round trip, exact");
    kani::cover!(!senior && back < dep, "junior round trip, rounding retained");
    assert!(back <= dep);
}

/// RV-6 (ST-1 `st1_sync_plan_bounded_by_target_and_buffer`, NO-VERDICT 1804 s at u32): the same
/// statement at u8 liquid/deployed (dials still full u16). The properties are branch-structural
/// (min / saturating_sub / exact recovery), so the width only bounds V. Mutant ST-M1.
#[kani::proof]
#[kani::solver(z3)]
fn rv_st1_sync_plan_u8() {
    let liquid = u8v();
    let deployed = u8v();
    let t: u16 = kani::any();
    let b: u16 = kani::any();
    let h: u16 = kani::any();
    let r = sync_plan(liquid, deployed, t, b, h);
    if t > 10_000 || b > 10_000 || h > 10_000 {
        assert!(r.is_none(), "a dial above 100% is refused");
        return;
    }
    let v = liquid + deployed;
    let target = (v as u128 * t as u128 / 10_000) as u64;
    let buffer = (v as u128 * b as u128).div_ceil(10_000) as u64;
    match r {
        Some(SyncAction::TopUp(a)) => {
            assert!(a > 0);
            assert!(deployed + a <= target, "never above the target");
            assert!(liquid - a >= buffer, "never below the liquid buffer");
            kani::cover!(a < target - deployed, "top-up limited by the buffer");
            kani::cover!(a == target - deployed && liquid - a > buffer, "top-up limited by the target");
        }
        Some(SyncAction::Recover(x)) => {
            kani::cover!(x > 0 && h > 0, "recover with hysteresis");
            assert!(deployed - x == target, "recovery lands exactly on the target");
        }
        Some(SyncAction::None) => kani::cover!(deployed < target, "below target but inside hysteresis or no spare"),
        None => panic!("in-range dials never fail"),
    }
}

/// Review: same body as `rv_subpool_roundtrip_no_profit_u8`, solver cadical (the z3 run was NO-VERDICT at 600 s).
#[kani::proof]
#[kani::solver(cadical)]
fn rv_subpool_roundtrip_no_profit_u8_cadical() {
    let (sub_lp, sub_bal, dep) = (u8v(), u8v(), u8v());
    let senior: bool = kani::any();
    kani::assume(sub_lp > 0 && sub_bal > 0 && dep > 0);
    let lp = if senior {
        calc_senior_lp_for_deposit(sub_lp, sub_bal, dep)
    } else {
        calc_junior_lp_for_deposit(sub_lp, sub_bal, dep)
    };
    // u8 operands: the pro-rata branch never overflows, so the mint is always computed.
    let lp = lp.expect("pro-rata mint never refused at u8");
    if lp == 0 {
        kani::cover!(true, "zero-share mint (caller refuses ZeroSharesMinted)");
        return;
    }
    let back = if senior {
        calc_senior_collateral_for_withdraw(sub_lp + lp, sub_bal + dep, lp)
    } else {
        calc_junior_collateral_for_withdraw(sub_lp + lp, sub_bal + dep, lp)
    }
    .expect("redemption never refused at u8");
    kani::cover!(senior && back == dep, "senior round trip, exact");
    kani::cover!(!senior && back < dep, "junior round trip, rounding retained");
    kani::cover!(sub_bal > sub_lp && back + 1 < dep, "share price > 1, loss > 1 atom");
    assert!(back <= dep);
}

/// Review: same body as `rv_st1_sync_plan_u8`, solver kissat (the z3 run was NO-VERDICT at 600 s).
#[kani::proof]
#[kani::solver(kissat)]
fn rv_st1_sync_plan_u8_kissat() {
    let liquid = u8v();
    let deployed = u8v();
    let t: u16 = kani::any();
    let b: u16 = kani::any();
    let h: u16 = kani::any();
    let r = sync_plan(liquid, deployed, t, b, h);
    if t > 10_000 || b > 10_000 || h > 10_000 {
        assert!(r.is_none(), "a dial above 100% is refused");
        return;
    }
    let v = liquid + deployed;
    let target = (v as u128 * t as u128 / 10_000) as u64;
    let buffer = (v as u128 * b as u128).div_ceil(10_000) as u64;
    match r {
        Some(SyncAction::TopUp(a)) => {
            assert!(a > 0);
            assert!(deployed + a <= target, "never above the target");
            assert!(liquid - a >= buffer, "never below the liquid buffer");
            kani::cover!(a < target - deployed, "top-up limited by the buffer");
            kani::cover!(a == target - deployed && liquid - a > buffer, "top-up limited by the target");
        }
        Some(SyncAction::Recover(x)) => {
            kani::cover!(x > 0 && h > 0, "recover with hysteresis");
            assert!(deployed - x == target, "recovery lands exactly on the target");
        }
        Some(SyncAction::None) => kani::cover!(deployed < target, "below target but inside hysteresis or no spare"),
        None => panic!("in-range dials never fail"),
    }
}
