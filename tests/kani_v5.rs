//! Kani v2.2 final run (design: ~/percolator-ops/ledger/kani-v22-final-run-design-rev2-2026-10-09.md,
//! rev 2.1 addendum). Stake harnesses on the REAL production code (`percolator_stake::math`,
//! `percolator_stake::state::StakePool`), never on a mirror copy.
//!
//! * ST-1 `sync_plan`, ST-2 `deployed_value`, ST-4 `liquid_withdrawal_ok` / `pool_value_v5`.
//! * 28 ports of the `kani-proofs/` mirror crate (rev 2 R3.4 as amended by rev 2.1): 21 math
//!   ports, 4 flush-accounting rows and 3 live ReturnInsurance rows, the last 7 on
//!   `StakePool::total_pool_value` (`src/state.rs:1074`) and, for the LP-value row,
//!   `StakePool::calc_collateral_for_withdraw`.
//!
//! Bounds follow the mirror crate (u8 / u16 / `< 100` domains, cast into the production u64
//! types). The mirror's scale-invariance argument (its module doc) is the paper width-lift for
//! the multiplicative harnesses: label "bounded + paper lemma".
//!
//! Where a port models a processor state transition (a flush adds to `total_flushed`; a
//! ReturnInsurance adds to `total_returned`, capped by `total_flushed - total_returned`,
//! `src/processor.rs:3612`), the harness writes the counters itself; only the VALUE functions
//! are the code under proof.
//!
//! Run (one harness): `cargo kani --tests --exact --harness <name>`.
#![cfg(kani)]

use percolator_stake::math::{
    calc_collateral_for_withdraw, calc_junior_collateral_for_withdraw, calc_junior_lp_for_deposit,
    calc_lp_for_deposit, calc_senior_collateral_for_withdraw, calc_senior_lp_for_deposit,
    deployed_value, distribute_fees, liquid_withdrawal_ok, pool_value_v5, sync_plan, SyncAction,
};
use percolator_stake::state::StakePool;

const VIRTUAL_SHARES: u64 = 1;
const VIRTUAL_ASSETS: u64 = 1;

fn u16v() -> u64 {
    let v: u16 = kani::any();
    v as u64
}

fn u8v() -> u64 {
    let v: u8 = kani::any();
    v as u64
}

/// A zeroed, mode-0 pool with the given ledger counters (all other bytes zero: junior 0,
/// realized junior loss 0, fees 0).
fn pool(deposited: u64, withdrawn: u64, flushed: u64, returned: u64) -> StakePool {
    let mut p: StakePool = bytemuck::Zeroable::zeroed();
    p.total_deposited = deposited;
    p.total_withdrawn = withdrawn;
    p.total_flushed = flushed;
    p.total_returned = returned;
    p
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// ST-1, ST-2, ST-4 (new v5 obligations)
// ════════════════════════════════════════════════════════════════════════════════════════════

/// ST-1 (I-S4) `sync_plan` (`src/math.rs:616`). With `V = liquid + deployed`,
/// `target = floor(V*t/1e4)`, `buffer = ceil(V*b/1e4)`: TopUp(a) ⇒ `deployed + a <= target` and
/// `liquid - a >= buffer`; Recover(r) ⇒ `deployed - r == target`; any dial > 1e4 ⇒ None.
/// Bounds: liquid, deployed u32 (cast to u64); dials u16. Cost M.
/// Mutant (rev2 R4.5 stake row 1): sync ignores the buffer ⇒ the `liquid - a >= buffer` assert.
#[kani::proof]
#[kani::solver(cadical)]
fn st1_sync_plan_bounded_by_target_and_buffer() {
    let liquid: u32 = kani::any();
    let deployed: u32 = kani::any();
    let t: u16 = kani::any();
    let b: u16 = kani::any();
    let h: u16 = kani::any();
    let (liquid, deployed) = (liquid as u64, deployed as u64);
    let r = sync_plan(liquid, deployed, t, b, h);
    if t > 10_000 || b > 10_000 || h > 10_000 {
        assert!(r.is_none(), "a dial above 100% is refused");
        kani::cover!(true, "dial out of range refused");
        return;
    }
    let v = liquid + deployed; // u32 + u32 fits u64
    let target = (v as u128 * t as u128 / 10_000) as u64;
    let buffer = (v as u128 * b as u128).div_ceil(10_000) as u64;
    match r {
        Some(SyncAction::TopUp(a)) => {
            assert!(a > 0);
            assert!(deployed + a <= target, "never above the target");
            assert!(liquid - a >= buffer, "never below the liquid buffer");
            kani::cover!(true, "top-up");
            kani::cover!(a < target - deployed, "top-up limited by the buffer");
        }
        Some(SyncAction::Recover(x)) => {
            assert!(deployed - x == target, "recovery lands exactly on the target");
            kani::cover!(true, "recover");
        }
        Some(SyncAction::None) => kani::cover!(true, "no action"),
        None => panic!("in-range dials never fail (u32 values cannot overflow u64)"),
    }
}

/// ST-2 `deployed_value` (`src/math.rs:549`): `U == 0 ⇒ Some(0)`; `us > U ⇒ None`; else
/// `floor(us*i/U) <= i`. Bounds: u32 cast up. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn st2_deployed_value_pro_rata() {
    let us: u32 = kani::any();
    let ut: u32 = kani::any();
    let i: u32 = kani::any();
    let r = deployed_value(us as u128, ut as u128, i as u128);
    if ut == 0 {
        assert_eq!(r, Some(0));
        kani::cover!(true, "no units");
    } else if us > ut {
        assert!(r.is_none());
        kani::cover!(true, "stake class above total refused");
    } else {
        let expect = (us as u128 * i as u128) / ut as u128;
        assert_eq!(r, Some(expect as u64));
        assert!(expect <= i as u128);
        kani::cover!(us < ut && expect < i as u128, "partial class value");
    }
}

/// ST-4 `liquid_withdrawal_ok` (`:645`) exact; `pool_value_v5` (`:584`) is a checked add.
/// Full u64 width (compare / add only). Cost S.
#[kani::proof]
fn st4_liquid_withdrawal_and_v5_value() {
    let w: u64 = kani::any();
    let liquid: u64 = kani::any();
    let vault: u64 = kani::any();
    assert_eq!(liquid_withdrawal_ok(w, liquid, vault), w <= liquid && w <= vault);
    assert_eq!(pool_value_v5(liquid, vault), liquid.checked_add(vault));
    kani::cover!(w <= liquid && w > vault, "refused by the vault balance only");
    kani::cover!(w > liquid && w <= vault, "refused by the liquid booked value only");
    kani::cover!(pool_value_v5(liquid, vault).is_none(), "v5 value overflow fails closed");
}

// ════════════════════════════════════════════════════════════════════════════════════════════
// Ports of kani-proofs/ (math, real functions)
// ════════════════════════════════════════════════════════════════════════════════════════════

/// Port of `proof_no_dilution`: a later depositor never lowers an earlier depositor's value.
/// u16 domain (mirror PERC-761 bound). Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn port_no_dilution() {
    let (init_s, init_pv, a_dep, b_dep) = (u16v(), u16v(), u16v(), u16v());
    kani::assume(init_s > 0 && init_pv > 0 && a_dep > 0 && b_dep > 0);
    let a_lp = match calc_lp_for_deposit(init_s, init_pv, a_dep) {
        Some(lp) if lp > 0 => lp,
        _ => return,
    };
    let (s1, pv1) = (init_s + a_lp, init_pv + a_dep);
    let before = match calc_collateral_for_withdraw(s1, pv1, a_lp) {
        Some(v) => v,
        None => return,
    };
    let b_lp = match calc_lp_for_deposit(s1, pv1, b_dep) {
        Some(lp) if lp > 0 => lp,
        _ => return,
    };
    let after = match calc_collateral_for_withdraw(s1 + b_lp, pv1 + b_dep, a_lp) {
        Some(v) => v,
        None => return,
    };
    kani::cover!(after >= before, "no-dilution assertion path reached");
    kani::cover!(after > before, "the late deposit's rounding benefits the early holder");
    assert!(after >= before);
}

/// Port of `proof_lp_deposit_overflow_guard`: every `Some(lp)` satisfies the pool-favouring
/// floor invariant over the N7 offset quantities. u8 domain. Cost S.
#[kani::proof]
fn port_lp_deposit_overflow_guard() {
    let (s, pv, dep) = (u8v(), u8v(), u8v());
    if let Some(lp) = calc_lp_for_deposit(s, pv, dep) {
        if pv > 0 {
            let ok = (lp as u128) * (pv as u128 + VIRTUAL_ASSETS as u128)
                <= (dep as u128) * (s as u128 + VIRTUAL_SHARES as u128);
            kani::cover!(ok, "rounding invariant path reached");
            assert!(ok);
        } else {
            kani::cover!(s == 0, "first-depositor branch");
            assert_eq!(lp, dep);
        }
    }
}

/// Port of `proof_overflow_guard_fires_concrete`, re-derived for the PRODUCTION u64 widths: the
/// guard `lp > u64::MAX` fires and returns None. Concrete. Cost S.
#[kani::proof]
fn port_overflow_guard_fires_concrete() {
    // deposit * (supply + 1) / (pv + 1) = (2^64-1) * (2^64-1) / 2 > u64::MAX
    assert!(calc_lp_for_deposit(u64::MAX - 1, 1, u64::MAX).is_none());
    assert_eq!(calc_lp_for_deposit(2, 1, 100_000), Some(150_000));
    assert_eq!(calc_lp_for_deposit(1, 1, 1), Some(1));
    assert!(calc_collateral_for_withdraw(1, u64::MAX - 1, u64::MAX).is_none());
    kani::cover!(true, "concrete guard checks reached");
}

/// Port of `proof_zero_deposit_zero_lp`. `< 100` domain. Cost S.
#[kani::proof]
fn port_zero_deposit_zero_lp() {
    let (s, pv) = (u8v(), u8v());
    kani::assume(s < 100 && pv < 100);
    match calc_lp_for_deposit(s, pv, 0) {
        Some(lp) => {
            kani::cover!(lp == 0, "Some(0) path");
            assert_eq!(lp, 0)
        }
        None => kani::cover!(true, "orphaned / valueless state blocks"),
    }
}

/// Port of `proof_zero_burn_zero_col`. `< 100` domain. Cost S.
#[kani::proof]
fn port_zero_burn_zero_col() {
    let (s, pv) = (u8v(), u8v());
    kani::assume(s < 100 && pv < 100);
    match calc_collateral_for_withdraw(s, pv, 0) {
        Some(c) => {
            kani::cover!(c == 0, "Some(0) path");
            assert_eq!(c, 0)
        }
        None => {
            kani::cover!(s == 0, "supply 0 refused");
            assert_eq!(s, 0)
        }
    }
}

/// Port of `proof_c9_orphaned_value_blocked`. Cost S.
#[kani::proof]
fn port_c9_orphaned_value_blocked() {
    let (pv, dep) = (u8v(), u8v());
    kani::assume(pv > 0 && pv < 100 && dep > 0 && dep < 100);
    let r = calc_lp_for_deposit(0, pv, dep);
    kani::cover!(r.is_none(), "orphaned value blocked");
    assert!(r.is_none());
}

/// Port of `proof_c9_valueless_lp_blocked`. Cost S.
#[kani::proof]
fn port_c9_valueless_lp_blocked() {
    let (s, dep) = (u8v(), u8v());
    kani::assume(s > 0 && s < 100 && dep > 0 && dep < 100);
    let r = calc_lp_for_deposit(s, 0, dep);
    kani::cover!(r.is_none(), "valueless LP blocked");
    assert!(r.is_none());
}

/// Port of `proof_c9_true_first_depositor`. Full u64 width (no arithmetic on the branch). Cost S.
#[kani::proof]
fn port_c9_true_first_depositor() {
    let dep: u64 = kani::any();
    kani::assume(dep > 0);
    let r = calc_lp_for_deposit(0, 0, dep);
    kani::cover!(r == Some(dep), "1:1 genesis");
    assert_eq!(r, Some(dep));
}

/// Port of `proof_roundtrip_under_pool_value_change`: if the pool value drops (or stays), the
/// round trip returns at most the deposit. u8 domain, signed delta. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn port_roundtrip_under_pool_value_change() {
    let (supply, pv, deposit) = (u8v(), u8v(), u8v());
    let delta: i16 = kani::any();
    kani::assume(supply > 0 && pv > 0 && deposit > 0);
    kani::assume(delta > -255 && delta < 255);
    let lp = match calc_lp_for_deposit(supply, pv, deposit) {
        Some(lp) if lp > 0 => lp,
        _ => return,
    };
    let new_pv = pv as i64 + deposit as i64 + delta as i64;
    kani::assume(new_pv > 0);
    let back = match calc_collateral_for_withdraw(supply + lp, new_pv as u64, lp) {
        Some(v) => v,
        None => return,
    };
    if delta <= 0 {
        kani::cover!(back <= deposit && delta < 0, "loss path reached");
        assert!(back <= deposit);
    } else {
        kani::cover!(back > deposit, "a gain is shared (the claim can rise above the deposit)");
    }
}

/// Port of `proof_no_inflation_attack`: after a donation, a victim's non-zero deposit that mints
/// LP always redeems a positive amount. u16 domain. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn port_no_inflation_attack() {
    let (att, vic, donation) = (u16v(), u16v(), u16v());
    kani::assume(att > 0 && vic > 0);
    let att_lp = calc_lp_for_deposit(0, 0, att).unwrap();
    let inflated = att + donation;
    if let Some(vlp) = calc_lp_for_deposit(att_lp, inflated, vic) {
        if vlp > 0 {
            if let Some(vb) = calc_collateral_for_withdraw(att_lp + vlp, inflated + vic, vlp) {
                kani::cover!(vb > 0 && donation > 0, "victim recovers after a donation");
                assert!(vb > 0);
            }
        } else {
            kani::cover!(true, "donation rounds the victim to 0 LP (the caller refuses ZeroSharesMinted)");
        }
    }
}

/// Port of `proof_determinism_across_states`: genesis 1:1 equals pro-rata at a 1:1 ratio.
/// `< 50` domain. Cost S.
#[kani::proof]
fn port_determinism_across_states() {
    let amount = u8v();
    kani::assume(amount > 0 && amount < 50);
    let lp1 = calc_lp_for_deposit(0, 0, amount).unwrap();
    let lp2 = calc_lp_for_deposit(amount, amount, amount).unwrap();
    kani::cover!(lp1 == lp2, "consistent");
    assert_eq!(lp1, lp2);
}

/// Port of `proof_deposit_withdraw_no_inflation_inductive` (PERC-760): from an ARBITRARY
/// non-empty pool (`supply > 0 ∧ pv > 0`), deposit then withdraw returns `<= deposit` and the
/// pool invariant `(supply == 0) == (pv == 0)` is preserved. u16 domain. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn port_deposit_withdraw_no_inflation_inductive() {
    let (supply, pv, deposit) = (u16v(), u16v(), u16v());
    kani::assume(supply > 0 && pv > 0 && deposit > 0);
    let lp = match calc_lp_for_deposit(supply, pv, deposit) {
        Some(lp) if lp > 0 => lp,
        _ => return,
    };
    let (ns, np) = (supply + lp, pv + deposit);
    assert!((ns == 0) == (np == 0), "INV preserved");
    let back = match calc_collateral_for_withdraw(ns, np, lp) {
        Some(v) => v,
        None => return,
    };
    kani::cover!(back <= deposit, "inductive anti-inflation path");
    kani::cover!(back < deposit, "rounding keeps value in the pool");
    assert!(back <= deposit);
}

/// Port of `proof_two_depositors_conservation_inductive`: two depositors into an arbitrary
/// non-empty pool, with appreciation between them; A then B withdraw; total out
/// `<= a + b + appreciation`. u16 domain. Cost M-L.
#[kani::proof]
#[kani::solver(cadical)]
fn port_two_depositors_conservation_inductive() {
    let (supply, pv, a, b, appr) = (u16v(), u16v(), u16v(), u16v(), u16v());
    kani::assume(supply > 0 && pv > 0 && a > 0 && b > 0);
    let a_lp = match calc_lp_for_deposit(supply, pv, a) {
        Some(lp) if lp > 0 => lp,
        _ => return,
    };
    let (s1, pv1) = (supply + a_lp, pv + a + appr);
    let b_lp = match calc_lp_for_deposit(s1, pv1, b) {
        Some(lp) if lp > 0 => lp,
        _ => return,
    };
    let (s2, pv2) = (s1 + b_lp, pv1 + b);
    let a_back = match calc_collateral_for_withdraw(s2, pv2, a_lp) {
        Some(v) => v,
        None => return,
    };
    let b_back = match calc_collateral_for_withdraw(s2 - a_lp, pv2 - a_back, b_lp) {
        Some(v) => v,
        None => return,
    };
    // NOTE (port): the mirror bounds total_out by a + b + appreciation. The incumbent
    // supply also owns part of the appreciation, so that bound is loose-but-true; kept as is.
    kani::cover!(appr > 0, "appreciation between the deposits");
    assert!(a_back + b_back <= a + b + appr);
}

/// Port of `proof_distribute_fees_no_senior_all_to_junior`. u16 balances/fee, mult <= 50,000
/// (the production cap) cast to u16 domain (max 50,000 fits u16). Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn port_distribute_fees_no_senior_all_to_junior() {
    let jb = u16v();
    let fee = u16v();
    let mult: u16 = kani::any();
    kani::assume(jb > 0 && fee > 0 && mult > 0 && mult <= 50_000);
    let (jf, sf) = distribute_fees(jb, 0, mult, fee);
    kani::cover!(jf == fee, "all fees to junior");
    assert!(jf == fee && sf == 0);
}

/// Port of `proof_subpool_deposit_orphan_blocked` on BOTH real sub-pool entry points
/// (`calc_junior_lp_for_deposit` `:165`, `calc_senior_lp_for_deposit` `:197`). Cost S.
#[kani::proof]
fn port_subpool_deposit_orphan_blocked() {
    let (bal, dep) = (u16v(), u16v());
    kani::assume(bal > 0 && dep > 0);
    let j = calc_junior_lp_for_deposit(0, bal, dep);
    let s = calc_senior_lp_for_deposit(0, bal, dep);
    kani::cover!(j.is_none() && s.is_none(), "orphaned sub-pool blocked");
    assert!(j.is_none() && s.is_none());
}

/// Port of `proof_subpool_first_deposit_one_to_one` (both sub-pools). Full u64 width. Cost S.
#[kani::proof]
fn port_subpool_first_deposit_one_to_one() {
    let dep: u64 = kani::any();
    kani::assume(dep > 0);
    let j = calc_junior_lp_for_deposit(0, 0, dep);
    let s = calc_senior_lp_for_deposit(0, 0, dep);
    kani::cover!(j == Some(dep), "junior genesis 1:1");
    assert_eq!(j, Some(dep));
    assert_eq!(s, Some(dep));
}

/// Port of `proof_subpool_deposit_withdraw_no_profit`: junior and senior each price deposit AND
/// redemption against their own sub-pool basis, so a round trip cannot profit. u16. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn port_subpool_deposit_withdraw_no_profit() {
    let (sub_lp, sub_bal, dep) = (u16v(), u16v(), u16v());
    let senior: bool = kani::any();
    kani::assume(sub_lp > 0 && sub_bal > 0 && dep > 0);
    let lp = if senior {
        calc_senior_lp_for_deposit(sub_lp, sub_bal, dep)
    } else {
        calc_junior_lp_for_deposit(sub_lp, sub_bal, dep)
    };
    let lp = match lp {
        Some(l) if l > 0 => l,
        _ => return,
    };
    let back = if senior {
        calc_senior_collateral_for_withdraw(sub_lp + lp, sub_bal + dep, lp)
    } else {
        calc_junior_collateral_for_withdraw(sub_lp + lp, sub_bal + dep, lp)
    };
    let back = match back {
        Some(v) => v,
        None => return,
    };
    kani::cover!(senior, "senior sub-pool round trip");
    kani::cover!(!senior, "junior sub-pool round trip");
    assert!(back <= dep);
}

// ── tranche valuation on the real StakePool ─────────────────────────────────────────────────

/// Port of `proof_senior_balance_never_underflows` on `StakePool::{total_pool_value,
/// effective_junior_balance, senior_balance}` (`src/state.rs:1074`, `:700`, `:728`): under the
/// pool invariants (returned <= flushed; junior balance <= gross principal) the effective junior
/// balance never exceeds pool value, so `senior_balance()` is `Some`. u16. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn port_senior_balance_never_underflows() {
    let (dep, wd, flush, ret, jb) = (u16v(), u16v(), u16v(), u16v(), u16v());
    kani::assume(wd <= dep && ret <= flush && jb <= dep - wd);
    let mut p = pool(dep, wd, flush, ret);
    p.set_tranche_enabled(true);
    p.set_junior_balance(jb);
    let pv = match p.total_pool_value() {
        Some(v) => v,
        None => return, // flushed beyond principal: not a reachable ledger
    };
    let ejb = p.effective_junior_balance();
    kani::cover!(ejb < jb, "junior marked down by an outstanding loss");
    assert!(ejb <= pv);
    assert!(p.senior_balance().is_some());
}

/// Port of `proof_tranche_decomposition`: `senior_balance + effective_junior_balance ==
/// total_pool_value` on the real pool. u16. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn port_tranche_decomposition() {
    let (dep, wd, flush, ret, jb) = (u16v(), u16v(), u16v(), u16v(), u16v());
    kani::assume(wd <= dep && ret <= flush && jb <= dep - wd);
    let mut p = pool(dep, wd, flush, ret);
    p.set_tranche_enabled(true);
    p.set_junior_balance(jb);
    let pv = match p.total_pool_value() {
        Some(v) => v,
        None => return,
    };
    let sb = match p.senior_balance() {
        Some(v) => v,
        None => return,
    };
    kani::cover!(flush > ret && jb > 0, "partition with an outstanding loss");
    assert_eq!(sb as u128 + p.effective_junior_balance() as u128, pv as u128);
}

/// Port of `proof_169_mode1_no_false_underflow_brick` on the real `total_pool_value` (i128
/// widening, #169): returns the true signed value whenever it is in range, including
/// `withdrawn > deposited` (fee-inclusive payouts), and None exactly when the value is negative.
/// u16 inputs (linear arithmetic; full width would also be cheap, kept at the mirror bound). Cost S.
#[kani::proof]
fn port_169_mode1_no_false_underflow_brick() {
    let (dep, wd, flush, ret, fees, rl) = (u16v(), u16v(), u16v(), u16v(), u16v(), u16v());
    let mut p = pool(dep, wd, flush, ret);
    p.pool_mode = 1;
    p.total_fees_earned = fees;
    p.set_realized_junior_loss(rl);
    let truth = dep as i128 - wd as i128 - flush as i128 + ret as i128 + fees as i128 - rl as i128;
    let got = p.total_pool_value();
    if truth >= 0 {
        kani::cover!(wd > dep, "withdrawn above deposited does not brick");
        assert_eq!(got, Some(truth as u64));
    } else {
        kani::cover!(true, "insolvency fails closed");
        assert!(got.is_none());
    }
}

/// Port of `proof_161_recovery_never_windfalls_protected_senior`: model-level (the #161 exit
/// booking is modelled). Senior `sp` and junior `jb0` deposit; `nl` is flushed; the LAST junior
/// redeems its whole junior LP supply `jlp` and is paid the REAL production payout
/// `calc_junior_collateral_for_withdraw(jlp, effective_junior_balance, jlp)` (as at
/// `processor.rs` ~1523-1529); then the #161 exit booking (`total_returned += L`,
/// `realized_junior_loss += L`, junior balance 0, `processor.rs` ~1683-1726) and a later
/// ReturnInsurance of `r <= flushed - returned` (`processor.rs` ~3612) are applied BY THE
/// HARNESS, not by the processor. Then `senior_balance() <= sp`. A payout of `None` is the
/// processor's Overflow refusal (no state change), so that path is out of scope. u16. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn port_161_recovery_never_windfalls_protected_senior() {
    let (sp, jb0, nl, jlp) = (u16v(), u16v(), u16v(), u16v());
    let deposited = sp + jb0;
    kani::assume(nl <= deposited);
    kani::assume(jlp > 0);
    // junior-first loss on the gross balances (what effective_junior_balance computes)
    let mut p = pool(deposited, 0, nl, 0);
    p.set_tranche_enabled(true);
    p.set_junior_balance(jb0);
    p.set_junior_total_lp(jlp);
    let ejb = p.effective_junior_balance();
    let l = jb0 - ejb; // absorbed loss
    // last junior exit: the production payout for redeeming the whole junior LP supply
    let payout = match calc_junior_collateral_for_withdraw(jlp, ejb, jlp) {
        Some(v) => v,
        None => return, // processor: Err(Overflow), nothing booked
    };
    p.total_withdrawn = payout;
    // #161 exit booking (modelled)
    p.total_returned = l;
    p.set_realized_junior_loss(l);
    p.set_junior_balance(0);
    p.set_junior_total_lp(0);
    // later ReturnInsurance, capped by the outstanding shortfall (processor.rs:3612)
    let r = u16v();
    kani::assume(r <= p.total_flushed.saturating_sub(p.total_returned));
    p.total_returned += r;
    let senior = match p.senior_balance() {
        Some(v) => v,
        None => return,
    };
    kani::cover!(senior == sp && r > 0, "senior restored exactly to principal");
    kani::cover!(l > 0, "junior forfeited a loss");
    assert!(senior <= sp);
}

/// ST-5 (stake fix `9942a2c`, Kani review round 2 B1): `calc_junior_collateral_for_withdraw`
/// (`src/math.rs`): a FULL-supply junior burn pays exactly the junior balance (never more than the
/// junior tranche's value, and no N7 residual left behind for senior); a partial burn is unchanged
/// (the N7 formula `calc_collateral_for_withdraw`) and never exceeds the balance; a burn above the
/// supply, or at zero supply, is refused. Full-burn and refusal arms at full u64 width; the partial
/// arm at u16 (it divides). Mutant ST-M4 (the full-burn branch reverted to the N7 formula). Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn st5_last_junior_full_burn_pays_exactly_ejb() {
    // full-burn and refusal arms: full width, no division on these paths
    let supply: u64 = kani::any();
    let bal: u64 = kani::any();
    let lp: u64 = kani::any();
    let r = calc_junior_collateral_for_withdraw(supply, bal, lp);
    if supply == 0 || lp > supply {
        assert_eq!(r, None, "over-burn or zero supply refused");
    } else if lp == supply {
        assert_eq!(r, Some(bal), "full burn pays exactly the junior balance");
    }
    kani::cover!(supply > 0 && lp == supply && bal > supply, "full burn with earned fees (the old N7 residual case)");
    kani::cover!(supply > 0 && lp > supply && r.is_none(), "over-burn refused");
    kani::cover!(supply == 0 && r.is_none(), "zero supply refused");
    // partial arm: u16 operands
    let ps = u16v();
    let pb = u16v();
    let pl = u16v();
    kani::assume(ps > 0 && pl > 0 && pl < ps);
    let part = calc_junior_collateral_for_withdraw(ps, pb, pl);
    assert_eq!(part, calc_collateral_for_withdraw(ps, pb, pl), "partial burns keep the N7 formula");
    assert!(part.map_or(true, |v| v <= pb), "never more than the junior balance");
    kani::cover!(part.is_some_and(|v| v > 0), "partial burn pays");
}

// ── flush accounting on StakePool::total_pool_value (rev 2.1) ───────────────────────────────

/// Port of `proof_flush_preserves_value` onto `StakePool::total_pool_value`: a flush of `x`
/// lowers the value by exactly `x`. `< 100` domain. Cost S.
#[kani::proof]
fn port_flush_preserves_value() {
    let (dep, wd, flushed, returned, x) = (u8v(), u8v(), u8v(), u8v(), u8v());
    kani::assume(dep < 100 && wd <= dep && flushed <= dep - wd && returned <= flushed);
    kani::assume(x <= dep - wd - flushed);
    let before = pool(dep, wd, flushed, returned).total_pool_value().unwrap();
    let after = pool(dep, wd, flushed + x, returned).total_pool_value().unwrap();
    kani::cover!(x > 0, "non-trivial flush");
    assert_eq!(before - x, after);
}

/// Port of `proof_flush_reduces_value_exactly`. Cost S.
#[kani::proof]
fn port_flush_reduces_value_exactly() {
    let (dep, wd, x) = (u8v(), u8v(), u8v());
    kani::assume(dep < 100 && wd <= dep && x <= dep - wd);
    let before = pool(dep, wd, 0, 0).total_pool_value().unwrap();
    let after = pool(dep, wd, x, 0).total_pool_value().unwrap();
    kani::cover!(x > 0, "non-trivial flush");
    assert_eq!(before - after, x);
}

/// Port of `proof_returns_increase_value`: one more returned atom raises the value by one.
/// Cost S.
#[kani::proof]
fn port_returns_increase_value() {
    let (dep, wd, f, r) = (u8v(), u8v(), u8v(), u8v());
    kani::assume(dep < 50 && wd <= dep && f <= dep - wd && r < f);
    let b = pool(dep, wd, f, r).total_pool_value().unwrap();
    let a = pool(dep, wd, f, r + 1).total_pool_value().unwrap();
    kani::cover!(a > b, "return raises value");
    assert_eq!(a, b + 1);
}

/// Port of `proof_pool_value_with_flush_no_panic` at FULL u64 width on every counter that
/// `total_pool_value` reads (deposited, withdrawn, flushed, returned, fees, realized junior
/// loss): never panics; `Some` iff the true i128 value is in `[0, u64::MAX]`. Cost S.
#[kani::proof]
fn port_pool_value_with_flush_no_panic() {
    let mut p = pool(kani::any(), kani::any(), kani::any(), kani::any());
    p.total_fees_earned = kani::any();
    let rl: u64 = kani::any();
    p.set_realized_junior_loss(rl);
    let truth = p.total_deposited as i128 - p.total_withdrawn as i128 - p.total_flushed as i128
        + p.total_returned as i128
        + p.total_fees_earned as i128
        - rl as i128;
    let got = p.total_pool_value();
    assert_eq!(got.is_some(), (0..=u64::MAX as i128).contains(&truth));
    kani::cover!(got.is_none() && truth > u64::MAX as i128, "too large fails closed");
    kani::cover!(got.is_some(), "in range");
}

// ── live ReturnInsurance rows (rev 2.1) ─────────────────────────────────────────────────────

/// Port of `proof_flush_return_conservation` (LIVE: ReturnInsurance `src/processor.rs:460`):
/// with `returned <= flushed`, the value is `<= deposited - withdrawn`; full return restores it
/// exactly; partial return stays strictly below. Cost S.
#[kani::proof]
fn port_flush_return_conservation() {
    let (d, w, f, r) = (u8v(), u8v(), u8v(), u8v());
    kani::assume(d < 100 && w <= d && f <= d - w && r <= f);
    let pv = pool(d, w, f, r).total_pool_value().unwrap();
    assert!(pv <= d - w);
    if r == f {
        kani::cover!(f > 0, "full return after a flush");
        assert_eq!(pv, d - w);
    } else {
        kani::cover!(true, "partial return");
        assert!(pv < d - w);
    }
}

/// Port of `proof_flush_full_return_conservation` (LIVE): flush then a full ReturnInsurance
/// (capped at `flushed - returned`, the processor's bound) restores the pre-flush value. Cost S.
#[kani::proof]
fn port_flush_full_return_conservation() {
    let (dep, wd, x) = (u8v(), u8v(), u8v());
    kani::assume(dep < 100 && wd <= dep && x <= dep - wd);
    let original = pool(dep, wd, 0, 0).total_pool_value().unwrap();
    let mut p = pool(dep, wd, x, 0);
    assert_eq!(p.total_pool_value().unwrap(), original - x);
    let outstanding = p.total_flushed.saturating_sub(p.total_returned);
    p.total_returned += outstanding; // ReturnInsurance of the whole outstanding amount
    kani::cover!(x > 0, "non-trivial flush and return");
    assert_eq!(p.total_pool_value().unwrap(), original);
}

/// Port of `proof_flush_conservation_lp_value` (LIVE) on `StakePool::calc_collateral_for_withdraw`
/// (`src/state.rs`, delegates to `math::calc_collateral_for_withdraw` over `total_pool_value`):
/// a flush can never let a full-supply redemption claim MORE than was flushed, and the claim is
/// monotone non-increasing. u8 domain. Cost M.
#[kani::proof]
#[kani::solver(cadical)]
fn port_flush_conservation_lp_value() {
    let (supply, dep, wd, x) = (u8v(), u8v(), u8v(), u8v());
    kani::assume(supply > 0 && dep > 0 && wd < dep && x > 0 && x < dep - wd);
    let mut before = pool(dep, wd, 0, 0);
    before.total_lp_supply = supply;
    let mut after = pool(dep, wd, x, 0);
    after.total_lp_supply = supply;
    match (before.calc_collateral_for_withdraw(supply), after.calc_collateral_for_withdraw(supply)) {
        (Some(b), Some(a)) => {
            kani::cover!(b - a < x, "the N7 offset retains part of the flushed value");
            assert!(b >= a);
            assert!(b - a <= x);
        }
        _ => unreachable!("u8 operands cannot overflow calc_collateral_for_withdraw"),
    }
}
