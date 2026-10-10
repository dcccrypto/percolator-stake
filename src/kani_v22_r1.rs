//! Kani v2.2 final run, stake R-1 (per-sub-pool dead-share floor flags, `aebbff6`).
//! PROOF-ONLY: a `cfg(kani)` child module of `processor`, hooked at the very END of
//! `src/processor.rs` (no production line moves; the SBF build never compiles it, G-ART).
//! It reaches the private `accrue_fees_inner` / `apply_minimum_liquidity_lock` through `super::`.
//!
//! Ghost model. Every harness carries a ghost `(ds, dj)`: the dead LP actually locked in the senior
//! and junior sub-pool supply (each 0 or MINIMUM_LIQUIDITY), and `(rs, rj)`: the real (SPL-minted)
//! LP in each. `total_lp_supply = ds + dj + rs + rj`, `junior_total_lp = dj + rj`. A LEGACY pool
//! (`_reserved[61] == 0`, supply > 0, created before R-1) holds exactly one floor in an unknown
//! sub-pool (pre-NEW-1 lock keyed on `total_lp_supply`). v2.2 is a fresh re-seed, so no legacy
//! pool exists on the v2.2 program; they are modelled because `record_floor_lock` handles them.
#![allow(dead_code)]
use super::{accrue_fees_inner, apply_minimum_liquidity_lock};
use crate::state::{StakePool, FLOOR_JUNIOR, FLOOR_SENIOR, MINIMUM_LIQUIDITY};
use bytemuck::Zeroable;

const M: u64 = MINIMUM_LIQUIDITY;

#[derive(Clone, Copy)]
struct Ghost {
    ds: u64,
    dj: u64,
    rs: u64,
    rj: u64,
    legacy: bool,
}

/// A symbolic pool consistent with the ghost. `cap` bounds the real LP (u64::MAX = full width).
/// Shapes: legacy (flags 0, one floor in either sub-pool, or empty), or flagged (any non-empty
/// subset of {senior, junior} floors; a flag is set iff that sub-pool holds its floor). A
/// non-tranche pool has no junior supply and (when flagged) only the senior floor, as
/// `process_deposit` / `process_deposit_junior` produce.
fn any_pool(cap: u64, real: bool) -> (StakePool, Ghost) {
    let mut p = StakePool::zeroed();
    let tranche: bool = kani::any();
    p.set_tranche_enabled(tranche);
    let legacy: bool = kani::any();
    let (ds, dj) = if legacy {
        let empty: bool = kani::any();
        let in_junior: bool = kani::any();
        kani::assume(!in_junior || tranche);
        if empty { (0, 0) } else if in_junior { (0, M) } else { (M, 0) }
    } else {
        let fs: bool = kani::any();
        let fj: bool = kani::any();
        kani::assume(fs || fj);
        kani::assume(tranche || (fs && !fj));
        p._reserved[61] = (if fs { FLOOR_SENIOR } else { 0 }) | (if fj { FLOOR_JUNIOR } else { 0 });
        (if fs { M } else { 0 }, if fj { M } else { 0 })
    };
    let (mut rs, mut rj) = (0u64, 0u64);
    if real {
        rs = kani::any();
        rj = kani::any();
        kani::assume(rs <= cap && rj <= cap);
        kani::assume(tranche || rj == 0);
        // A legacy pool's empty shape has no supply at all.
        kani::assume(!(legacy && ds + dj == 0) || (rs == 0 && rj == 0));
    }
    let junior = dj.checked_add(rj);
    kani::assume(junior.is_some());
    let total = junior.unwrap().checked_add(ds).and_then(|t| t.checked_add(rs));
    kani::assume(total.is_some());
    p.total_lp_supply = total.unwrap();
    p.set_junior_total_lp(junior.unwrap());
    (p, Ghost { ds, dj, rs, rj, legacy })
}

/// ST-7a (F3 for the REAL gate, R-1): over full-width u64 supplies and every pool shape, the
/// production gate `StakePool::has_real_lp_holders()` (AccrueFees F3, both mode-0 pre-accrue checks,
/// F-9 recovery) is exact: `real_lp_supply() == rs + rj` and the gate admits iff one real share
/// exists. On a flagged pool `real_senior_lp() / real_junior_lp()` are exact and `dead_lp()` is
/// the ghost. On legacy and non-tranche pools the gate equals the single-floor
/// `math::has_real_lp_holders(total)` (the premise of the kept `kani_f3_...` proof in tests/kani.rs);
/// on a tranche pool with two floors it does not, and the cover witnesses that state (2,000 dead LP,
/// math admits, the real gate refuses). Legacy `real_*_lp` keep the pre-fix routing (documented).
/// Mutant ST-M10 (`real_lp_supply` drops the junior floor). Cost S.
#[kani::proof]
fn kani_v22_st7a_real_gate_tranche_aware() {
    let (p, g) = any_pool(u64::MAX, true);
    let real = g.rs + g.rj;
    assert_eq!(p.real_lp_supply(), real, "real LP is exact on every shape");
    assert_eq!(p.has_real_lp_holders(), real > 0, "the gate admits iff a real share exists");
    if g.legacy {
        assert_eq!(p.dead_lp(), None);
        assert_eq!((p.real_senior_lp(), p.real_junior_lp()), (p.senior_total_lp(), p.junior_total_lp()));
    } else {
        assert_eq!(p.dead_lp(), Some((g.ds, g.dj)));
        assert_eq!((p.real_senior_lp(), p.real_junior_lp()), (g.rs, g.rj));
    }
    let single = crate::math::has_real_lp_holders(p.total_lp_supply);
    if g.legacy || !p.tranche_enabled() {
        assert_eq!(p.has_real_lp_holders(), single, "single-floor rule exact on legacy/non-tranche");
    }
    kani::cover!(
        p.tranche_enabled() && p.total_lp_supply == 2 * M && single && !p.has_real_lp_holders(),
        "two dead floors: single-floor rule admits, the real gate refuses (R-1)"
    );
    kani::cover!(!g.legacy && g.rs == 0 && g.rj > 0 && p.has_real_lp_holders(), "junior-only real holder admitted");
    kani::cover!(g.legacy && p.has_real_lp_holders(), "legacy admitted");
    kani::cover!(!p.tranche_enabled() && p.total_lp_supply == M && !p.has_real_lp_holders(), "non-tranche dead-only refused");
}

/// ST-7b (floor flags over symbolic pool histories). A real `StakePool` starts fresh or legacy
/// (ghost-consistent) and runs 3 symbolic steps: senior deposit, junior deposit, senior withdraw,
/// junior withdraw, enable tranches. Deposits follow `processor.rs` exactly: the lock keys on the
/// sub-pool supply (`senior_total_lp()` on a tranche pool, `total_lp_supply` otherwise; junior:
/// `junior_total_lp()`), the REAL `apply_minimum_liquidity_lock` decides the mint, the REAL
/// `record_floor_lock` runs when the sub-pool was empty, then the supplies increment by the full lp;
/// a withdrawal burns at most the real LP. After every step: a flagged pool has exactly the ghost
/// floors as bits (bit set iff that sub-pool holds its 1,000 dead shares; no other bit), flags never
/// clear, and `real_lp_supply / real_senior_lp / real_junior_lp` are exact; an unflagged pool is
/// empty or holds exactly one floor (legacy) and `real_lp_supply` is still exact. The legacy
/// inference (a lock on a legacy pool also records the OTHER sub-pool's pre-fix floor) is the
/// covered conversion. Mutant ST-M6 (drop the legacy other-bit). Cost M.
#[kani::proof]
#[kani::unwind(4)]
fn kani_v22_st7b_floor_flags_track_dead_shares() {
    let (mut p, mut g) = any_pool(u16::MAX as u64, true);
    let mut converted_via_junior = false;
    let mut converted_via_senior = false;
    let mut two_floors_no_holder = false;
    let mut k = 0;
    while k < 3 {
        let before = p.floor_flags();
        let was_legacy = before == 0 && p.total_lp_supply > 0;
        let op: u8 = kani::any();
        let lp = kani::any::<u16>() as u64;
        match op % 5 {
            0 => {
                let sb = if p.tranche_enabled() { p.senior_total_lp() } else { p.total_lp_supply };
                if let Ok(minted) = apply_minimum_liquidity_lock(sb, lp) {
                    if sb == 0 {
                        p.record_floor_lock(false);
                        g.ds = M;
                        converted_via_senior |= was_legacy;
                    }
                    p.total_lp_supply += lp;
                    g.rs += minted;
                }
            }
            1 => {
                if p.tranche_enabled() {
                    let jb = p.junior_total_lp();
                    if let Ok(minted) = apply_minimum_liquidity_lock(jb, lp) {
                        if jb == 0 {
                            p.record_floor_lock(true);
                            g.dj = M;
                            converted_via_junior |= was_legacy;
                        }
                        p.total_lp_supply += lp;
                        p.set_junior_total_lp(jb + lp);
                        g.rj += minted;
                    }
                }
            }
            2 => {
                let b = lp.min(g.rs);
                p.total_lp_supply -= b;
                g.rs -= b;
            }
            3 => {
                let b = lp.min(g.rj);
                p.total_lp_supply -= b;
                p.set_junior_total_lp(p.junior_total_lp() - b);
                g.rj -= b;
            }
            _ => p.set_tranche_enabled(true),
        }
        let f = p.floor_flags();
        assert_eq!(before & !f, 0, "a floor flag never clears");
        assert_eq!(p.real_lp_supply(), g.rs + g.rj, "real LP exact");
        assert_eq!(p.total_lp_supply, g.ds + g.dj + g.rs + g.rj);
        if f == 0 {
            assert!(g.ds + g.dj == if p.total_lp_supply == 0 { 0 } else { M }, "unflagged: empty or one legacy floor");
        } else {
            assert_eq!(f & !(FLOOR_SENIOR | FLOOR_JUNIOR), 0);
            assert_eq!(f & FLOOR_SENIOR != 0, g.ds == M, "senior bit iff senior holds its dead floor");
            assert_eq!(f & FLOOR_JUNIOR != 0, g.dj == M, "junior bit iff junior holds its dead floor");
            assert_eq!((p.real_senior_lp(), p.real_junior_lp()), (g.rs, g.rj));
        }
        two_floors_no_holder |= f == FLOOR_SENIOR | FLOOR_JUNIOR && !p.has_real_lp_holders();
        k += 1;
    }
    kani::cover!(converted_via_junior, "legacy senior floor recorded by a junior lock");
    kani::cover!(converted_via_senior, "legacy junior floor recorded by a senior lock");
    kani::cover!(two_floors_no_holder, "two floors, every real share burned: gate refuses");
}

/// ST-7c (real_lp_supply() == 0 => nothing booked). Every pool shape with no real LP, symbolic
/// mode (0/1), risk mode, cursor, armed bit, vault balance and wrapper counter: the REAL
/// `accrue_fees_inner` (the AccrueFees body and the Deposit/DepositJunior/Withdraw pre-accrue) books
/// nothing (`total_fees_earned`, `junior_balance`, pool value unchanged), and the REAL
/// `book_terminal_recovery` (F-9) books no fee leg (`to_fees == 0`). `process_accrue_fees`'
/// explicit refusal (error 29) is AccountInfo-level: LiteSVM row LS-R1a. Mutants ST-M8 (inner gate
/// back to `math::has_real_lp_holders(total)`), ST-M9 (F-9 gate back). Cost M.
#[kani::proof]
fn kani_v22_st7c_no_real_lp_nothing_booked() {
    let (mut p, g) = any_pool(0, false);
    p.pool_mode = kani::any::<bool>() as u8;
    p.risk_mode = kani::any();
    p.total_deposited = kani::any::<u32>() as u64;
    p.total_withdrawn = kani::any::<u32>() as u64;
    p.total_flushed = kani::any::<u32>() as u64;
    p.total_returned = kani::any::<u32>() as u64;
    p.total_fees_earned = kani::any::<u32>() as u64;
    p.total_recovered_from_wrapper = kani::any::<u32>() as u64;
    p.mode0_fees_attributed = kani::any::<u32>() as u64;
    p.set_fee_attribution_armed(kani::any());
    p.set_junior_balance(kani::any::<u32>() as u64);
    assert_eq!(p.real_lp_supply(), 0);
    let pv0 = p.total_pool_value();
    kani::assume(pv0.is_some());
    let (fees0, jb0) = (p.total_fees_earned, p.junior_balance());
    let bal = kani::any::<u32>() as u64;
    let paid: Option<u128> = if kani::any() { Some(kani::any::<u32>() as u128) } else { None };
    let mut q = p;
    let r = accrue_fees_inner(&mut q, bal, paid);
    if r.is_ok() {
        assert_eq!((q.total_fees_earned, q.junior_balance()), (fees0, jb0), "nothing booked");
        assert_eq!(q.total_pool_value(), pv0);
    }
    let mut t = p;
    let tr = t.book_terminal_recovery(bal);
    let t_ok = tr.is_ok();
    if let Ok((_, to_fees)) = tr {
        assert_eq!(to_fees, 0, "F-9 books no fee leg without real LP");
        assert_eq!((t.total_fees_earned, t.junior_balance()), (fees0, jb0));
    }
    kani::cover!(t_ok, "F-9 Ok reached (review round 3 T2)");
    let two = !g.legacy && g.ds == M && g.dj == M;
    kani::cover!(two && p.pool_mode == 1 && r.is_ok() && bal > pv0.unwrap(), "two floors, mode-1 surplus, skipped");
    kani::cover!(
        p.pool_mode == 0 && p.is_first_loss() && r.is_ok() && q.mode0_fees_attributed > p.mode0_fees_attributed,
        "S2 backlog consumed unbooked"
    );
    kani::cover!(two && bal > pv0.unwrap() + p.wrapper_recoverable(), "F-9 surplus beyond recoverable, no fee leg");
}

/// ST-7d (book_fee_delta routing + conservation). Flagged pools (every v2.2 pool), every shape with
/// a real holder (the callers' gate), symbolic balances, multiplier and fee: when the REAL
/// `book_fee_delta` succeeds, `total_fees_earned` and the pool value rise by exactly the fee, the
/// junior balance rises by `j <= fee` and the senior remainder is `fee - j`; `j > 0` only if tranches
/// are on and real junior LP exists; `fee - j > 0` only if real senior LP exists (so a dead-only
/// senior with real juniors gives the whole fee to junior). Legacy pools keep the pre-fix routing (a
/// legacy junior-genesis floor still takes a share; no legacy pool exists on v2.2) and are excluded.
/// Mutants ST-M7 (junior guard back to `junior_total_lp() > 0`), ST-M11 (`junior_takes_all` off).
/// Cost L (u128 split division).
#[kani::proof]
#[kani::solver(cadical)]
fn kani_v22_st7d_book_fee_delta_routes_to_real_holders() {
    let (mut p, g) = any_pool(u32::MAX as u64, true);
    kani::assume(!g.legacy && p.has_real_lp_holders());
    p.total_deposited = kani::any::<u32>() as u64;
    p.total_withdrawn = kani::any::<u32>() as u64;
    p.total_fees_earned = kani::any::<u32>() as u64;
    p.set_junior_balance(kani::any::<u32>() as u64);
    let mult: u16 = kani::any();
    kani::assume(mult <= 50_000);
    p.set_junior_fee_mult_bps(mult);
    let pv0 = p.total_pool_value();
    kani::assume(pv0.is_some() && p.senior_balance().is_some());
    let fee = kani::any::<u16>() as u64;
    kani::assume(fee > 0);
    let (fees0, jb0) = (p.total_fees_earned, p.junior_balance());
    let mut q = p;
    if q.book_fee_delta(fee).is_ok() {
        assert_eq!(q.total_fees_earned, fees0 + fee);
        assert_eq!(q.total_pool_value(), Some(pv0.unwrap() + fee), "the fee is conserved");
        assert!(q.junior_balance() >= jb0);
        let j = q.junior_balance() - jb0;
        assert!(j <= fee);
        if j > 0 {
            assert!(p.tranche_enabled() && g.rj > 0, "junior credited only with real junior LP");
        }
        if fee - j > 0 {
            assert!(g.rs > 0, "senior credited only with real senior LP");
        }
        kani::cover!(p.tranche_enabled() && g.dj == M && g.rj == 0 && jb0 > 0 && j == 0, "dead-only junior gets nothing");
        kani::cover!(p.tranche_enabled() && g.ds == M && g.rs == 0 && p.senior_balance().unwrap() > 0 && j == fee, "dead-only senior: all to junior");
        kani::cover!(g.rs > 0 && g.rj > 0 && j > 0 && j < fee, "both real: split");
        kani::cover!(!p.tranche_enabled() && j == 0, "non-tranche: all to senior");
    }
}
