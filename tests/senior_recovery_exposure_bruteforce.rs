//! Exhaustive check of `StakePool::senior_recovery_exposure()` against ground
//! truth: "does SOME legal `RecoverFlushedInsurance` raise `senior_balance()`?"
//!
//! Two sweeps, and the difference between them is the honest cost of this gate.
//!
//! `bruteforce_senior_exposure` assumes the wrapper insurance fund can actually pay
//! out `wrapper_recoverable()`. Under that assumption the predicate is EXACT: zero
//! over-blocks and zero under-blocks across 1_861_461 reachable states, where the
//! blunt `wrapper_recoverable() > 0` has 55_440 over-blocks (the junior-absorbed
//! carve-out) and the bare `net_loss > junior_balance()` has under-blocks.
//!
//! `bruteforce_over_blocks_when_the_wrapper_cannot_pay` drops that assumption, and
//! is the test that keeps this file honest. `wrapper_recoverable()` is a COUNTER,
//! not a balance. After a genuine insurance loss the wrapper holds nothing while the
//! counter still reads the whole flush, no recovery is physically possible, no snipe
//! exists — and the gate fires anyway. That over-block is shared verbatim with the
//! shipped A-H2 gate (`wrapper_recoverable() > 0`) and is only fixable by
//! reconciling the counter against the bound market's real insurance balance. See
//! `tests/ah3_accounting_fix_analysis.rs`.
use bytemuck::Zeroable;
use percolator_stake::state::StakePool;

fn mk(d: u64, w: u64, f: u64, a: u64, c: u64, j: u64, jb: u64) -> StakePool {
    let mut p = StakePool::zeroed();
    p.set_discriminator();
    p.total_deposited = d;
    p.total_withdrawn = w;
    p.total_flushed = f;
    p.total_returned = c + a + j;
    p.total_recovered_from_wrapper = c;
    p.set_realized_junior_loss(j);
    p.set_tranche_enabled(true);
    p.set_junior_balance(jb);
    p
}

/// Candidate gate.
fn exposed(p: &StakePool) -> bool {
    let net = p.total_flushed.saturating_sub(p.total_returned);
    let rec = p.wrapper_recoverable();
    rec > 0 && (rec > net || net > p.junior_balance())
}

#[test]
fn bruteforce_senior_exposure() {
    let mut checked = 0u64;
    let mut over = 0u64;
    let mut under = 0u64;
    let mut first_over = String::new();
    let mut first_under = String::new();
    let (mut blunt_over, mut blunt_under) = (0u64, 0u64);
    let (mut n159_over, mut n159_under) = (0u64, 0u64);
    let mut first_blunt_over = String::new();
    let mut first_n159_under = String::new();

    let d = 40u64;
    for w in [0u64, 5, 10] {
        for f in 0..=20u64 {
            for a in 0..=20u64 {
                for c in 0..=20u64 {
                    for j in 0..=8u64 {
                        if c + j > f {
                            continue;
                        } // wrapper_recoverable >= 0
                        if a + c + j > f + 20 {
                            continue;
                        } // keep it sane
                        for jb in 0..=20u64 {
                            if jb > d - w {
                                continue;
                            }
                            let p = mk(d, w, f, a, c, j, jb);
                            let sb0 = match p.senior_balance() {
                                Some(v) => v,
                                None => continue,
                            };
                            checked += 1;
                            let rec = p.wrapper_recoverable();
                            // ground truth: does ANY legal recovery raise senior_balance()?
                            let mut truth = false;
                            let mut worst = 0u64;
                            for amt in 1..=rec {
                                let mut q = p;
                                q.total_returned += amt;
                                q.total_recovered_from_wrapper += amt;
                                if let Some(sb1) = q.senior_balance() {
                                    if sb1 > sb0 {
                                        truth = true;
                                        worst = worst.max(sb1 - sb0);
                                    }
                                }
                            }
                            let g = exposed(&p);
                            if g && !truth {
                                over += 1;
                                if first_over.is_empty() {
                                    first_over = format!("OVER f={f} a={a} c={c} j={j} jb={jb} w={w} rec={rec} net={} sb0={sb0}", f.saturating_sub(p.total_returned));
                                }
                            }
                            let blunt = rec > 0;
                            let n159 = p.total_flushed.saturating_sub(p.total_returned)
                                > p.junior_balance();
                            if blunt && !truth {
                                blunt_over += 1;
                                if first_blunt_over.is_empty() {
                                    first_blunt_over =
                                        format!("f={f} a={a} c={c} j={j} jb={jb} w={w} rec={rec}");
                                }
                            }
                            if !blunt && truth {
                                blunt_under += 1;
                            }
                            if n159 && !truth {
                                n159_over += 1;
                            }
                            if !n159 && truth {
                                n159_under += 1;
                                if first_n159_under.is_empty() {
                                    first_n159_under = format!("f={f} a={a} c={c} j={j} jb={jb} w={w} rec={rec} gain={worst}");
                                }
                            }
                            if !g && truth {
                                under += 1;
                                if first_under.is_empty() {
                                    first_under = format!("UNDER f={f} a={a} c={c} j={j} jb={jb} w={w} rec={rec} gain={worst} sb0={sb0}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    println!("checked={checked} over={over} under={under}");
    println!("BLUNT   over={blunt_over} under={blunt_under}");
    println!("N159    over={n159_over} under={n159_under}");
    println!("first blunt over: {first_blunt_over}");
    println!("first n159 under: {first_n159_under}");
    println!("{first_over}");
    println!("{first_under}");
    assert_eq!(under, 0, "UNDER-BLOCK: {first_under}");
    assert_eq!(over, 0, "OVER-BLOCK: {first_over}");

    // The carve-out must actually be load-bearing, or this sweep proves nothing.
    assert!(
        blunt_over > 50_000,
        "the blunt form must over-block substantially, else the carve-out is moot"
    );
    assert!(
        n159_under > 0,
        "the old form must under-block, else there was no bug to fix"
    );
}

/// **The over-block the sweep above cannot see.** `wrapper_recoverable()` counts what
/// the ACCOUNTING says is recoverable; it never consults the wrapper's real balance.
/// When the market has consumed the insurance fund, `RecoverFlushedInsurance` reverts
/// forever, so ground-truth exposure is ZERO in every such state — yet the gate is
/// permanently shut.
///
/// This is not a defect introduced by the senior gate: the shipped A-H2 gate
/// (`wrapper_recoverable() > 0`) over-blocks on a strict SUPERSET of these states.
/// Both are fixed by the same follow-up (permissionless reconciliation against the
/// bound market), not by weakening either predicate.
#[test]
fn bruteforce_over_blocks_when_the_wrapper_cannot_pay() {
    let mut gate_fires_but_wrapper_empty = 0u64;
    let mut a_h2_also_fires = 0u64;
    let d = 40u64;
    for f in 1..=20u64 {
        for a in 0..=20u64 {
            for c in 0..=20u64 {
                for j in 0..=8u64 {
                    if c + j > f {
                        continue;
                    }
                    for jb in 0..=20u64 {
                        if jb > d {
                            continue;
                        }
                        let p = mk(d, 0, f, a, c, j, jb);
                        if p.senior_balance().is_none() {
                            continue;
                        }
                        // Wrapper insurance fund is EMPTY: no recovery can execute,
                        // so true exposure is 0 whatever the counters say.
                        if exposed(&p) {
                            gate_fires_but_wrapper_empty += 1;
                            if p.wrapper_recoverable() > 0 {
                                a_h2_also_fires += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    println!(
        "wrapper-empty over-blocks: senior gate {gate_fires_but_wrapper_empty}, \
         of which A-H2's blunt gate also fires on {a_h2_also_fires}"
    );
    assert!(
        gate_fires_but_wrapper_empty > 0,
        "this over-block is real and must be reported, not hidden"
    );
    assert_eq!(
        gate_fires_but_wrapper_empty, a_h2_also_fires,
        "every state where the SENIOR gate over-blocks on an empty wrapper is one \
         where the already-shipped A-H2 gate over-blocks too — the senior gate adds \
         no new class of over-block, only the tranche-arm instance of an existing one"
    );
}
