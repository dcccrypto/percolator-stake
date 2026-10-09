//! Kani v2.2 final run, stake NEW-1 (per-tranche MINIMUM_LIQUIDITY dead-share floor, `b83ddf9`).
//! PROOF-ONLY: a `cfg(kani)` child module of `processor`, hooked at the very END of
//! `src/processor.rs` (no production line moves; the SBF build never compiles it, G-ART).
//! It reaches the private `apply_minimum_liquidity_lock` through `super::`.
#![allow(dead_code)]
use super::apply_minimum_liquidity_lock;
use crate::math::{
    calc_junior_collateral_for_withdraw, calc_junior_lp_for_deposit, calc_senior_collateral_for_withdraw,
    calc_senior_lp_for_deposit,
};
use crate::state::MINIMUM_LIQUIDITY;

/// ST-6a: the real lock. Not a (sub-)pool genesis (`supply_before != 0`) => the full amount is
/// minted; at a genesis a computed mint <= MINIMUM_LIQUIDITY is refused (error 28) and a larger one
/// mints `lp - MINIMUM_LIQUIDITY` (the dead shares are counted in supply, never minted). Full u64.
/// Mutant ST-M5 (lock disabled). Cost S.
#[kani::proof]
fn kani_v22_st6a_minimum_liquidity_lock() {
    let supply: u64 = kani::any();
    let lp: u64 = kani::any();
    let r = apply_minimum_liquidity_lock(supply, lp);
    if supply != 0 {
        assert_eq!(r, Ok(lp));
    } else if lp <= MINIMUM_LIQUIDITY {
        assert!(r.is_err(), "first deposit <= 1,000 into an empty (sub-)pool refused");
    } else {
        assert_eq!(r, Ok(lp - MINIMUM_LIQUIDITY));
    }
    kani::cover!(supply == 0 && lp == MINIMUM_LIQUIDITY && r.is_err(), "exact-1,000 genesis refused");
    kani::cover!(supply == 0 && lp > MINIMUM_LIQUIDITY && r.is_ok(), "genesis locks the floor");
    kani::cover!(supply != 0 && r == Ok(lp), "non-genesis mints in full");
}

#[derive(Clone, Copy)]
struct Sub {
    supply: u64, // junior_total_lp or senior_total_lp (incl. dead shares)
    held: u64,   // SPL-minted LP held by users (the only LP Withdraw can burn)
    bal: u64,    // the sub-pool's balance
}

/// ST-6b (NEW-1, model-level: the processor's counter updates are modelled, every price and the lock
/// are the REAL functions). On a tranche pool each sub-pool (junior: DepositJunior keyed on
/// `junior_total_lp`; senior: Deposit keyed on `senior_total_lp`) follows `processor.rs`: the lock
/// keys on THAT sub-pool's supply; supply += lp (pre-lock), held += minted (post-lock); a withdrawal
/// burns at most `held`. Invariant after every step of a 3-step symbolic sequence: the sub-pool is
/// either empty (supply == held == 0) or its supply is >= 1,000 with exactly 1,000 dead shares
/// (`supply - held == 1,000`), so once set the floor never decreases and a sub-pool never returns
/// to supply 0; a first deposit whose computed mint is <= 1,000 is refused. u16 amounts, 3 steps.
/// Mutant ST-M5 (lock disabled). The processor's KEY choice (junior_total_lp / senior_total_lp vs
/// total_lp_supply) is processor code this model does not execute: its revert is the LiteSVM
/// mutant LS-NEW1a/b (`kani/mutants/v22/stake_litesvm.tsv`). Cost M.
#[kani::proof]
#[kani::unwind(4)]
#[kani::solver(cadical)]
fn kani_v22_st6b_tranche_floor_never_decreases() {
    let mut subs = [Sub { supply: 0, held: 0, bal: 0 }; 2]; // [junior, senior]
    let mut refused_small_genesis = false;
    let mut floor_set_then_drained = false;
    let mut senior_after_junior = false;
    let mut k = 0;
    while k < 3 {
        let which: bool = kani::any();
        let i = which as usize; // 0 junior, 1 senior
        let deposit: bool = kani::any();
        let amt = kani::any::<u16>() as u64;
        let s = subs[i];
        if deposit {
            let lp = if i == 0 {
                calc_junior_lp_for_deposit(s.supply, s.bal, amt)
            } else {
                calc_senior_lp_for_deposit(s.supply, s.bal, amt)
            };
            if let Some(lp) = lp {
                if lp > 0 {
                    match apply_minimum_liquidity_lock(s.supply, lp) {
                        Ok(minted) => {
                            if i == 1 && subs[0].supply != 0 && s.supply == 0 {
                                senior_after_junior = true;
                            }
                            subs[i] = Sub { supply: s.supply + lp, held: s.held + minted, bal: s.bal + amt };
                        }
                        Err(_) => {
                            assert!(s.supply == 0 && lp <= MINIMUM_LIQUIDITY);
                            refused_small_genesis = true;
                        }
                    }
                }
            }
        } else if s.held > 0 {
            let burn = amt.min(s.held);
            let pay = if i == 0 {
                calc_junior_collateral_for_withdraw(s.supply, s.bal, burn)
            } else {
                calc_senior_collateral_for_withdraw(s.supply, s.bal, burn)
            };
            if let Some(pay) = pay {
                if burn > 0 && pay <= s.bal {
                    subs[i] = Sub { supply: s.supply - burn, held: s.held - burn, bal: s.bal - pay };
                    if subs[i].held == 0 {
                        floor_set_then_drained = true;
                    }
                }
            }
        }
        for t in subs.iter() {
            assert!(
                (t.supply == 0 && t.held == 0) || (t.supply >= MINIMUM_LIQUIDITY && t.supply - t.held == MINIMUM_LIQUIDITY),
                "a sub-pool is empty or carries exactly the 1,000 dead shares"
            );
        }
        k += 1;
    }
    kani::cover!(refused_small_genesis, "first sub-pool deposit <= 1,000 refused");
    kani::cover!(floor_set_then_drained && subs.iter().any(|t| t.supply == MINIMUM_LIQUIDITY), "every real share burned: supply stays 1,000");
    kani::cover!(senior_after_junior, "senior sub-pool genesis after a junior genesis locks its own floor");
}
