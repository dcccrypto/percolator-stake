//! ST-3 harnesses. Bounds: u32 operands cast up (products < 2^64, exact in u128). The full-width
//! claim is the identity of the two formulas (both `floor(a*U/I)` resp. `ceil(r*U/I)` over the
//! same checked u128 product), stated as the paper width-lift.
//! Run: `cargo kani --features devnet -Z function-contracts -Z stubbing --harness proofs::<h> --exact`.
use crate::math::{expected_recover_burn, expected_topup_units};
use crate::p4_rescue_ins::{ins_units_for_topup, ins_units_reset_needed, ins_units_to_burn};

/// ST-3a: `expected_topup_units(a, U, I) == ins_units_for_topup(a, U, I)` whenever the wrapper
/// computes it (`U == 0` genesis, or `U > 0 ∧ I > 0`); in the RESET case (`U > 0 ∧ I == 0`,
/// `ins_units_reset_needed`) the wrapper resets the ledger first, so the stake value equals the
/// wrapper's genesis mint `ins_units_for_topup(a, 0, I) == a`.
/// Mutant (rev2 R4.5 stake row 2): stake topup rounds up (ceil) ⇒ the equality fails.
#[kani::proof]
#[kani::solver(cadical)]
fn st3_topup_units_match_wrapper() {
    let a: u32 = kani::any();
    let u: u32 = kani::any();
    let i: u32 = kani::any();
    let (a, u, i) = (a as u64, u as u128, i as u128);
    let stake = expected_topup_units(a, u, i);
    if ins_units_reset_needed(u, i) {
        kani::cover!(true, "reset arm (U > 0, I_mint == 0)");
        assert_eq!(stake, ins_units_for_topup(a as u128, 0, i));
        assert_eq!(stake, Some(a as u128));
    } else {
        kani::cover!(u == 0, "genesis arm");
        kani::cover!(u > 0 && i > 0 && stake != Some(a as u128), "pro-rata arm, not 1:1");
        assert_eq!(stake, ins_units_for_topup(a as u128, u, i));
    }
}

/// ST-3b: `expected_recover_burn(r, U, I_free) == ins_units_to_burn(r, U, I_free)` for every
/// input (both `None` when `U == 0`, `I_free == 0` or `r > I_free`; otherwise both
/// `ceil(r*U/I_free)`, which is `<= U` because `r <= I_free`).
/// Mutant (rev2 R4.5 stake row 3): stake burn rounds down (floor) ⇒ the equality fails.
#[kani::proof]
#[kani::solver(cadical)]
fn st3_recover_burn_matches_wrapper() {
    let r: u32 = kani::any();
    let u: u32 = kani::any();
    let i: u32 = kani::any();
    let (r, u, i) = (r as u64, u as u128, i as u128);
    let stake = expected_recover_burn(r, u, i);
    kani::cover!(stake.is_some(), "a burn is computed");
    kani::cover!(stake.is_none() && u > 0 && i > 0, "r above I_free refused");
    kani::cover!(
        stake.is_some_and(|b| b * i != r as u128 * u),
        "inexact division (the ceil rounds up)"
    );
    assert_eq!(stake, ins_units_to_burn(r as u128, u, i));
}
