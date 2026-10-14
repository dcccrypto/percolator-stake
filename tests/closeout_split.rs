//! CLOSE-OUT RULE (Khubair 2026-10-14 12:55, confirmed 13:36 and 19:35), every v5 pool mode:
//! at a market's close the creator gets back the insurance seed recorded at bind if intact,
//! else what is left of it, and never more; everything else goes to the stakers pro rata (booked
//! to the pool); with no real staker the rest is left unbooked in the vault and recorded as
//! unclaimed.
//!
//! Full-width proptests on the pure split (`math::closeout_creator_share` / `closeout_split`)
//! and on the REAL `StakePool` settlement path (`closeout_creator_share` +
//! `book_closeout_remainder`, the two calls RecoverTerminalInsurance makes), single and multi
//! call. `PROPTEST_CASES` overrides the per-block default (4,096).
//!
//! NEGATIVE CONTROLS (file copy, see the report): replacing `math::closeout_creator_share` with
//! the f372fa2 rule (whole surplus to the creator when no real staker / FEE_ONLY) or with the
//! 75dd991 rule (FIRST_LOSS creator class forwarded in full) fails these properties.

use bytemuck::Zeroable;
use percolator_stake::math::{closeout_creator_share, closeout_split};
use percolator_stake::state::{self, StakePool};
use proptest::prelude::*;

fn opt_released() -> impl Strategy<Value = Option<u64>> {
    prop_oneof![Just(None), any::<u64>().prop_map(Some)]
}

fn v5_pool(first_loss: bool) -> StakePool {
    let mut p = StakePool::zeroed();
    p.is_initialized = 1;
    p.set_discriminator();
    p.risk_mode = if first_loss {
        state::RISK_MODE_FIRST_LOSS
    } else {
        state::RISK_MODE_FEE_ONLY
    };
    p.set_fee_attribution_armed(true);
    p
}

// ─────────────────────────────────────────────────────────────────────────────
// Examples (the edge cases named in the brief)
// ─────────────────────────────────────────────────────────────────────────────

/// Balance below the seed: the creator gets what is there, the stakers 0 (both modes).
#[test]
fn closeout_balance_below_seed_creator_gets_all_of_it_stakers_zero() {
    for first_loss in [false, true] {
        let mut p = v5_pool(first_loss);
        p.total_deposited = 10_000_000;
        p.total_lp_supply = state::MINIMUM_LIQUIDITY + 10_000_000; // real stakers
        p.record_creator_seed(5_000_000);
        let v0 = p.total_pool_value().unwrap();
        let released = 3_000_000;
        let share = p.closeout_creator_share(released, None);
        assert_eq!(share, 3_000_000);
        let (r, f) = p.book_closeout_remainder(v0 + released - share).unwrap();
        assert_eq!((r, f), (0, 0), "stakers get nothing of the fund");
        assert_eq!(p.total_pool_value().unwrap(), v0, "staker principal untouched");
        assert_eq!(p.terminal_unclaimed_atoms(), 0);
    }
}

/// Zero real stakers: the creator gets at most the seed; growth and dust are NOT the creator's;
/// they stay unbooked in the vault and are recorded as unclaimed (not booked to dead shares).
#[test]
fn closeout_zero_stakers_creator_capped_rest_unclaimed() {
    for first_loss in [false, true] {
        for lp in [0, state::MINIMUM_LIQUIDITY] {
            let mut p = v5_pool(first_loss);
            p.total_deposited = state::MINIMUM_LIQUIDITY;
            p.total_lp_supply = lp;
            p.record_creator_seed(5_000_000);
            let v0 = p.total_pool_value().unwrap();
            let released = 7_000_001; // seed + growth + 1 atom of dust
            let share = p.closeout_creator_share(released, None);
            assert_eq!(share, 5_000_000, "never beyond the seed");
            let (r, f) = p.book_closeout_remainder(v0 + released - share).unwrap();
            assert_eq!((r, f), (0, 0));
            assert_eq!(p.total_pool_value().unwrap(), v0, "nothing booked to the dead shares");
            assert_eq!(p.total_fees_earned, 0);
            assert_eq!(p.terminal_unclaimed_atoms(), 2_000_001, "recorded unclaimed");
            // A later settlement cannot hand the unclaimed to the creator.
            let surplus = 2_000_001;
            p.set_creator_surplus_forwarded_atoms(share);
            assert_eq!(p.closeout_creator_share(surplus, None), 0);
        }
    }
}

/// Pools bound before this build (no record): the creator is owed nothing; with stakers they
/// get the whole fund, without it is unclaimed. Never paid to the creator on a guess.
#[test]
fn closeout_no_seed_record_creator_owed_nothing() {
    let mut p = v5_pool(false);
    p.total_deposited = 1_000_000_000;
    p.total_lp_supply = state::MINIMUM_LIQUIDITY + 1_000_000_000;
    p._v5_reserved[state::V5_RESERVED_CREATOR_SEED].copy_from_slice(&[0xff; 7]); // bytes, no flag
    assert_eq!(p.closeout_creator_share(4_547_246, None), 0);
    let v0 = p.total_pool_value().unwrap();
    let (r, f) = p.book_closeout_remainder(v0 + 4_547_246).unwrap();
    assert_eq!(r + f, 4_547_246);
}

/// Unitised FIRST_LOSS: the wrapper pays the stake class first (booked to stakers), then the
/// creator class; the creator gets min(seed, creator class released) and the growth on creator
/// units goes to the stakers. Worked example: seed 5M, creator units grew to 6M, stake units 4M
/// (principal 4M): creator 5M, stakers 4M principal + 1M growth.
#[test]
fn closeout_first_loss_growth_on_creator_units_goes_to_stakers() {
    let mut p = v5_pool(true);
    p.total_deposited = 10_000_000;
    p.total_flushed = 4_000_000;
    p.total_lp_supply = state::MINIMUM_LIQUIDITY + 10_000_000;
    p.record_creator_seed(5_000_000);
    let v0 = p.total_pool_value().unwrap();
    // Call 1: 4M = the stake class only (creator class released 0).
    let s1 = p.closeout_creator_share(4_000_000, Some(0));
    assert_eq!(s1, 0);
    p.book_closeout_remainder(v0 + 4_000_000).unwrap();
    assert_eq!(p.total_pool_value().unwrap(), v0 + 4_000_000, "principal back to stakers");
    // Call 2: 6M of creator class.
    let v1 = p.total_pool_value().unwrap();
    let s2 = p.closeout_creator_share(6_000_000, Some(6_000_000));
    assert_eq!(s2, 5_000_000, "creator capped at the seed");
    p.set_creator_surplus_forwarded_atoms(s2);
    p.book_closeout_remainder(v1 + 6_000_000 - s2).unwrap();
    assert_eq!(p.total_pool_value().unwrap(), v1 + 1_000_000, "creator-unit growth to stakers");
    // Loss case: creator class worth only 3M (pro-rata loss): the creator gets 3M.
    let q = {
        let mut q = v5_pool(true);
        q.record_creator_seed(5_000_000);
        q
    };
    assert_eq!(q.closeout_creator_share(9_000_000, Some(3_000_000)), 3_000_000);
}

// ─────────────────────────────────────────────────────────────────────────────
// Full-width proptests
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// The pure split, full u64 range: conserved to the atom; creator <= surplus; creator never
    /// beyond the seed cumulatively (`forwarded + creator <= seed` whenever `forwarded <= seed`,
    /// and 0 once `forwarded >= seed`); creator <= creator class released - forwarded on a
    /// unitised market; zero stakers -> stakers 0; never both stakers and unclaimed.
    #[test]
    fn closeout_math_full_width(
        surplus in any::<u64>(),
        seed in any::<u64>(),
        forwarded in any::<u64>(),
        released in opt_released(),
        real in any::<bool>(),
    ) {
        let (c, s, u) = closeout_split(surplus, seed, forwarded, released, real);
        prop_assert_eq!(c as u128 + s as u128 + u as u128, surplus as u128, "conserved");
        prop_assert!(c <= surplus);
        prop_assert_eq!(c, closeout_creator_share(surplus, seed, forwarded, released));
        prop_assert!(forwarded as u128 + c as u128 <= (seed as u128).max(forwarded as u128),
            "creator never beyond the seed");
        if forwarded >= seed { prop_assert_eq!(c, 0); }
        if let Some(r) = released {
            prop_assert!(c <= r.saturating_sub(forwarded), "never beyond the creator class");
        }
        if !real { prop_assert_eq!(s, 0); prop_assert_eq!(u, surplus - c); }
        else { prop_assert_eq!(u, 0); }
        // Exact formula.
        let cap = released.map_or(seed, |r| seed.min(r));
        prop_assert_eq!(c, surplus.min(cap.saturating_sub(forwarded)));
    }

    /// One settlement on the REAL pool (wide state): from a fully booked pool the wrapper
    /// releases `released`; the creator is paid `closeout_creator_share`; the rest goes through
    /// `book_closeout_remainder`. Booked staker value never falls (I-S1); every released atom is
    /// the creator's, booked, or recorded unclaimed (exactly); zero real stakers books nothing.
    #[test]
    fn closeout_single_settlement_real_pool(
        first_loss in any::<bool>(),
        deposited in 0u64..1u64 << 62,
        withdrawn_frac in 0u64..=1_000,
        flushed_frac in 0u64..=1_000,
        returned_frac in 0u64..=1_000,
        recovered_frac in 0u64..=1_000,
        fees in 0u64..1u64 << 60,
        // Half the cases around the dead-share floor (zero real stakers / one real share).
        lp in prop_oneof![0u64..=2 * state::MINIMUM_LIQUIDITY, 0u64..1u64 << 62],
        released in 0u64..1u64 << 62,
        seed in any::<u64>(),
        recorded in any::<bool>(),
        fwd_448 in 0u64..1u64 << 62,
        fwd_464 in 0u64..1u64 << 62,
        creator_class in opt_released(),
        backlog in any::<u64>(),
    ) {
        let mut p = v5_pool(first_loss);
        p.total_deposited = deposited;
        p.total_withdrawn = deposited / 1_000 * withdrawn_frac;
        let live = deposited - p.total_withdrawn;
        p.total_flushed = if first_loss { live / 1_000 * flushed_frac } else { 0 };
        p.total_returned = p.total_flushed / 1_000 * returned_frac;
        p.total_recovered_from_wrapper = p.total_returned / 1_000 * recovered_frac;
        p.total_fees_earned = fees;
        p.total_lp_supply = lp;
        p.set_s2_backlog_owed_atoms(backlog);
        if recorded { p.record_creator_seed(seed); }
        p.creator_forwarded_atoms = fwd_448;
        p.set_creator_surplus_forwarded_atoms(fwd_464);
        let seed_eff = if recorded { seed.min(state::CREATOR_SEED_MAX) } else { 0 };
        let creator_class = if first_loss { creator_class } else { None };
        let v0 = p.total_pool_value().unwrap();
        let real = p.has_real_lp_holders();
        let balance = v0 + released;
        let share = p.closeout_creator_share(released, creator_class);
        let (r, f) = p.book_closeout_remainder(balance - share).unwrap();
        let v1 = p.total_pool_value().unwrap();
        let unclaimed = p.terminal_unclaimed_atoms();
        prop_assert!(v1 >= v0, "I-S1: booked staker value never falls");
        prop_assert_eq!(v1 - v0, r + f);
        prop_assert_eq!(share as u128 + (r + f) as u128 + unclaimed as u128, released as u128,
            "conserved to the atom");
        prop_assert!(share as u128 + (fwd_448 as u128 + fwd_464 as u128)
            <= (seed_eff as u128).max(fwd_448 as u128 + fwd_464 as u128), "never beyond the seed");
        if let Some(cc) = creator_class { prop_assert!(share <= cc); }
        if !recorded { prop_assert_eq!(share, 0, "no record: nothing to the creator"); }
        if real { prop_assert_eq!(unclaimed, 0); }
        else {
            prop_assert_eq!(v1, v0, "zero real stakers: nothing booked");
            prop_assert_eq!(unclaimed, released - share);
        }
    }

    /// Several partial settlements (the wrapper releases the fund in up to 8 chunks, as partial
    /// tag-29 calls do), FEE_ONLY or unitised FIRST_LOSS (stake class paid first, then creator
    /// class), with or without real stakers: after all calls the creator's total is EXACTLY
    /// `min(seed, total released)` (FEE_ONLY) / `min(seed, creator class released)` (FIRST_LOSS),
    /// independent of the chunking; it never exceeds the seed at any step; and creator + booked +
    /// unclaimed == released, to the atom.
    #[test]
    fn closeout_multi_call_conserves(
        first_loss in any::<bool>(),
        real in any::<bool>(),
        seed in 0u64..1u64 << 56,
        stake_class in 0u64..1u64 << 58,
        creator_class in 0u64..1u64 << 58,
        principal in 0u64..1u64 << 58,
        cuts in proptest::collection::vec(0u64..=10_000, 1..8),
    ) {
        let mut p = v5_pool(first_loss);
        p.total_deposited = principal + state::MINIMUM_LIQUIDITY;
        p.total_flushed = if first_loss { principal } else { 0 };
        p.total_lp_supply = if real { principal + 2 * state::MINIMUM_LIQUIDITY } else { state::MINIMUM_LIQUIDITY };
        p.record_creator_seed(seed);
        let fund = if first_loss { stake_class + creator_class } else { creator_class };
        let v0 = p.total_pool_value().unwrap();
        let mut balance = v0; // the vault, fully booked
        let mut released_cum = 0u64;
        let mut creator_total = 0u64;
        let total_cuts: u64 = cuts.iter().sum::<u64>().max(1);
        let mut acc = 0u64;
        for (i, c) in cuts.iter().enumerate() {
            acc += c;
            // Cumulative release after this call (the last call releases the rest of the fund).
            let target = if i + 1 == cuts.len() { fund } else {
                ((fund as u128 * acc as u128) / total_cuts as u128) as u64
            };
            let chunk = target - released_cum;
            released_cum = target;
            balance += chunk;
            let cc_released = if first_loss { Some(released_cum.saturating_sub(stake_class)) } else { None };
            let surplus = balance - p.total_pool_value().unwrap();
            let share = p.closeout_creator_share(surplus, cc_released);
            prop_assert!(share <= surplus);
            balance -= share;
            creator_total += share;
            p.set_creator_surplus_forwarded_atoms(p.creator_surplus_forwarded_atoms() + share);
            prop_assert!(creator_total <= seed, "never beyond the seed, at any step");
            p.book_closeout_remainder(balance).unwrap();
            prop_assert!(p.total_pool_value().unwrap() <= balance);
        }
        let want = if first_loss { seed.min(creator_class) } else { seed.min(fund) };
        prop_assert_eq!(creator_total, want, "exact creator total, independent of chunking");
        let booked = p.total_pool_value().unwrap() - v0;
        let unclaimed = p.terminal_unclaimed_atoms();
        prop_assert_eq!(creator_total as u128 + booked as u128 + unclaimed as u128, fund as u128,
            "conserved to the atom over all calls");
        prop_assert_eq!(balance, p.total_pool_value().unwrap() + unclaimed, "vault == books + unclaimed");
        if real { prop_assert_eq!(unclaimed, 0); } else { prop_assert_eq!(booked, 0); }
    }
}
