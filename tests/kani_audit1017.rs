//! v2.2 full audit 2026-10-17, workstream K: full-width (u64/u128) close-out proofs. The existing
//! `kani_closeout_*` rows quantify u32 values standing for u64 amounts; these functions are pure
//! `min` / `saturating_sub` / subtraction (no multiplication), so the full width costs nothing.
//! Real production fns from `percolator_stake::math`. cfg(kani) only.
#![cfg(kani)]

use percolator_stake::math::{closeout_creator_share, closeout_split, creator_seed_at_bind};

/// K-S1: one close-out settlement splits `surplus` EXACTLY (creator + stakers + unclaimed), the
/// creator can never be sent more than the seed over any number of partial settlements
/// (`forwarded + creator <= seed`, and `<= released` for a unitised first-loss pool), and stakers
/// and unclaimed are never both non-zero (no real staker => nothing is booked to the dead shares).
#[kani::proof]
fn kani_audit1017_s1_closeout_split_exact_full_width() {
    let surplus: u64 = kani::any();
    let seed: u64 = kani::any();
    let forwarded: u64 = kani::any();
    let released: u64 = kani::any();
    let unitised: bool = kani::any();
    let real_stakers: bool = kani::any();
    // invariant of the record: the creator was never sent more than the entitlement so far
    let cc = if unitised { Some(released) } else { None };
    kani::assume(forwarded <= seed);
    if unitised {
        kani::assume(forwarded <= released);
    }
    let (c, s, u) = closeout_split(surplus, seed, forwarded, cc, real_stakers);
    assert!(c as u128 + s as u128 + u as u128 == surplus as u128);
    assert!(c <= surplus);
    assert!(forwarded as u128 + c as u128 <= seed as u128);
    if unitised {
        assert!(forwarded as u128 + c as u128 <= released as u128);
    }
    assert!(s == 0 || u == 0);
    if real_stakers {
        assert!(u == 0);
    } else {
        assert!(s == 0);
    }
    // the creator gets the full remaining entitlement whenever the surplus covers it
    let entitled = if unitised { seed.min(released) } else { seed };
    assert!(c == surplus.min(entitled - forwarded));
    assert!(c == closeout_creator_share(surplus, seed, forwarded, cc));
    kani::cover!(c > 0 && s > 0, "creator and stakers both paid");
    kani::cover!(c > 0 && !real_stakers && u > 0, "creator paid, remainder unclaimed (no real staker)");
    kani::cover!(c == 0 && surplus > 0 && entitled == forwarded, "entitlement exhausted: creator gets nothing more");
    kani::cover!(unitised && released < seed && c > 0, "unitised pool capped by released units");
}

/// K-S2: the creator's seed measured at bind is bounded by every claim it must exclude, at full
/// u128 width: asset-0 budget, insurance minus the global reservation, and the vault.
#[kani::proof]
fn kani_audit1017_s2_seed_at_bind_bounded_by_own_money() {
    let insurance: u128 = kani::any();
    let vault: u128 = kani::any();
    let reserved: u128 = kani::any();
    let budget: u128 = kani::any();
    let net_deployed: u64 = kani::any();
    let seed = creator_seed_at_bind(insurance, vault, reserved, budget, net_deployed) as u128;
    assert!(seed <= budget.saturating_sub(reserved));
    assert!(seed <= insurance.saturating_sub(reserved));
    assert!(seed <= vault);
    assert!(seed <= u64::MAX as u128);
    kani::cover!(seed > 0, "positive seed");
    kani::cover!(seed == 0 && budget > 0, "zero seed although a budget exists (reservation or deployment)");
    kani::cover!(net_deployed > 0 && seed > 0, "deployed principal subtracted");
}
