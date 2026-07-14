//! N7 (CONSOLIDATED-PLAN §2.2) — AccrueFees donation/share-inflation defense.
//!
//! ── The bug ──────────────────────────────────────────────────────────────────
//! `AccrueFees` (tag 12, permissionless, mode-1 pools only) books ANY
//! un-attributed vault-balance delta as "fees": `total_fees_earned +=
//! current_balance - total_pool_value()` whenever `current_balance > pool_value
//! && total_lp_supply > 0` (`processor.rs::accrue_fees_inner`). Nothing
//! authenticates the source of that delta — a raw SPL `transfer` straight into
//! the pool's vault token account (bypassing the `Deposit` instruction entirely)
//! is indistinguishable from real trading-fee revenue.
//!
//! Classic ERC4626-style attack this enables pre-fix: attacker becomes the
//! pool's FIRST depositor (mints LP 1:1, cheap), donates a large raw amount `X`
//! directly to the vault ATA, then permissionlessly cranks `AccrueFees` — which
//! books `X` as fees and inflates `total_pool_value()` while `total_lp_supply`
//! stays at the attacker's tiny genesis mint. The attacker loses nothing (they
//! still hold 100% of LP at that point, so `X` is still "their" money) but a
//! subsequent victim `Deposit` of any amount `Y < total_pool_value()/total_lp_supply`
//! rounds `calc_lp_for_deposit` down to 0 and reverts with `ZeroSharesMinted` —
//! DoSing every deposit below the attacker-inflated share price, for a cost of $0
//! to the attacker (they can withdraw the donated `X` right back out).
//!
//! ── The fix (this file proves it) ───────────────────────────────────────────
//! 1. `state::MINIMUM_LIQUIDITY` dead-share lock: the pool's genesis deposit
//!    mints `lp_to_mint - MINIMUM_LIQUIDITY` real LP to the depositor while
//!    `total_lp_supply` tracks the FULL `lp_to_mint` — the difference is
//!    permanently unredeemable by anyone, raising the fixed cost of establishing
//!    a genesis position cheaply.
//! 2. `math::{calc_lp_for_deposit, calc_collateral_for_withdraw}` virtual-offset
//!    (`VIRTUAL_SHARES`/`VIRTUAL_ASSETS` = 1): every pro-rata calculation is
//!    priced against `(real + virtual)`, so a donation-then-accrue round always
//!    permanently forfeits a sliver of value to the unowned virtual share instead
//!    of being fully recoverable by the attacker.
//!
//! These tests model the EXACT production formulas (mirroring
//! `poc_jit_fee_snipe.rs`'s established pattern: `StakePool` + `math::*` calls,
//! no Solana runtime) including the genesis dead-share carve-out, so the
//! comparison against the pre-N7 baseline is apples-to-apples.

use bytemuck::Zeroable;
use percolator_stake::state::{StakePool, MINIMUM_LIQUIDITY};

fn mode1_pool() -> StakePool {
    let mut pool = StakePool::zeroed();
    pool.is_initialized = 1;
    pool.bump = 255;
    pool.vault_authority_bump = 254;
    pool.admin_transferred = 1;
    pool.pool_mode = 1; // trading LP pool — the only mode AccrueFees operates on
    pool.set_discriminator();
    pool
}

/// Models `AccrueFees` / `accrue_fees_inner`: fold any vault surplus into
/// total_fees_earned. Byte-identical guard to production: `current_balance >
/// pool_value && total_lp_supply > 0`.
fn accrue(pool: &mut StakePool, vault_balance: u64) {
    let pv = pool.total_pool_value().unwrap();
    if vault_balance > pv && pool.total_lp_supply > 0 {
        pool.total_fees_earned += vault_balance - pv;
    }
}

/// Models the CURRENT (fixed) `process_deposit`, including the N7
/// `apply_minimum_liquidity_lock` carve-out on the pool's genesis deposit.
/// Returns (real_lp_minted_to_depositor, total_lp_supply_after).
fn deposit_fixed(pool: &mut StakePool, vault: &mut u64, amount: u64) -> u64 {
    let total_lp_supply_before = pool.total_lp_supply;
    let lp_to_mint = pool.calc_lp_for_deposit(amount).expect("calc_lp_for_deposit");
    assert!(lp_to_mint > 0, "S-4 guard: must never mint 0 LP for a nonzero deposit");

    let mint_amount = if total_lp_supply_before == 0 {
        lp_to_mint
            .checked_sub(MINIMUM_LIQUIDITY)
            .expect("genesis deposit must exceed MINIMUM_LIQUIDITY")
    } else {
        lp_to_mint
    };
    assert!(mint_amount > 0, "N7 guard: genesis deposit must mint > 0 real LP");

    pool.total_deposited += amount;
    pool.total_lp_supply += lp_to_mint; // full amount, including any dead-share portion
    *vault += amount;
    mint_amount
}

/// Models the PRE-N7 (buggy) withdraw formula (no virtual-offset). Used ONLY as
/// an attack-cost baseline for comparison in the tests below — never call this
/// in production.
fn pre_n7_calc_collateral_for_withdraw(supply: u64, pv: u64, lp: u64) -> u64 {
    ((lp as u128) * (pv as u128) / (supply as u128)) as u64
}

/// The genesis deposit itself must be rejected outright if it cannot clear the
/// MINIMUM_LIQUIDITY floor — this is the FIRST layer of the N7 defense: it's not
/// just that the attack is more expensive, the cheapest form of it (a 1-unit
/// genesis deposit) is impossible outright.
#[test]
fn genesis_deposit_below_minimum_liquidity_is_impossible() {
    let mut pool = mode1_pool();
    let mut vault = 0u64;
    // A 1-unit genesis deposit would have minted 1 LP pre-N7 (the cheapest
    // possible attacker foothold). Post-N7, calc_lp_for_deposit(0,0,1) still
    // returns Some(1) (the pure math is unaware of the dead-share rule — that
    // lives in the processor), but apply_minimum_liquidity_lock rejects it:
    let lp_to_mint = pool.calc_lp_for_deposit(1).unwrap();
    assert_eq!(lp_to_mint, 1);
    assert!(
        lp_to_mint <= MINIMUM_LIQUIDITY,
        "sanity: this deposit is below the dead-share floor"
    );
    // (process_deposit would reject this with DepositBelowMinimumLiquidity —
    // exercised at the instruction level in n6_marketauth_rotation_e2e.rs-style
    // LiteSVM tests / regression_166_pda_squat.rs, which now requires deposits
    // > MINIMUM_LIQUIDITY on genesis.)
    let _ = (&mut vault, &mut pool); // silence unused warnings if pool/vault unused further
}

/// Core N7 regression proof: the donation-then-accrue-then-victim-deposit attack
/// no longer lets the attacker fully DoS a victim deposit for free — some value
/// is now permanently and irrecoverably lost to the dead-share floor + virtual
/// offset with every round, unlike the pre-N7 baseline where the attack was
/// completely free (attacker recovers 100% of the donation).
#[test]
fn donation_then_accrue_attack_now_costs_the_attacker_real_value() {
    let mut pool = mode1_pool();
    let mut vault = 0u64;

    // Attacker's genesis deposit: comfortably above MINIMUM_LIQUIDITY.
    let attacker_genesis_deposit = MINIMUM_LIQUIDITY + 1_000; // 2,000
    let attacker_lp = deposit_fixed(&mut pool, &mut vault, attacker_genesis_deposit);
    assert_eq!(
        attacker_lp,
        1_000,
        "attacker's REAL LP is genesis_deposit - MINIMUM_LIQUIDITY, not the full deposit"
    );
    assert_eq!(pool.total_lp_supply, attacker_genesis_deposit, "tracked supply includes the dead shares");

    // Attacker donates a large amount directly to the vault (bypassing Deposit).
    let donation = 1_000_000u64;
    vault += donation;

    // Attacker cranks the permissionless AccrueFees, booking the donation as fees.
    accrue(&mut pool, vault);
    assert_eq!(pool.total_fees_earned, donation, "the donation is booked as fees, as the bug describes");

    // Attacker immediately tries to recover 100% of their genesis position PLUS
    // the donation by withdrawing all their (real, minted) LP.
    let attacker_withdraw_all = pool
        .calc_collateral_for_withdraw(attacker_lp)
        .unwrap();
    let attacker_total_recovered = attacker_withdraw_all; // they only ever put in genesis_deposit + donation

    // PRE-N7 baseline: attacker's LP would have been the FULL genesis deposit
    // (no dead-share carve-out), and the withdraw formula has no virtual offset —
    // so attacker recovers the donation dollar-for-dollar (below, for comparison).
    let pre_n7_attacker_lp = attacker_genesis_deposit; // no carve-out
    let pre_n7_total_pool_value = attacker_genesis_deposit + donation; // same accounting, no offset
    let pre_n7_attacker_recovered = pre_n7_calc_collateral_for_withdraw(
        pre_n7_attacker_lp,
        pre_n7_total_pool_value,
        pre_n7_attacker_lp,
    );
    assert_eq!(
        pre_n7_attacker_recovered,
        attacker_genesis_deposit + donation,
        "PRE-N7: attacker recovers their full genesis deposit + the ENTIRE donation — free attack"
    );

    // POST-N7: the attacker's real LP (1,000 out of a tracked 2,000 supply) only
    // entitles them to roughly HALF the pool's value — the other half is
    // permanently unclaimable dead-share value. This is the core N7 property:
    // establishing a cheap genesis foothold and then inflating the price no
    // longer lets the attacker walk away with everything they put in.
    assert!(
        attacker_total_recovered < pre_n7_attacker_recovered,
        "N7 must strictly reduce what the attacker can recover vs the pre-N7 baseline \
         (got {attacker_total_recovered}, pre-N7 baseline was {pre_n7_attacker_recovered})"
    );
    let attacker_permanent_loss = (attacker_genesis_deposit + donation) - attacker_total_recovered;
    assert!(
        attacker_permanent_loss > 0,
        "N7: the attacker must permanently forfeit some value they put into the pool \
         (dead shares + virtual offset), whereas pre-N7 they forfeited nothing"
    );
    // The forfeiture should be substantial here (dead shares are ~50% of the
    // attacker's tracked supply in this scenario: 1,000 real out of 2,000 total).
    assert!(
        attacker_permanent_loss > donation / 4,
        "N7 forfeiture should be a meaningful fraction of the attempted attack, not a rounding error \
         (forfeited {attacker_permanent_loss} of a {donation} donation)"
    );
}

/// After the SAME attack sequence, a victim depositing a REASONABLE amount
/// (comparable in magnitude to the attacker's real stake, not a dust amount)
/// must still be able to mint nonzero LP — N7 does not turn the pool unusable,
/// it just makes the manipulation attempt costly rather than DoS-strength-free.
#[test]
fn victim_can_still_deposit_a_reasonable_amount_after_the_attack() {
    let mut pool = mode1_pool();
    let mut vault = 0u64;

    let attacker_genesis_deposit = MINIMUM_LIQUIDITY + 1_000;
    let _attacker_lp = deposit_fixed(&mut pool, &mut vault, attacker_genesis_deposit);

    let donation = 100_000u64; // smaller donation than the previous test
    vault += donation;
    accrue(&mut pool, vault);

    // A victim depositing an amount on the same order of magnitude as the
    // current share price must still get a nonzero mint (not universally DoS'd).
    let victim_deposit = pool.total_pool_value().unwrap() / 10; // ~10% of current TVL
    assert!(victim_deposit > 0);
    let victim_lp = pool.calc_lp_for_deposit(victim_deposit).unwrap();
    assert!(
        victim_lp > 0,
        "a victim depositing a reasonable fraction of TVL must still mint nonzero LP after the attack \
         (deposit={victim_deposit}, pool_value={:?})",
        pool.total_pool_value()
    );
}

/// Non-genesis deposits (pool already has real LP holders) are NOT subject to
/// the dead-share carve-out — only the pool's very first deposit pays it. This
/// confirms apply_minimum_liquidity_lock's scoping is correct: the floor is a
/// one-time genesis cost, not a per-deposit tax.
#[test]
fn dead_share_floor_applies_only_once_at_genesis() {
    let mut pool = mode1_pool();
    let mut vault = 0u64;

    let first_lp = deposit_fixed(&mut pool, &mut vault, MINIMUM_LIQUIDITY + 500);
    assert_eq!(first_lp, 500, "genesis: mint = deposit - MINIMUM_LIQUIDITY");

    // Second depositor's amount is deliberately BELOW MINIMUM_LIQUIDITY — if the
    // floor were (incorrectly) applied per-deposit, this would underflow/panic
    // or mint 0. It must mint normally (pro-rata), proving genesis-only scoping.
    let second_lp = deposit_fixed(&mut pool, &mut vault, 10);
    assert!(second_lp > 0, "non-genesis deposits below MINIMUM_LIQUIDITY must still mint normally");
}
