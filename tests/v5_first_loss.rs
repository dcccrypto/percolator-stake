//! Stake v5 (Phase 4 item 6, 2026-10-05): first-loss insurance staking — pure-logic tests.
//!
//! The cross-program behaviour (consent, sync top-up / recovery through the wrapper's units
//! ledger, losses spread pro rata, no admin flush) is exercised against the REAL wrapper in
//! `percolator-prog/tests/p4_wave_d.rs` (`xprog_*`), because this repo's own e2e harness hand-
//! encodes an older InitMarket. Here: the sync plan (I-S4) with a mutant negative control, the
//! units-ledger reader (fail closed), the v5 wire, and the config bounds.

use percolator_stake::instruction::StakeInstruction;
use percolator_stake::math::{self, SyncAction};
use percolator_stake::processor::V5Init;
use percolator_stake::state::{self, read_wrapper_ins_units};
use proptest::prelude::*;

fn target_of(v: u64, bps: u16) -> u64 {
    ((v as u128) * (bps as u128) / 10_000) as u64
}
fn buffer_of(v: u64, bps: u16) -> u64 {
    ((v as u128) * (bps as u128)).div_ceil(10_000) as u64
}

/// The I-S4 property of a sync plan, checked on the post-state.
fn sync_ok(liquid: u64, deployed: u64, t: u16, b: u16, h: u16, plan: SyncAction) -> bool {
    let v = liquid as u128 + deployed as u128;
    if v > u64::MAX as u128 {
        return true;
    }
    let v = v as u64;
    let (target, hyst, buffer) = (target_of(v, t), target_of(v, h), buffer_of(v, b));
    match plan {
        SyncAction::TopUp(a) => {
            // Never above the target, never below the liquid buffer, only when under the band.
            deployed + a <= target && liquid - a >= buffer && deployed + hyst < target && a > 0
        }
        SyncAction::Recover(r) => deployed - r == target && deployed > target + hyst,
        SyncAction::None => {
            // Either inside the band, or under it with no spare liquidity.
            deployed + hyst >= target && deployed <= target + hyst || liquid <= buffer
        }
    }
}

/// MUTANT (design 6.4 "sync ignores the buffer"): the same plan without the liquid buffer.
fn sync_plan_mutant_ignores_buffer(liquid: u64, deployed: u64, t: u16, h: u16) -> SyncAction {
    let v = liquid + deployed;
    let target = target_of(v, t);
    let hyst = target_of(v, h);
    if deployed + hyst < target {
        let a = (target - deployed).min(liquid);
        return if a == 0 { SyncAction::None } else { SyncAction::TopUp(a) };
    }
    if deployed > target + hyst {
        return SyncAction::Recover(deployed - target);
    }
    SyncAction::None
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// I-S4 at full u64 width: deployed <= target + h after a sync and the buffer is respected.
    #[test]
    fn sync_plan_respects_target_and_buffer(
        liquid in 0u64..=u64::MAX / 4,
        deployed in 0u64..=u64::MAX / 4,
        t in 0u16..=8_000,
        b in 0u16..=2_000,
        h in 0u16..=2_000,
    ) {
        let plan = math::sync_plan(liquid, deployed, t, b, h).expect("in-bounds config");
        prop_assert!(sync_ok(liquid, deployed, t, b, h, plan), "{plan:?}");
    }

    /// Deployed value is pro rata in units and never exceeds the insurance it is a share of.
    #[test]
    fn deployed_value_pro_rata(us in 0u64..=1u64 << 50, extra in 0u64..=1u64 << 50, i in 0u64..=1u64 << 60) {
        let total = us as u128 + extra as u128;
        let v = math::deployed_value(us as u128, total, i as u128).unwrap();
        if total == 0 {
            prop_assert_eq!(v, 0);
        } else {
            prop_assert!(v as u128 <= i as u128);
            prop_assert_eq!(v as u128, us as u128 * i as u128 / total);
        }
    }
}

/// NEGATIVE CONTROL: the buffer-ignoring mutant violates I-S4 on an ordinary pool (the property
/// above is not vacuous).
#[test]
fn mutant_sync_ignoring_buffer_is_caught() {
    // 4M liquid, nothing deployed, target 80%, buffer 30%: the mutant deploys 3.2M and leaves
    // 0.8M < the 1.2M buffer.
    let (liquid, deployed, t, b, h) = (4_000_000u64, 0u64, 8_000u16, 3_000u16, 500u16);
    let m = sync_plan_mutant_ignores_buffer(liquid, deployed, t, h);
    assert!(!sync_ok(liquid, deployed, t, b, h, m), "mutant must break I-S4: {m:?}");
    let real = math::sync_plan(liquid, deployed, t, b, h).unwrap();
    assert_eq!(real, SyncAction::TopUp(2_800_000), "the real plan stops at the buffer");
    assert!(sync_ok(liquid, deployed, t, b, h, real));
}

#[test]
fn sync_plan_examples() {
    // Design defaults: 50% target, 30% buffer, 5% hysteresis.
    assert_eq!(math::sync_plan(4_000_000, 0, 5_000, 3_000, 500), Some(SyncAction::TopUp(2_000_000)));
    assert_eq!(math::sync_plan(2_000_000, 2_000_000, 5_000, 3_000, 500), Some(SyncAction::None));
    // Inside the band: nothing.
    assert_eq!(math::sync_plan(2_100_000, 1_900_000, 5_000, 3_000, 500), Some(SyncAction::None));
    // Over the band (a lowered target): recover to the target.
    assert_eq!(math::sync_plan(2_000_000, 2_000_000, 2_000, 3_000, 500), Some(SyncAction::Recover(1_200_000)));
    // Out-of-range config fails closed.
    assert_eq!(math::sync_plan(1, 1, 10_001, 0, 0), None);
    assert!(math::liquid_withdrawal_ok(10, 10, 10));
    assert!(!math::liquid_withdrawal_ok(11, 10, 100));
    assert!(!math::liquid_withdrawal_ok(10, 100, 9));
}

/// Two stakers' LP values move by the same fraction when the deployed value falls (I-S3 at the
/// stake layer): the LP price is (liquid + deployed) / supply for everyone.
#[test]
fn stakers_lose_pro_rata() {
    let (liquid, supply) = (4_500_000u64, 9_000_000u64);
    let (lp_a, lp_b) = (6_000_000u64, 3_000_000u64);
    for (d0, d1) in [(4_500_000u64, 3_471_775u64), (1_000, 0), (7, 3)] {
        let pv0 = math::pool_value_v5(liquid, d0).unwrap();
        let pv1 = math::pool_value_v5(liquid, d1).unwrap();
        let a0 = math::calc_collateral_for_withdraw(supply, pv0, lp_a).unwrap() as u128;
        let b0 = math::calc_collateral_for_withdraw(supply, pv0, lp_b).unwrap() as u128;
        let a1 = math::calc_collateral_for_withdraw(supply, pv1, lp_a).unwrap() as u128;
        let b1 = math::calc_collateral_for_withdraw(supply, pv1, lp_b).unwrap() as u128;
        assert!((a1 * b0).abs_diff(b1 * a0) <= a0 + b0, "{a1}/{a0} vs {b1}/{b0}");
    }
}

fn units_bytes(market: [u8; 32], total: u128, stake: u128, creator: u128) -> Vec<u8> {
    let mut d = vec![0u8; state::WRAPPER_INS_UNITS_LEN];
    d[0..8].copy_from_slice(&state::WRAPPER_MAGIC.to_le_bytes());
    d[8..10].copy_from_slice(&18u16.to_le_bytes());
    d[state::WRAPPER_OFF_KIND] = state::WRAPPER_KIND_INSURANCE_UNITS;
    d[state::WRAPPER_INS_UNITS_OFF_MARKET..state::WRAPPER_INS_UNITS_OFF_MARKET + 32].copy_from_slice(&market);
    d[state::WRAPPER_INS_UNITS_OFF_UNITS_TOTAL..][..16].copy_from_slice(&total.to_le_bytes());
    d[state::WRAPPER_INS_UNITS_OFF_UNITS_STAKE..][..16].copy_from_slice(&stake.to_le_bytes());
    d[state::WRAPPER_INS_UNITS_OFF_UNITS_CREATOR..][..16].copy_from_slice(&creator.to_le_bytes());
    d[state::WRAPPER_INS_UNITS_OFF_SNAP_MINT..][..16].copy_from_slice(&1_000u128.to_le_bytes());
    d[state::WRAPPER_INS_UNITS_OFF_SNAP_FREE..][..16].copy_from_slice(&900u128.to_le_bytes());
    d[state::WRAPPER_INS_UNITS_OFF_SNAP_SLOT..][..8].copy_from_slice(&77u64.to_le_bytes());
    d[state::WRAPPER_INS_UNITS_OFF_VERSION] = state::WRAPPER_INS_UNITS_VERSION;
    d
}

/// The units reader fails closed on every mismatch (wrong market, kind, version, magic, a
/// broken class invariant, a short account).
#[test]
fn units_reader_fails_closed() {
    let m = [7u8; 32];
    let ok = units_bytes(m, 30, 10, 20);
    let u = read_wrapper_ins_units(&ok, &m).expect("valid");
    assert_eq!((u.units_total, u.units_stake, u.units_creator, u.snap_mint, u.snap_free, u.snap_slot), (30, 10, 20, 1_000, 900, 77));
    assert!(read_wrapper_ins_units(&ok, &[8u8; 32]).is_none(), "wrong market");
    let mut bad = ok.clone();
    bad[state::WRAPPER_OFF_KIND] = 10;
    assert!(read_wrapper_ins_units(&bad, &m).is_none(), "wrong kind");
    let mut bad = ok.clone();
    bad[state::WRAPPER_INS_UNITS_OFF_VERSION] = 2;
    assert!(read_wrapper_ins_units(&bad, &m).is_none(), "wrong version");
    let mut bad = ok.clone();
    bad[0] ^= 1;
    assert!(read_wrapper_ins_units(&bad, &m).is_none(), "wrong magic");
    assert!(read_wrapper_ins_units(&units_bytes(m, 31, 10, 20), &m).is_none(), "class invariant");
    assert!(read_wrapper_ins_units(&ok[..ok.len() - 1], &m).is_none(), "short");
}

#[test]
fn v5_wire_decodes() {
    let mut d = vec![0u8];
    d.extend_from_slice(&5u64.to_le_bytes());
    d.extend_from_slice(&0u64.to_le_bytes());
    assert!(matches!(StakeInstruction::unpack(&d).unwrap(), StakeInstruction::InitPool { .. }));
    d.push(1);
    d.extend_from_slice(&6_000u16.to_le_bytes());
    d.extend_from_slice(&2_500u16.to_le_bytes());
    d.extend_from_slice(&400u16.to_le_bytes());
    match StakeInstruction::unpack(&d).unwrap() {
        StakeInstruction::InitPoolV5 { risk_mode, deploy_target_bps, liquid_buffer_bps, hysteresis_bps, .. } => {
            assert_eq!((risk_mode, deploy_target_bps, liquid_buffer_bps, hysteresis_bps), (1, 6_000, 2_500, 400))
        }
        other => panic!("{other:?}"),
    }
    let mut dep = vec![1u8];
    dep.extend_from_slice(&42u64.to_le_bytes());
    assert!(matches!(StakeInstruction::unpack(&dep).unwrap(), StakeInstruction::Deposit { amount: 42 }));
    // S-5: the old 9-byte consent (version only) is refused; the 15-byte form binds the
    // deployment parameters.
    let mut stale = dep.clone();
    stale.push(1);
    assert!(StakeInstruction::unpack(&stale).is_err(), "version-only consent refused");
    dep.extend_from_slice(&percolator_stake::state::deposit_consent_bytes(6_000, 2_500, 400));
    assert!(matches!(
        StakeInstruction::unpack(&dep).unwrap(),
        StakeInstruction::DepositWithConsent {
            amount: 42,
            accept_first_loss_version: 2,
            target_bps: 6_000,
            buffer_bps: 2_500,
            hysteresis_bps: 400
        }
    ));
    assert!(matches!(StakeInstruction::unpack(&[31]).unwrap(), StakeInstruction::SyncInsuranceDeployment));
    assert!(StakeInstruction::unpack(&[31, 0]).is_err());
    assert!(matches!(
        StakeInstruction::unpack(&[32, 0xd0, 0x07]).unwrap(),
        StakeInstruction::ProposeDeployTarget { target_bps: 2_000 }
    ));
    assert!(matches!(StakeInstruction::unpack(&[33]).unwrap(), StakeInstruction::CommitDeployTarget));
}

#[test]
fn v5_config_bounds() {
    assert!(V5Init::first_loss_defaults().validate().is_ok());
    let mk = |m, t, b, h| V5Init { risk_mode: m, deploy_target_bps: t, liquid_buffer_bps: b, hysteresis_bps: h };
    assert!(mk(1, 8_000, 2_000, 500).validate().is_ok());
    assert!(mk(1, 8_001, 0, 500).validate().is_err(), "target above 80%");
    assert!(mk(1, 8_000, 2_001, 500).validate().is_err(), "target + buffer > 100%");
    assert!(mk(1, 5_000, 3_000, 2_001).validate().is_err(), "hysteresis above 20%");
    assert!(mk(2, 0, 0, 0).validate().is_ok(), "fee-only");
    assert!(mk(2, 1, 0, 0).validate().is_err(), "fee-only never deploys");
    assert!(mk(0, 0, 0, 0).validate().is_err(), "legacy mode is not creatable");
    assert!(mk(3, 0, 0, 0).validate().is_err());
}

/// S-1 (security review 2026-10-05): the units stake demands from a sync CPI. The reviewer's
/// SEC-D2 state (`U = 1` against `I = 3,000,000`) expects ZERO units for a 2,000,000 top-up, which
/// the sync refuses (`InsuranceUnitsMismatch`) instead of donating the deployment.
#[test]
fn s1_expected_units() {
    assert_eq!(math::expected_topup_units(2_000_000, 1, 3_000_000), Some(0), "SEC-D2 shape -> 0 -> refused");
    assert_eq!(math::expected_topup_units(2_000_000, 0, 0), Some(2_000_000), "genesis 1:1");
    assert_eq!(math::expected_topup_units(7, 5, 0), Some(7), "after the wrapper's reset");
    assert_eq!(math::expected_topup_units(1_000, 3_000, 2_000), Some(1_500));
    assert_eq!(math::expected_recover_burn(1_000, 3_000, 2_000), Some(1_500));
    assert_eq!(math::expected_recover_burn(1, 3, 2), Some(2), "ceil");
    assert_eq!(math::expected_recover_burn(3, 3, 2), None, "r > I_free");
    assert_eq!(math::expected_recover_burn(1, 0, 2), None);
    // Same rounding as the wrapper: floor on mint, ceil on burn.
    for (a, u, i) in [(1u64, 7u128, 3u128), (999, 1_000_003, 999_983), (5, 1, 9)] {
        let m = math::expected_topup_units(a, u, i).unwrap();
        assert_eq!(m, (a as u128) * u / i);
        let b = math::expected_recover_burn(a.min(i as u64), u, i).unwrap();
        assert_eq!(b, ((a.min(i as u64) as u128) * u).div_ceil(i));
    }
}
