//! S2 audit 2026-10-17: every StakePool setter that lives in `_reserved` / `_mode_padding` /
//! `_v5_reserved` / the appended fields writes ONLY its own bytes. Regression guard for the
//! 474079f `_reserved` collision (cooldown timelock vs HWM), extended to the v5 close-out bytes.
use bytemuck::Zeroable;
use percolator_stake::state::StakePool;

type Setter = (&'static str, fn(&mut StakePool));

fn setters() -> Vec<Setter> {
    vec![
        ("market_resolved", |p| p.set_market_resolved(true)),
        ("hwm_enabled", |p| p.set_hwm_enabled(true)),
        ("hwm_floor_bps", |p| p.set_hwm_floor_bps(0xFFFF)),
        ("epoch_high_water_tvl", |p| p.set_epoch_high_water_tvl(u64::MAX)),
        ("hwm_last_epoch", |p| p.set_hwm_last_epoch(u64::MAX)),
        ("tranche_enabled", |p| p.set_tranche_enabled(true)),
        ("junior_balance", |p| p.set_junior_balance(u64::MAX)),
        ("junior_total_lp", |p| p.set_junior_total_lp(u64::MAX)),
        ("junior_fee_mult", |p| p.set_junior_fee_mult_bps(0xFFFF)),
        ("realized_junior_loss", |p| p.set_realized_junior_loss(u64::MAX)),
        ("asset_admin_burned", |p| p.set_asset_admin_burned(true)),
        ("fee_attribution_armed", |p| p.set_fee_attribution_armed(true)),
        ("floor_flags", |p| { p.record_floor_lock(true); p.record_floor_lock(false); }),
        ("creator_seed", |p| p.record_creator_seed(u64::MAX)),
        ("creator_surplus_fwd", |p| p.set_creator_surplus_forwarded_atoms(u64::MAX)),
        ("s2_backlog", |p| p.set_s2_backlog_owed_atoms(u64::MAX)),
        ("terminal_unclaimed", |p| p.set_terminal_unclaimed_atoms(u64::MAX)),
        ("pending_cooldown", |p| p.set_pending_cooldown_slots(u64::MAX)),
        ("cooldown_proposed_at", |p| p.set_cooldown_proposed_at_slot(u64::MAX)),
    ]
}

fn bytes(p: &StakePool) -> Vec<u8> { bytemuck::bytes_of(p).to_vec() }

#[test]
fn every_reserved_field_writes_disjoint_bytes_and_leaves_discriminator_and_version() {
    let mut base = StakePool::zeroed();
    base.set_discriminator();
    let ver = base.version();
    let mut touched: Vec<(&str, Vec<usize>)> = Vec::new();
    for (name, f) in setters() {
        let mut p = base;
        p.total_lp_supply = 5_000; // record_floor_lock legacy-branch input; harmless elsewhere
        let before = bytes(&p);
        f(&mut p);
        let after = bytes(&p);
        let idx: Vec<usize> = (0..before.len()).filter(|&i| before[i] != after[i]).collect();
        assert!(!idx.is_empty(), "{name} wrote nothing");
        assert!(idx.iter().all(|&i| !(320..329).contains(&i)), "{name} clobbers discriminator/version: {idx:?}");
        assert!(p.validate_discriminator() && p.version() == ver, "{name}");
        touched.push((name, idx));
    }
    for i in 0..touched.len() {
        for j in (i + 1)..touched.len() {
            let (a, b) = (&touched[i], &touched[j]);
            // floor_flags and creator_seed legitimately share nothing; any overlap is a collision.
            let overlap: Vec<_> = a.1.iter().filter(|x| b.1.contains(x)).collect();
            assert!(overlap.is_empty(), "ALIAS: {} and {} both write bytes {:?}", a.0, b.0, overlap);
        }
    }
}

#[test]
fn every_field_roundtrips_after_all_others_are_saturated() {
    let mut p = StakePool::zeroed();
    p.set_discriminator();
    for (_, f) in setters() { f(&mut p); }
    assert!(p.market_resolved() && p.hwm_enabled() && p.tranche_enabled() && p.asset_admin_burned() && p.fee_attribution_armed());
    assert_eq!(p.hwm_floor_bps(), 0xFFFF);
    assert_eq!(p.epoch_high_water_tvl(), u64::MAX);
    assert_eq!(p.hwm_last_epoch(), u64::MAX);
    assert_eq!(p.junior_balance(), u64::MAX);
    assert_eq!(p.junior_total_lp(), u64::MAX);
    assert_eq!(p.junior_fee_mult_bps(), 0xFFFF);
    assert_eq!(p.realized_junior_loss(), u64::MAX);
    assert_eq!(p.creator_seed_atoms(), (1u64 << 56) - 1);
    assert_eq!(p.creator_surplus_forwarded_atoms(), u64::MAX);
    assert_eq!(p.s2_backlog_owed_atoms(), u64::MAX);
    assert_eq!(p.terminal_unclaimed_atoms(), u64::MAX);
    assert_eq!(p.pending_cooldown_slots(), u64::MAX);
    assert_eq!(p.cooldown_proposed_at_slot(), u64::MAX);
}
