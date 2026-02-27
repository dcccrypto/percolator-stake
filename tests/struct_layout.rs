//! Struct layout verification tests.
//!
//! Ensures bytemuck Pod compliance and that struct sizes
//! don't accidentally change (would break on-chain state).

use percolator_stake::state::{StakeDeposit, StakePool, STAKE_DEPOSIT_SIZE, STAKE_POOL_SIZE};

#[test]
fn test_stake_pool_size_is_352() {
    // If this changes, existing on-chain data becomes unreadable.
    // NEVER change this without a migration plan.
    assert_eq!(STAKE_POOL_SIZE, 352);
    assert_eq!(std::mem::size_of::<StakePool>(), 352);
}

#[test]
fn test_stake_deposit_size_is_152() {
    assert_eq!(STAKE_DEPOSIT_SIZE, 152);
    assert_eq!(std::mem::size_of::<StakeDeposit>(), 152);
}

#[test]
fn test_stake_pool_alignment() {
    assert_eq!(std::mem::align_of::<StakePool>(), 8);
}

#[test]
fn test_stake_deposit_alignment() {
    assert_eq!(std::mem::align_of::<StakeDeposit>(), 8);
}

#[test]
fn test_stake_pool_zeroed_is_not_initialized() {
    let pool = StakePool::zeroed();
    assert_eq!(pool.is_initialized, 0);
    assert_eq!(pool.admin_transferred, 0);
    assert_eq!(pool.total_deposited, 0);
    assert_eq!(pool.total_lp_supply, 0);
    assert_eq!(pool.total_withdrawn, 0);
    assert_eq!(pool.total_flushed, 0);
    assert_eq!(pool.total_returned, 0);
}

#[test]
fn test_stake_deposit_zeroed_is_not_initialized() {
    let deposit = StakeDeposit::zeroed();
    assert_eq!(deposit.is_initialized, 0);
    assert_eq!(deposit.lp_amount, 0);
    assert_eq!(deposit.last_deposit_slot, 0);
}

#[test]
fn test_bytemuck_roundtrip_pool() {
    let mut pool = StakePool::zeroed();
    pool.is_initialized = 1;
    pool.bump = 42;
    pool.vault_authority_bump = 99;
    pool.total_deposited = 1_000_000;
    pool.total_lp_supply = 500_000;
    pool.cooldown_slots = 100;
    pool.deposit_cap = 10_000_000;

    // Serialize
    let bytes: &[u8] = bytemuck::bytes_of(&pool);
    assert_eq!(bytes.len(), STAKE_POOL_SIZE);

    // Deserialize
    let recovered: &StakePool = bytemuck::from_bytes(bytes);
    assert_eq!(recovered.is_initialized, 1);
    assert_eq!(recovered.bump, 42);
    assert_eq!(recovered.vault_authority_bump, 99);
    assert_eq!(recovered.total_deposited, 1_000_000);
    assert_eq!(recovered.total_lp_supply, 500_000);
    assert_eq!(recovered.cooldown_slots, 100);
    assert_eq!(recovered.deposit_cap, 10_000_000);
}

#[test]
fn test_bytemuck_roundtrip_deposit() {
    let mut deposit = StakeDeposit::zeroed();
    deposit.is_initialized = 1;
    deposit.bump = 77;
    deposit.last_deposit_slot = 12345;
    deposit.lp_amount = 999;

    let bytes: &[u8] = bytemuck::bytes_of(&deposit);
    assert_eq!(bytes.len(), STAKE_DEPOSIT_SIZE);

    let recovered: &StakeDeposit = bytemuck::from_bytes(bytes);
    assert_eq!(recovered.is_initialized, 1);
    assert_eq!(recovered.bump, 77);
    assert_eq!(recovered.last_deposit_slot, 12345);
    assert_eq!(recovered.lp_amount, 999);
}

use bytemuck::{Pod, Zeroable};

#[test]
fn test_pod_zeroable_impls() {
    // These compile-time checks ensure Pod + Zeroable derive is valid
    fn assert_pod<T: Pod + Zeroable>() {}
    assert_pod::<StakePool>();
    assert_pod::<StakeDeposit>();
}

/// Field offset verification — ensures no hidden padding changes
#[test]
fn test_stake_pool_field_offsets() {
    let pool = StakePool::zeroed();
    let base = &pool as *const _ as usize;

    assert_eq!(&pool.is_initialized as *const _ as usize - base, 0);
    assert_eq!(&pool.bump as *const _ as usize - base, 1);
    assert_eq!(&pool.vault_authority_bump as *const _ as usize - base, 2);
    assert_eq!(&pool.admin_transferred as *const _ as usize - base, 3);
    assert_eq!(&pool._padding as *const _ as usize - base, 4);
    assert_eq!(&pool.slab as *const _ as usize - base, 8);
    assert_eq!(&pool.admin as *const _ as usize - base, 40);
    assert_eq!(&pool.collateral_mint as *const _ as usize - base, 72);
    assert_eq!(&pool.lp_mint as *const _ as usize - base, 104);
    assert_eq!(&pool.vault as *const _ as usize - base, 136);
    assert_eq!(&pool.total_deposited as *const _ as usize - base, 168);
    assert_eq!(&pool.total_lp_supply as *const _ as usize - base, 176);
    assert_eq!(&pool.cooldown_slots as *const _ as usize - base, 184);
    assert_eq!(&pool.deposit_cap as *const _ as usize - base, 192);
    assert_eq!(&pool.total_flushed as *const _ as usize - base, 200);
    assert_eq!(&pool.total_returned as *const _ as usize - base, 208);
    assert_eq!(&pool.total_withdrawn as *const _ as usize - base, 216);
    assert_eq!(&pool.percolator_program as *const _ as usize - base, 224);
    assert_eq!(&pool._reserved as *const _ as usize - base, 256);
}
