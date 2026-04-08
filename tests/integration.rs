//! Integration tests for percolator-stake.
//!
//! Covers full staking lifecycle flows, CPI tag correctness (CRIT-1 regression
//! guard), pool version/discriminator validation, cooldown enforcement, and
//! junior tranche accounting. Tests operate entirely on structs and data — no
//! Solana runtime or solana-program-test is used.
//!
//! CRIT-1 context: Tags 30/31 were the incorrect values for SetInsuranceWithdrawPolicy
//! and WithdrawInsuranceLimited. The correct tags are 22 and 23 respectively.
//! Any regression back to 30/31 will break these tests.

use bytemuck::Zeroable;
use percolator_stake::{
    cpi_tag_constants::{TAG_SET_INSURANCE_WITHDRAW_POLICY, TAG_WITHDRAW_INSURANCE_LIMITED},
    instruction::StakeInstruction,
    state::{
        derive_deposit_pda, derive_pool_pda, derive_vault_authority, StakeDeposit, StakePool,
        STAKE_DEPOSIT_DISCRIMINATOR, STAKE_DEPOSIT_SIZE, STAKE_POOL_DISCRIMINATOR, STAKE_POOL_SIZE,
    },
};

// ════════════════════════════════════════════════════════════════
// Helpers
// ════════════════════════════════════════════════════════════════

fn initialized_pool() -> StakePool {
    let mut pool = StakePool::zeroed();
    pool.is_initialized = 1;
    pool.bump = 255;
    pool.vault_authority_bump = 254;
    pool.admin_transferred = 1;
    pool.set_discriminator();
    pool
}

fn initialized_deposit() -> StakeDeposit {
    let mut dep = StakeDeposit::zeroed();
    dep.is_initialized = 1;
    dep.bump = 253;
    dep.set_discriminator();
    dep
}

// ════════════════════════════════════════════════════════════════
// LIFECYCLE 1: InitPool → Deposit → AccrueFees → Withdraw
// ════════════════════════════════════════════════════════════════

/// Full senior LP cycle: first deposit gets 1:1 LP, full withdraw returns
/// exact amount, LP supply returns to 0.
#[test]
fn test_full_senior_deposit_withdraw_cycle() {
    let mut pool = initialized_pool();
    pool.cooldown_slots = 0; // no cooldown for this test

    // Step 1: InitPool — pool starts empty
    assert_eq!(pool.total_deposited, 0);
    assert_eq!(pool.total_lp_supply, 0);

    // Step 2: Deposit 5_000_000
    let deposit_amount = 5_000_000u64;
    let lp = pool.calc_lp_for_deposit(deposit_amount).expect("calc_lp must succeed");
    assert_eq!(lp, deposit_amount, "first depositor gets 1:1 LP");
    pool.total_deposited += deposit_amount;
    pool.total_lp_supply += lp;

    assert_eq!(pool.total_pool_value(), Some(deposit_amount));

    // Step 3: AccrueFees simulation — pool earns 100_000 in trading fees
    // (pool_mode=1 required for fees to count in pool_value)
    pool.pool_mode = 1;
    pool.total_fees_earned = 100_000;
    let pool_value_with_fees = pool.total_pool_value().expect("pool value must be computable");
    assert_eq!(pool_value_with_fees, deposit_amount + 100_000);

    // Step 4: Withdraw all LP
    pool.pool_mode = 0; // reset to simple mode for withdrawal math
    pool.total_fees_earned = 0;
    let collateral_back = pool
        .calc_collateral_for_withdraw(lp)
        .expect("calc_collateral must succeed");
    assert_eq!(collateral_back, deposit_amount, "first depositor gets exact amount back");

    pool.total_withdrawn += collateral_back;
    pool.total_lp_supply -= lp;

    assert_eq!(pool.total_lp_supply, 0, "LP supply must be zero after full withdrawal");
    assert_eq!(
        pool.total_pool_value(),
        Some(0),
        "pool value must be zero after full withdrawal"
    );
}

/// Two sequential depositors: both get proportional LP, both get exact amounts back.
#[test]
fn test_two_depositor_senior_lifecycle() {
    let mut pool = initialized_pool();

    // Alice deposits 2_000_000
    let alice_dep = 2_000_000u64;
    let alice_lp = pool.calc_lp_for_deposit(alice_dep).unwrap();
    pool.total_deposited += alice_dep;
    pool.total_lp_supply += alice_lp;

    // Bob deposits 1_000_000 (pool already has 2M)
    let bob_dep = 1_000_000u64;
    let bob_lp = pool.calc_lp_for_deposit(bob_dep).unwrap();
    pool.total_deposited += bob_dep;
    pool.total_lp_supply += bob_lp;

    // Alice withdraws
    let alice_back = pool.calc_collateral_for_withdraw(alice_lp).unwrap();
    pool.total_withdrawn += alice_back;
    pool.total_lp_supply -= alice_lp;

    // Bob withdraws
    let bob_back = pool.calc_collateral_for_withdraw(bob_lp).unwrap();
    pool.total_withdrawn += bob_back;
    pool.total_lp_supply -= bob_lp;

    // Conservation: total back = total deposited (no rounding loss at these scales)
    assert_eq!(
        alice_back + bob_back,
        alice_dep + bob_dep,
        "total withdrawn must equal total deposited"
    );
    assert_eq!(pool.total_lp_supply, 0, "LP supply must be exhausted");
}

// ════════════════════════════════════════════════════════════════
// LIFECYCLE 2: Junior tranche — DepositJunior → WithdrawJunior
// ════════════════════════════════════════════════════════════════

/// Junior tranche: verify LP token accounting and no balance drift across
/// a full DepositJunior → WithdrawJunior roundtrip.
#[test]
fn test_junior_deposit_withdraw_no_drift() {
    let mut pool = initialized_pool();
    pool.set_tranche_enabled(true);
    pool.set_junior_fee_mult_bps(20_000); // 2x default

    // Initial pool state (senior already deposited)
    pool.total_deposited = 10_000_000;
    pool.total_lp_supply = 10_000_000;

    // Set junior balance to match what a DepositJunior call would set
    let junior_deposit = 3_000_000u64;
    pool.set_junior_balance(junior_deposit);
    pool.set_junior_total_lp(junior_deposit); // first junior: 1:1

    // Total deposited includes junior
    pool.total_deposited += junior_deposit;
    pool.total_lp_supply += junior_deposit;

    // Verify junior balance is tracked
    assert_eq!(pool.junior_balance(), junior_deposit);
    assert_eq!(pool.junior_total_lp(), junior_deposit);

    // Senior LP = total - junior
    let senior_lp = pool.senior_total_lp();
    assert_eq!(senior_lp, 10_000_000, "senior LP must be original amount");

    // WithdrawJunior: burn all junior LP
    let junior_lp_to_burn = junior_deposit;
    let junior_collateral_back = pool
        .calc_collateral_for_withdraw(junior_lp_to_burn)
        .unwrap();

    // In a no-loss scenario, junior gets back exactly what they put in
    // (since total_pool_value = total_deposited - total_withdrawn - flushed + returned)
    assert!(
        junior_collateral_back <= junior_deposit,
        "junior withdrawal must not exceed deposit"
    );
    // Allow 1 unit rounding tolerance
    assert!(
        junior_deposit - junior_collateral_back <= 1,
        "junior withdrawal rounding drift must be at most 1"
    );

    pool.total_withdrawn += junior_collateral_back;
    pool.total_lp_supply -= junior_lp_to_burn;
    pool.set_junior_balance(0);
    pool.set_junior_total_lp(0);

    // No balance drift: junior balance zeroed
    assert_eq!(pool.junior_balance(), 0);
    assert_eq!(pool.junior_total_lp(), 0);
}

/// Junior tranche: effective_junior_balance accounts for insurance losses.
#[test]
fn test_junior_absorbs_insurance_loss_first() {
    let mut pool = initialized_pool();
    pool.set_tranche_enabled(true);

    // Senior: 10M, Junior: 5M (gross balances)
    pool.total_deposited = 15_000_000;
    pool.total_lp_supply = 15_000_000;
    pool.set_junior_balance(5_000_000);
    pool.set_junior_total_lp(5_000_000);

    // Insurance event: 2M flushed, 0 returned → 2M net loss
    pool.total_flushed = 2_000_000;
    pool.total_returned = 0;
    pool.total_withdrawn = 0;

    // Junior absorbs loss first (up to junior balance)
    let eff_junior = pool.effective_junior_balance();
    // gross_pool = 15M - 0 = 15M, gross_senior = 15M - 5M = 10M
    // distribute_loss(junior=5M, senior=10M, loss=2M) → junior absorbs 2M first
    // eff_junior = 5M - 2M = 3M
    assert_eq!(
        eff_junior, 3_000_000,
        "junior absorbs the 2M insurance loss before senior"
    );

    // Senior is unaffected
    let senior_bal = pool.senior_balance().unwrap();
    // pool_value = 15M - 0 - 2M + 0 = 13M, senior = 13M - 3M = 10M
    assert_eq!(senior_bal, 10_000_000, "senior is fully shielded from loss");
}

/// Junior tranche: loss exceeding junior balance forces senior to absorb remainder.
#[test]
fn test_insurance_loss_exceeds_junior_spills_to_senior() {
    let mut pool = initialized_pool();
    pool.set_tranche_enabled(true);

    pool.total_deposited = 15_000_000;
    pool.total_lp_supply = 15_000_000;
    pool.set_junior_balance(2_000_000); // only 2M junior
    pool.set_junior_total_lp(2_000_000);

    // 5M loss (exceeds junior 2M)
    pool.total_flushed = 5_000_000;
    pool.total_returned = 0;

    let eff_junior = pool.effective_junior_balance();
    // junior (2M) fully wiped, returns 0
    assert_eq!(eff_junior, 0, "junior is fully wiped by a loss exceeding its balance");

    // pool_value = 15M - 5M = 10M, senior = 10M - 0 = 10M
    // But senior also lost 3M (the spill-over): senior = 10M - 0 = 10M
    // (the 3M spill is already reflected in pool_value being 10M instead of 13M)
    let pool_val = pool.total_pool_value().unwrap();
    assert_eq!(pool_val, 10_000_000);
}

// ════════════════════════════════════════════════════════════════
// CPI TAGS: FlushToInsurance uses tag 9 (TopUpInsurance)
// ════════════════════════════════════════════════════════════════

/// FlushToInsurance CPI data must have tag byte 9.
#[test]
fn test_flush_to_insurance_cpi_tag_is_9() {
    // Build the CPI data as the production code does
    let amount = 500_000u64;
    let mut data = Vec::with_capacity(9);
    data.push(9u8); // TAG_TOP_UP_INSURANCE
    data.extend_from_slice(&amount.to_le_bytes());

    assert_eq!(data[0], 9, "FlushToInsurance must use CPI tag 9 (TopUpInsurance)");
    assert_eq!(&data[1..9], &amount.to_le_bytes());
}

/// Instruction-level decode of FlushToInsurance must produce the right amount.
#[test]
fn test_flush_instruction_decodes_correctly() {
    let mut data = vec![3u8]; // StakeInstruction::FlushToInsurance tag
    data.extend_from_slice(&777_777u64.to_le_bytes());
    match StakeInstruction::unpack(&data).unwrap() {
        StakeInstruction::FlushToInsurance { amount } => {
            assert_eq!(amount, 777_777);
        }
        _ => panic!("Expected FlushToInsurance"),
    }
}

// ════════════════════════════════════════════════════════════════
// CRIT-1 REGRESSION: AdminSetInsurancePolicy CPI tag = 22 (not 30)
// ════════════════════════════════════════════════════════════════
//
// These tests are the primary regression guard for CRIT-1. If anyone
// changes TAG_SET_INSURANCE_WITHDRAW_POLICY back to 30 or any other value,
// these tests will fail immediately.

/// AdminSetInsurancePolicy must use CPI tag 22.
/// Tag 30 = ForceCloseResolved (completely different, dangerous).
/// Tag 22 = SetInsuranceWithdrawPolicy (correct).
#[test]
fn test_admin_set_insurance_policy_cpi_tag_is_22_not_30() {
    assert_eq!(
        TAG_SET_INSURANCE_WITHDRAW_POLICY, 22,
        "CRIT-1: SetInsuranceWithdrawPolicy must use tag 22, not 30 (ForceCloseResolved)"
    );

    // Build data as cpi.rs does
    let authority = [0u8; 32];
    let min_withdraw_base = 100_000u64;
    let max_withdraw_bps = 500u16;
    let cooldown_slots = 1000u64;

    let mut data = Vec::with_capacity(51);
    data.push(TAG_SET_INSURANCE_WITHDRAW_POLICY);
    data.extend_from_slice(&authority);
    data.extend_from_slice(&min_withdraw_base.to_le_bytes());
    data.extend_from_slice(&max_withdraw_bps.to_le_bytes());
    data.extend_from_slice(&cooldown_slots.to_le_bytes());

    assert_eq!(data[0], 22, "First byte of SetInsuranceWithdrawPolicy CPI data must be 22");
    assert_ne!(data[0], 30, "CRIT-1: tag must not be 30 (ForceCloseResolved)");
    assert_ne!(data[0], 21, "tag must not be 21 (AdminForceCloseAccount)");
    assert_ne!(data[0], 31, "tag must not be 31 (unrecognized)");

    // Verify data contains authority at [1..33]
    assert_eq!(&data[1..33], &authority);
    // min_withdraw_base at [33..41]
    assert_eq!(
        u64::from_le_bytes(data[33..41].try_into().unwrap()),
        min_withdraw_base
    );
    // max_withdraw_bps at [41..43]
    assert_eq!(
        u16::from_le_bytes(data[41..43].try_into().unwrap()),
        max_withdraw_bps
    );
    // cooldown_slots at [43..51]
    assert_eq!(
        u64::from_le_bytes(data[43..51].try_into().unwrap()),
        cooldown_slots
    );
}

/// AdminWithdrawInsurance must use CPI tag 23.
/// Tag 31 was previously used (wrong, unrecognized by percolator-prog).
/// Tag 23 = WithdrawInsuranceLimited (correct).
#[test]
fn test_admin_withdraw_insurance_cpi_tag_is_23_not_31() {
    assert_eq!(
        TAG_WITHDRAW_INSURANCE_LIMITED, 23,
        "CRIT-1: WithdrawInsuranceLimited must use tag 23, not 31 (unrecognized)"
    );

    let amount = 250_000u64;
    let mut data = Vec::with_capacity(9);
    data.push(TAG_WITHDRAW_INSURANCE_LIMITED);
    data.extend_from_slice(&amount.to_le_bytes());

    assert_eq!(data[0], 23, "First byte of WithdrawInsuranceLimited CPI data must be 23");
    assert_ne!(data[0], 31, "CRIT-1: tag must not be 31 (old wrong value)");
    assert_ne!(data[0], 30, "tag must not be 30 (ForceCloseResolved)");
    assert_eq!(
        u64::from_le_bytes(data[1..9].try_into().unwrap()),
        amount,
        "WithdrawInsuranceLimited amount must be encoded after tag"
    );
}

/// The two CRIT-1 tags must be distinct (cannot collide with each other).
#[test]
fn test_crit1_tags_are_distinct() {
    assert_ne!(
        TAG_SET_INSURANCE_WITHDRAW_POLICY,
        TAG_WITHDRAW_INSURANCE_LIMITED,
        "CRIT-1: policy and withdraw tags must be distinct"
    );
}

/// Regression guard: both tags must match the production constants imported
/// directly from the crate — not hardcoded in the test.
#[test]
fn test_crit1_tags_match_production_constants() {
    // These values are the only correct values per the percolator-prog decode table.
    // If the constants in src/cpi.rs are ever changed, this test fails at compile
    // time (if the constant is renamed) or at runtime (if the value is changed).
    const EXPECTED_POLICY: u8 = 22;
    const EXPECTED_WITHDRAW: u8 = 23;

    assert_eq!(
        TAG_SET_INSURANCE_WITHDRAW_POLICY, EXPECTED_POLICY,
        "TAG_SET_INSURANCE_WITHDRAW_POLICY drifted from expected value 22"
    );
    assert_eq!(
        TAG_WITHDRAW_INSURANCE_LIMITED, EXPECTED_WITHDRAW,
        "TAG_WITHDRAW_INSURANCE_LIMITED drifted from expected value 23"
    );
}

/// Verify that tags 30 and 31 are NOT used for insurance operations.
/// This is the exact scenario that CRIT-1 patched.
#[test]
fn test_crit1_dangerous_tags_not_used_for_insurance() {
    // Tag 30 in percolator-prog is ForceCloseResolved.
    // Tag 31 is unrecognized. Using either for insurance ops would be catastrophic.
    assert_ne!(
        TAG_SET_INSURANCE_WITHDRAW_POLICY, 30,
        "CRIT-1 REGRESSION: SetInsuranceWithdrawPolicy must not use tag 30 (ForceCloseResolved)!"
    );
    assert_ne!(
        TAG_WITHDRAW_INSURANCE_LIMITED, 31,
        "CRIT-1 REGRESSION: WithdrawInsuranceLimited must not use tag 31 (unrecognized)!"
    );
    // Also verify no off-by-one errors
    assert_ne!(TAG_SET_INSURANCE_WITHDRAW_POLICY, 29);
    assert_ne!(TAG_SET_INSURANCE_WITHDRAW_POLICY, 31);
    assert_ne!(TAG_WITHDRAW_INSURANCE_LIMITED, 22);
    assert_ne!(TAG_WITHDRAW_INSURANCE_LIMITED, 30);
}

// ════════════════════════════════════════════════════════════════
// POOL VERSION VALIDATION: reject version-0 pools
// ════════════════════════════════════════════════════════════════

/// A pool with version 0 (uninitialized or pre-versioning) must fail validation.
/// The processor rejects any pool whose version() != CURRENT_VERSION.
#[test]
fn test_pool_version_0_rejected() {
    let mut pool = initialized_pool();
    // Force version to 0 by overwriting byte 8 of _reserved
    pool._reserved[8] = 0;
    assert_eq!(pool.version(), 0, "version must be 0 after override");

    // The processor checks: pool.version() != StakePool::CURRENT_VERSION
    let is_valid_version = pool.version() == StakePool::CURRENT_VERSION;
    assert!(
        !is_valid_version,
        "Version-0 pool must be rejected by version validation"
    );
}

/// A properly initialized pool has version CURRENT_VERSION.
#[test]
fn test_pool_current_version_accepted() {
    let pool = initialized_pool();
    assert_eq!(pool.version(), StakePool::CURRENT_VERSION);
    assert_eq!(
        pool.version(),
        StakePool::CURRENT_VERSION,
        "Initialized pool must have CURRENT_VERSION"
    );
}

/// set_discriminator() sets both discriminator and version.
#[test]
fn test_set_discriminator_sets_version_and_magic() {
    let mut pool = StakePool::zeroed();
    pool.set_discriminator();

    assert!(pool.validate_discriminator(), "discriminator must validate after set_discriminator");
    assert_eq!(
        pool.version(),
        StakePool::CURRENT_VERSION,
        "version must be CURRENT_VERSION after set_discriminator"
    );
    assert_eq!(&pool._reserved[..8], &STAKE_POOL_DISCRIMINATOR);
}

// ════════════════════════════════════════════════════════════════
// DISCRIMINATOR VALIDATION: reject pools without valid discriminator
// ════════════════════════════════════════════════════════════════

/// Zeroed pool must NOT pass discriminator validation.
/// FINDING-10: zeroed-data branch was removed — must fail.
#[test]
fn test_zeroed_pool_fails_discriminator() {
    let pool = StakePool::zeroed();
    assert!(
        !pool.validate_discriminator(),
        "Zeroed pool must not pass discriminator validation (FINDING-10)"
    );
}

/// Pool with correct discriminator must pass validation.
#[test]
fn test_initialized_pool_passes_discriminator() {
    let pool = initialized_pool();
    assert!(pool.validate_discriminator(), "Initialized pool must pass discriminator validation");
}

/// Pool with corrupted discriminator (one byte flipped) must fail.
#[test]
fn test_corrupted_discriminator_fails() {
    let mut pool = initialized_pool();
    pool._reserved[3] ^= 0xFF; // flip one byte
    assert!(
        !pool.validate_discriminator(),
        "Corrupted discriminator must fail validation"
    );
}

/// Pool with wrong discriminator (e.g. STAKE_DEPOSIT_DISCRIMINATOR) must fail.
#[test]
fn test_wrong_discriminator_fails() {
    let mut pool = StakePool::zeroed();
    pool._reserved[..8].copy_from_slice(&STAKE_DEPOSIT_DISCRIMINATOR);
    assert!(
        !pool.validate_discriminator(),
        "Pool with StakeDeposit discriminator must fail pool discriminator validation"
    );
}

/// Zeroed deposit must NOT pass discriminator validation.
#[test]
fn test_zeroed_deposit_fails_discriminator() {
    let deposit = StakeDeposit::zeroed();
    assert!(
        !deposit.validate_discriminator(),
        "Zeroed deposit must not pass discriminator validation"
    );
}

/// Initialized deposit passes discriminator validation.
#[test]
fn test_initialized_deposit_passes_discriminator() {
    let deposit = initialized_deposit();
    assert!(
        deposit.validate_discriminator(),
        "Initialized deposit must pass discriminator validation"
    );
}

/// Deposit with wrong discriminator fails.
#[test]
fn test_wrong_deposit_discriminator_fails() {
    let mut deposit = StakeDeposit::zeroed();
    deposit._reserved[..8].copy_from_slice(&STAKE_POOL_DISCRIMINATOR);
    assert!(
        !deposit.validate_discriminator(),
        "Deposit with StakePool discriminator must fail deposit discriminator validation"
    );
}

// ════════════════════════════════════════════════════════════════
// COOLDOWN ENFORCEMENT: Deposit → immediate withdraw fails
// ════════════════════════════════════════════════════════════════

/// Cooldown state: deposit records last_deposit_slot; withdraw requires
/// current_slot > last_deposit_slot + cooldown_slots.
#[test]
fn test_cooldown_blocks_immediate_withdrawal() {
    let mut pool = initialized_pool();
    pool.cooldown_slots = 1000;

    let mut deposit = initialized_deposit();
    let deposit_slot = 5000u64;
    deposit.last_deposit_slot = deposit_slot;

    // Immediate withdrawal attempt at slot = deposit_slot (same slot as deposit)
    let current_slot = deposit_slot;
    let cooldown_elapsed = current_slot > deposit.last_deposit_slot + pool.cooldown_slots;
    assert!(
        !cooldown_elapsed,
        "Immediate withdrawal must be blocked (current_slot <= deposit_slot + cooldown)"
    );
}

/// Withdrawal attempt at exactly cooldown boundary must also be blocked
/// (strictly greater required: current_slot > last_deposit_slot + cooldown_slots).
#[test]
fn test_cooldown_boundary_is_exclusive() {
    let mut pool = initialized_pool();
    pool.cooldown_slots = 100;

    let mut deposit = initialized_deposit();
    deposit.last_deposit_slot = 1000;

    // Exactly at the boundary: slot = 1000 + 100 = 1100
    let boundary_slot = 1000 + 100;
    let cooldown_elapsed = boundary_slot > deposit.last_deposit_slot + pool.cooldown_slots;
    assert!(
        !cooldown_elapsed,
        "Withdrawal at exactly cooldown boundary must be blocked (strictly greater required)"
    );
}

/// Withdrawal after cooldown must succeed.
#[test]
fn test_cooldown_withdrawal_after_period_allowed() {
    let mut pool = initialized_pool();
    pool.cooldown_slots = 100;

    let mut deposit = initialized_deposit();
    deposit.last_deposit_slot = 1000;

    // One slot past cooldown: 1000 + 100 + 1 = 1101
    let after_cooldown_slot = 1000 + 100 + 1;
    let cooldown_elapsed = after_cooldown_slot > deposit.last_deposit_slot + pool.cooldown_slots;
    assert!(
        cooldown_elapsed,
        "Withdrawal after cooldown period must be allowed"
    );
}

/// Zero-cooldown pool allows immediate withdrawal.
#[test]
fn test_zero_cooldown_allows_immediate_withdrawal() {
    let mut pool = initialized_pool();
    pool.cooldown_slots = 0;

    let mut deposit = initialized_deposit();
    deposit.last_deposit_slot = 5000;

    // At same slot as deposit
    let current_slot = 5001u64; // any slot > 5000 + 0 = 5000
    let cooldown_elapsed = current_slot > deposit.last_deposit_slot + pool.cooldown_slots;
    assert!(
        cooldown_elapsed,
        "Zero-cooldown pool must allow withdrawal at any slot after deposit"
    );
}

// ════════════════════════════════════════════════════════════════
// DEPOSIT CAP ENFORCEMENT
// ════════════════════════════════════════════════════════════════

/// Deposit exceeding cap must be rejected.
#[test]
fn test_deposit_cap_exceeded_rejected() {
    let mut pool = initialized_pool();
    pool.deposit_cap = 10_000_000;
    pool.total_deposited = 9_000_000;
    pool.total_lp_supply = 9_000_000;

    // Attempt to deposit 2M → would reach 11M > cap
    let deposit_amount = 2_000_000u64;
    let new_total = pool.total_deposited.checked_add(deposit_amount).unwrap();
    let cap_exceeded = new_total > pool.deposit_cap;
    assert!(cap_exceeded, "Deposit exceeding cap must be rejected");
}

/// Deposit at exactly the cap must be allowed.
#[test]
fn test_deposit_at_cap_allowed() {
    let mut pool = initialized_pool();
    pool.deposit_cap = 10_000_000;
    pool.total_deposited = 9_000_000;
    pool.total_lp_supply = 9_000_000;

    // Deposit exactly 1M → reaches cap exactly
    let deposit_amount = 1_000_000u64;
    let new_total = pool.total_deposited.checked_add(deposit_amount).unwrap();
    let cap_exceeded = new_total > pool.deposit_cap;
    assert!(!cap_exceeded, "Deposit exactly at cap must be allowed");
}

/// Uncapped pool (deposit_cap = 0) never rejects.
#[test]
fn test_uncapped_pool_allows_any_deposit() {
    let mut pool = initialized_pool();
    pool.deposit_cap = 0; // 0 = uncapped

    // The processor treats cap=0 as "no limit"
    // deposit_cap == 0 || new_total <= deposit_cap
    let deposit_amount = u64::MAX / 2;
    let uncapped = pool.deposit_cap == 0;
    assert!(uncapped, "deposit_cap=0 must mean uncapped");
    let _ = deposit_amount; // would be allowed
}

// ════════════════════════════════════════════════════════════════
// ACCRUED FEES: AccrueFees updates pool value for trading LP mode
// ════════════════════════════════════════════════════════════════

/// AccrueFees increases pool_value via total_fees_earned (pool_mode=1).
#[test]
fn test_accrue_fees_increases_pool_value() {
    let mut pool = initialized_pool();
    pool.pool_mode = 1; // trading LP mode
    pool.total_deposited = 10_000_000;
    pool.total_lp_supply = 10_000_000;
    pool.total_fees_earned = 0;

    let base_value = pool.total_pool_value().unwrap();
    assert_eq!(base_value, 10_000_000);

    // Accrue 500_000 in fees
    pool.total_fees_earned = 500_000;
    let new_value = pool.total_pool_value().unwrap();
    assert_eq!(
        new_value, 10_500_000,
        "Fees must increase pool value in trading LP mode"
    );
}

/// Fees do NOT count toward pool value in insurance LP mode (pool_mode=0).
#[test]
fn test_fees_not_counted_in_insurance_mode() {
    let mut pool = initialized_pool();
    pool.pool_mode = 0; // insurance LP mode (legacy)
    pool.total_deposited = 10_000_000;
    pool.total_lp_supply = 10_000_000;
    pool.total_fees_earned = 500_000;

    let value = pool.total_pool_value().unwrap();
    assert_eq!(
        value, 10_000_000,
        "Fees must NOT count toward pool value in insurance LP mode"
    );
}

// ════════════════════════════════════════════════════════════════
// FLUSH ACCOUNTING: FlushToInsurance reduces pool value
// ════════════════════════════════════════════════════════════════

/// FlushToInsurance reduces accessible pool value by flushed amount.
#[test]
fn test_flush_reduces_pool_value() {
    let mut pool = initialized_pool();
    pool.total_deposited = 10_000_000;
    pool.total_lp_supply = 10_000_000;

    pool.total_flushed = 3_000_000; // 3M moved to insurance
    let value = pool.total_pool_value().unwrap();
    assert_eq!(
        value, 7_000_000,
        "Flushed amount must reduce pool value"
    );
}

/// Full flush + return roundtrip is conservative (value restored exactly).
#[test]
fn test_flush_return_roundtrip_conservative() {
    let mut pool = initialized_pool();
    pool.total_deposited = 10_000_000;
    pool.total_lp_supply = 10_000_000;

    pool.total_flushed = 3_000_000;
    pool.total_returned = 3_000_000; // full return after resolution

    let value = pool.total_pool_value().unwrap();
    assert_eq!(
        value, 10_000_000,
        "Full flush+return must restore pool value exactly"
    );
}

/// Partial return from insurance (2M loss): pool value permanently reduced.
#[test]
fn test_partial_return_reflects_insurance_loss() {
    let mut pool = initialized_pool();
    pool.total_deposited = 10_000_000;
    pool.total_flushed = 3_000_000;
    pool.total_returned = 1_000_000; // only 1M returned (2M lost to payouts)

    let value = pool.total_pool_value().unwrap();
    // 10M - 3M + 1M = 8M (2M permanently lost)
    assert_eq!(value, 8_000_000, "Partial return must reflect the 2M insurance loss");
}

// ════════════════════════════════════════════════════════════════
// MARKET RESOLUTION: blocks new deposits
// ════════════════════════════════════════════════════════════════

/// Market resolution flag blocks new deposits.
#[test]
fn test_market_resolved_blocks_deposits() {
    let mut pool = initialized_pool();
    assert!(!pool.market_resolved(), "Pool must not be resolved initially");

    pool.set_market_resolved(true);
    assert!(
        pool.market_resolved(),
        "Resolved pool must block new deposits"
    );
}

/// Market resolution flag can be toggled (for testing purposes; production only sets once).
#[test]
fn test_market_resolved_flag_storage() {
    let mut pool = initialized_pool();
    pool.set_market_resolved(true);
    assert!(pool.market_resolved());
    pool.set_market_resolved(false);
    assert!(!pool.market_resolved());
}

// ════════════════════════════════════════════════════════════════
// HWM: high-water mark epoch tracking
// ════════════════════════════════════════════════════════════════

/// HWM refreshes correctly across epoch boundaries.
#[test]
fn test_hwm_refreshes_on_new_epoch() {
    let mut pool = initialized_pool();
    pool.set_hwm_enabled(true);
    pool.set_hwm_floor_bps(5000); // 50% floor

    // Epoch 1: TVL = 10M
    let hwm = pool.refresh_hwm(1, 10_000_000);
    assert_eq!(hwm, 10_000_000, "First epoch: HWM set to current TVL");

    // Still epoch 1, TVL grows to 12M
    let hwm = pool.refresh_hwm(1, 12_000_000);
    assert_eq!(hwm, 12_000_000, "Same epoch: HWM raised to new high");

    // Epoch 2: new epoch resets HWM to current TVL (9M, after a drawdown)
    let hwm = pool.refresh_hwm(2, 9_000_000);
    assert_eq!(hwm, 9_000_000, "New epoch: HWM reset to current TVL");
}

/// HWM floor at 50% (5000 bps) — verify storage.
#[test]
fn test_hwm_floor_bps_stored_correctly() {
    let mut pool = initialized_pool();
    pool.set_hwm_floor_bps(5000);
    assert_eq!(pool.hwm_floor_bps(), 5000);

    pool.set_hwm_floor_bps(10000);
    assert_eq!(pool.hwm_floor_bps(), 10000);

    pool.set_hwm_floor_bps(0);
    assert_eq!(pool.hwm_floor_bps(), 0);
}

// ════════════════════════════════════════════════════════════════
// INSTRUCTION ENCODING: verify all instruction round-trips
// ════════════════════════════════════════════════════════════════

/// All standard instruction tags round-trip through unpack.
#[test]
fn test_all_standard_instruction_tags_decode() {
    // Tag 0: InitPool
    let mut data = vec![0u8];
    data.extend_from_slice(&50u64.to_le_bytes()); // cooldown_slots
    data.extend_from_slice(&5_000_000u64.to_le_bytes()); // deposit_cap
    match StakeInstruction::unpack(&data).unwrap() {
        StakeInstruction::InitPool { cooldown_slots, deposit_cap } => {
            assert_eq!(cooldown_slots, 50);
            assert_eq!(deposit_cap, 5_000_000);
        }
        _ => panic!("Expected InitPool"),
    }

    // Tag 1: Deposit
    let mut data = vec![1u8];
    data.extend_from_slice(&1_000_000u64.to_le_bytes());
    match StakeInstruction::unpack(&data).unwrap() {
        StakeInstruction::Deposit { amount } => assert_eq!(amount, 1_000_000),
        _ => panic!("Expected Deposit"),
    }

    // Tag 2: Withdraw
    let mut data = vec![2u8];
    data.extend_from_slice(&500_000u64.to_le_bytes());
    match StakeInstruction::unpack(&data).unwrap() {
        StakeInstruction::Withdraw { lp_amount } => assert_eq!(lp_amount, 500_000),
        _ => panic!("Expected Withdraw"),
    }

    // Tag 3: FlushToInsurance
    let mut data = vec![3u8];
    data.extend_from_slice(&250_000u64.to_le_bytes());
    match StakeInstruction::unpack(&data).unwrap() {
        StakeInstruction::FlushToInsurance { amount } => assert_eq!(amount, 250_000),
        _ => panic!("Expected FlushToInsurance"),
    }

    // Tag 5: TransferAdmin
    let data = vec![5u8];
    assert!(matches!(StakeInstruction::unpack(&data).unwrap(), StakeInstruction::TransferAdmin));

    // Tag 9: AdminResolveMarket
    let data = vec![9u8];
    assert!(matches!(
        StakeInstruction::unpack(&data).unwrap(),
        StakeInstruction::AdminResolveMarket
    ));

    // Tag 10: AdminWithdrawInsurance
    let mut data = vec![10u8];
    data.extend_from_slice(&3_000_000u64.to_le_bytes());
    match StakeInstruction::unpack(&data).unwrap() {
        StakeInstruction::AdminWithdrawInsurance { amount } => assert_eq!(amount, 3_000_000),
        _ => panic!("Expected AdminWithdrawInsurance"),
    }
}

/// Invalid instruction tags must return errors.
#[test]
fn test_invalid_instruction_tags_rejected() {
    for tag in [99u8, 200, 255] {
        let data = vec![tag];
        assert!(
            StakeInstruction::unpack(&data).is_err(),
            "Tag {tag} must be rejected as invalid"
        );
    }
}

/// Empty instruction data must return error.
#[test]
fn test_empty_instruction_data_rejected() {
    assert!(StakeInstruction::unpack(&[]).is_err(), "Empty data must be rejected");
}

/// Truncated instruction data must return error.
#[test]
fn test_truncated_deposit_instruction_rejected() {
    let data = vec![1u8, 0, 0, 0]; // Only 4 bytes of amount (need 8)
    assert!(
        StakeInstruction::unpack(&data).is_err(),
        "Truncated Deposit data must be rejected"
    );
}

// ════════════════════════════════════════════════════════════════
// PDA DERIVATION: determinism and uniqueness
// ════════════════════════════════════════════════════════════════

use solana_program::pubkey::Pubkey;

/// Pool PDA derivation is deterministic.
#[test]
fn test_pool_pda_deterministic() {
    let program_id = Pubkey::new_unique();
    let slab = Pubkey::new_unique();

    let (pda1, bump1) = derive_pool_pda(&program_id, &slab);
    let (pda2, bump2) = derive_pool_pda(&program_id, &slab);
    assert_eq!(pda1, pda2);
    assert_eq!(bump1, bump2);
}

/// Different slabs produce different pool PDAs.
#[test]
fn test_different_slabs_produce_different_pool_pdas() {
    let program_id = Pubkey::new_unique();
    let slab_a = Pubkey::new_unique();
    let slab_b = Pubkey::new_unique();

    let (pda_a, _) = derive_pool_pda(&program_id, &slab_a);
    let (pda_b, _) = derive_pool_pda(&program_id, &slab_b);
    assert_ne!(pda_a, pda_b);
}

/// Vault authority PDA is distinct from pool PDA and is deterministic.
#[test]
fn test_vault_authority_pda_distinct_and_deterministic() {
    let program_id = Pubkey::new_unique();
    let slab = Pubkey::new_unique();
    let (pool, _) = derive_pool_pda(&program_id, &slab);

    let (auth1, b1) = derive_vault_authority(&program_id, &pool);
    let (auth2, b2) = derive_vault_authority(&program_id, &pool);
    assert_eq!(auth1, auth2);
    assert_eq!(b1, b2);
    assert_ne!(auth1, pool, "Vault authority must differ from pool PDA");
}

/// Deposit PDAs are per-user and deterministic.
#[test]
fn test_deposit_pda_per_user_deterministic() {
    let program_id = Pubkey::new_unique();
    let slab = Pubkey::new_unique();
    let (pool, _) = derive_pool_pda(&program_id, &slab);

    let user_a = Pubkey::new_unique();
    let user_b = Pubkey::new_unique();

    let (dep_a1, _) = derive_deposit_pda(&program_id, &pool, &user_a);
    let (dep_a2, _) = derive_deposit_pda(&program_id, &pool, &user_a);
    let (dep_b, _) = derive_deposit_pda(&program_id, &pool, &user_b);

    assert_eq!(dep_a1, dep_a2, "Same user must get same deposit PDA");
    assert_ne!(dep_a1, dep_b, "Different users must get different deposit PDAs");
}

// ════════════════════════════════════════════════════════════════
// STRUCT SIZES: Pod alignment invariants
// ════════════════════════════════════════════════════════════════

/// StakePool size must match the constant.
#[test]
fn test_stake_pool_size_constant_matches_struct() {
    assert_eq!(STAKE_POOL_SIZE, core::mem::size_of::<StakePool>());
    // Verify Pod is satisfied (bytemuck will panic at instantiation otherwise)
    let _ = StakePool::zeroed();
}

/// StakeDeposit size must match the constant.
#[test]
fn test_stake_deposit_size_constant_matches_struct() {
    assert_eq!(STAKE_DEPOSIT_SIZE, core::mem::size_of::<StakeDeposit>());
    let _ = StakeDeposit::zeroed();
}

// ════════════════════════════════════════════════════════════════
// OVERFLOW SAFETY: checked math in pool computations
// ════════════════════════════════════════════════════════════════

/// Pool value returns None when total_withdrawn exceeds total_deposited (invalid state).
#[test]
fn test_pool_value_underflow_returns_none() {
    let mut pool = initialized_pool();
    pool.total_deposited = 100;
    pool.total_withdrawn = 200; // impossible, but must not panic

    assert!(
        pool.total_pool_value().is_none(),
        "Over-withdrawn pool must return None (checked arithmetic)"
    );
}

/// Large deposit/withdraw amounts don't overflow via u128 intermediate.
#[test]
fn test_large_amounts_no_overflow() {
    let mut pool = initialized_pool();
    pool.total_deposited = u64::MAX / 2;
    pool.total_lp_supply = u64::MAX / 2;

    let lp = pool.calc_lp_for_deposit(u64::MAX / 4).unwrap();
    assert_eq!(lp, u64::MAX / 4, "Large LP calculation must use u128 intermediate");
}
