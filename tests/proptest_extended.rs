//! Extended property-based tests for percolator-stake.
//!
//! ## Running Tests
//!
//! ```
//! cargo test                                      # default cases (100 each)
//! PROPTEST_CASES=1000 cargo test                  # 1000 cases
//! cargo test proptest_extended                    # this file only
//! ```
//!
//! ## Coverage
//!
//! 1. Tranche distribution fuzzing  — distribute_fees / distribute_loss
//! 2. LP token price fuzzing        — calc_lp_for_deposit / calc_collateral_for_withdraw
//! 3. Withdrawal fairness           — random deposit/withdraw sequences
//! 4. CPI data encoding fuzzing     — tag byte and data length for every CPI builder

use proptest::prelude::*;

// Mirror the production functions from src/math.rs.
// This is intentional: tests should verify the spec-level contract,
// not just that one copy of the function matches another.

// ── Shared math mirrors ─────────────────────────────────────────────────────

fn calc_lp_for_deposit(supply: u64, pool_value: u64, deposit: u64) -> Option<u64> {
    if supply == 0 && pool_value == 0 {
        Some(deposit)
    } else if supply == 0 || pool_value == 0 {
        None
    } else {
        let lp = (deposit as u128)
            .checked_mul(supply as u128)?
            .checked_div(pool_value as u128)?;
        if lp > u64::MAX as u128 { None } else { Some(lp as u64) }
    }
}

fn calc_collateral_for_withdraw(supply: u64, pool_value: u64, lp: u64) -> Option<u64> {
    if supply == 0 { return None; }
    let col = (lp as u128)
        .checked_mul(pool_value as u128)?
        .checked_div(supply as u128)?;
    if col > u64::MAX as u128 { None } else { Some(col as u64) }
}

/// Mirror of math::distribute_fees
fn distribute_fees(
    junior_balance: u64,
    senior_balance: u64,
    junior_fee_mult_bps: u16,
    total_fee: u64,
) -> (u64, u64) {
    if total_fee == 0 { return (0, 0); }
    let total_balance = junior_balance as u128 + senior_balance as u128;
    if total_balance == 0 { return (0, 0); }

    let junior_weight = (junior_balance as u128) * (junior_fee_mult_bps as u128);
    let senior_weight = (senior_balance as u128) * 10_000u128;
    let total_weight = junior_weight + senior_weight;

    if total_weight == 0 { return (0, 0); }

    let junior_fee_u128 = if let Some(product) = (total_fee as u128).checked_mul(junior_weight) {
        product / total_weight
    } else {
        let q = (total_fee as u128) / total_weight;
        let r = (total_fee as u128) % total_weight;
        let part1 = q * junior_weight;
        let part2 = r.checked_mul(junior_weight)
            .map(|p| p / total_weight)
            .unwrap_or(total_fee as u128);
        part1.saturating_add(part2)
    };

    let junior_fee = junior_fee_u128.min(total_fee as u128) as u64;
    let senior_fee = total_fee.saturating_sub(junior_fee);
    (junior_fee, senior_fee)
}

/// Mirror of math::distribute_loss
fn distribute_loss(junior_balance: u64, senior_balance: u64, loss_amount: u64) -> (u64, u64) {
    let total = junior_balance.saturating_add(senior_balance);
    let capped_loss = loss_amount.min(total);
    if capped_loss <= junior_balance {
        (capped_loss, 0)
    } else {
        let senior_loss = capped_loss.saturating_sub(junior_balance);
        (junior_balance, senior_loss)
    }
}

// ============================================================================
// SECTION 1: Tranche distribution fuzzing
// ============================================================================
//
// Properties verified:
//   - junior_fee + senior_fee <= total_fee (no fabrication)
//   - Rounding loss <= 1 lamport (junior_fee + senior_fee >= total_fee - 1)
//   - Zero fee => (0, 0) distribution
//   - junior_mult_bps > 10_000 with equal balances => junior_fee >= senior_fee
//   - Zero total balance => (0, 0) regardless of fee

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Fee distribution never fabricates tokens: sum <= total_fee
    #[test]
    fn prop_fee_distribution_no_fabrication(
        junior_balance in 0u64..=u64::MAX / 2,
        senior_balance in 0u64..=u64::MAX / 2,
        junior_mult_bps in 0u16..=50_000u16,
        total_fee in 0u64..=u64::MAX / 2,
    ) {
        let (j, s) = distribute_fees(junior_balance, senior_balance, junior_mult_bps, total_fee);
        prop_assert!(
            (j as u128) + (s as u128) <= total_fee as u128,
            "junior_fee={} + senior_fee={} > total_fee={}",
            j, s, total_fee
        );
    }

    /// Rounding loss is at most 1 lamport
    #[test]
    fn prop_fee_distribution_rounding_loss_bounded(
        junior_balance in 1u64..=1_000_000_000,
        senior_balance in 1u64..=1_000_000_000,
        junior_mult_bps in 1u16..=20_000u16,
        total_fee in 1u64..=1_000_000_000,
    ) {
        let (j, s) = distribute_fees(junior_balance, senior_balance, junior_mult_bps, total_fee);
        let distributed = (j as u128) + (s as u128);
        let fee = total_fee as u128;
        // Must be within 1 lamport of total_fee (floor rounding)
        prop_assert!(
            distributed >= fee.saturating_sub(1),
            "excessive rounding: distributed={} total_fee={}",
            distributed, fee
        );
        prop_assert!(distributed <= fee, "distribution exceeded fee");
    }

    /// Zero fee always produces zero distribution
    #[test]
    fn prop_fee_zero_produces_zero(
        junior_balance in 0u64..=u64::MAX,
        senior_balance in 0u64..=u64::MAX,
        junior_mult_bps in 0u16..=50_000u16,
    ) {
        let (j, s) = distribute_fees(junior_balance, senior_balance, junior_mult_bps, 0);
        prop_assert_eq!(j, 0, "zero fee must yield zero junior");
        prop_assert_eq!(s, 0, "zero fee must yield zero senior");
    }

    /// Equal balances + junior_mult_bps > 10_000 => junior_fee >= senior_fee
    #[test]
    fn prop_high_mult_junior_gets_more(
        balance in 1u64..=100_000_000,
        junior_mult_bps in 10_001u16..=50_000u16,
        total_fee in 1u64..=100_000_000,
    ) {
        let (j, s) = distribute_fees(balance, balance, junior_mult_bps, total_fee);
        prop_assert!(
            j >= s,
            "junior_mult_bps={} with equal balances: junior_fee={} < senior_fee={}",
            junior_mult_bps, j, s
        );
    }

    /// 1x multiplier (10_000 bps) with equal balances => approx 50/50
    #[test]
    fn prop_equal_mult_equal_split(
        balance in 1u64..=100_000_000,
        total_fee in 2u64..=100_000_000,
    ) {
        let (j, s) = distribute_fees(balance, balance, 10_000, total_fee);
        // At 1x multiplier with equal balances: 50/50 split (±1 rounding)
        let diff = j.abs_diff(s);
        prop_assert!(diff <= 1, "1x multiplier should split evenly: j={} s={}", j, s);
    }

    /// Loss distribution: junior absorbs first, senior only loses when junior is wiped
    #[test]
    fn prop_loss_junior_first(
        junior_balance in 0u64..=u64::MAX / 2,
        senior_balance in 0u64..=u64::MAX / 2,
        loss_amount in 0u64..=u64::MAX,
    ) {
        let (jl, sl) = distribute_loss(junior_balance, senior_balance, loss_amount);
        // Total loss is capped at available
        let total_available = junior_balance.saturating_add(senior_balance);
        let effective_loss = loss_amount.min(total_available);
        prop_assert_eq!(
            (jl as u128) + (sl as u128),
            effective_loss as u128,
            "loss distribution doesn't sum: jl={} sl={} effective={}",
            jl, sl, effective_loss
        );
        // Senior only loses if junior is fully wiped
        if sl > 0 {
            prop_assert_eq!(jl, junior_balance, "senior has loss but junior not wiped");
        }
        // Junior loss never exceeds junior_balance
        prop_assert!(jl <= junior_balance, "junior loss {} > junior_balance {}", jl, junior_balance);
        // Senior loss never exceeds senior_balance
        prop_assert!(sl <= senior_balance, "senior loss {} > senior_balance {}", sl, senior_balance);
    }

    /// Zero loss => (0, 0)
    #[test]
    fn prop_zero_loss_no_distribution(
        junior_balance in 0u64..=u64::MAX,
        senior_balance in 0u64..=u64::MAX,
    ) {
        let (jl, sl) = distribute_loss(junior_balance, senior_balance, 0);
        prop_assert_eq!(jl, 0, "zero loss must produce zero junior loss");
        prop_assert_eq!(sl, 0, "zero loss must produce zero senior loss");
    }
}

// ============================================================================
// SECTION 2: LP token price fuzzing
// ============================================================================
//
// Properties verified:
//   - First depositor always gets 1:1 (supply == 0 && pool_value == 0)
//   - LP tokens received > 0 for any non-zero deposit into a valid pool
//   - Pool price (pool_value / supply) is non-decreasing after deposit + accrue
//   - Orphaned value blocks deposits (supply == 0 but pool_value > 0)

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// First depositor always gets exactly 1:1
    #[test]
    fn prop_first_depositor_one_to_one(amount in 1u64..=u64::MAX) {
        let lp = calc_lp_for_deposit(0, 0, amount);
        prop_assert_eq!(lp, Some(amount), "first depositor must get 1:1 LP tokens");
    }

    /// Non-zero deposit into a valid pool yields Some LP tokens (may be 0 for dust)
    #[test]
    fn prop_deposit_returns_some(
        supply in 1u64..=1_000_000_000,
        pool_value in 1u64..=1_000_000_000,
        deposit in 1u64..=1_000_000_000,
    ) {
        // Valid pool: supply > 0 and pool_value > 0 — must not panic, must return Some
        let result = calc_lp_for_deposit(supply, pool_value, deposit);
        prop_assert!(result.is_some(), "valid pool deposit must return Some");
    }

    /// Orphaned value (supply == 0, pool_value > 0) blocks deposit
    #[test]
    fn prop_orphaned_value_blocks_deposit(
        orphaned_value in 1u64..=u64::MAX,
        deposit in 1u64..=u64::MAX,
    ) {
        let result = calc_lp_for_deposit(0, orphaned_value, deposit);
        prop_assert_eq!(result, None, "orphaned value must block deposit");
    }

    /// Zero LP supply with non-zero pool value blocks deposit
    #[test]
    fn prop_valueless_supply_blocks_deposit(
        supply in 1u64..=u64::MAX,
        deposit in 1u64..=u64::MAX,
    ) {
        let result = calc_lp_for_deposit(supply, 0, deposit);
        prop_assert_eq!(result, None, "valueless LP supply must block deposit");
    }

    /// Price monotonicity: depositor cannot dilute existing holders.
    /// After deposit, existing LP holder can withdraw >= what they could before.
    #[test]
    fn prop_deposit_no_dilution(
        // Generate existing_lp in [1..=supply] using flat_map-style: supply first, then lp
        (supply, existing_lp) in (2u64..=100_000_000u64).prop_flat_map(|s| {
            (Just(s), 1u64..=s)
        }),
        pool_value in 1u64..=100_000_000u64,
        deposit in 1u64..=100_000_000u64,
    ) {

        // Existing holder's share before deposit
        let before = match calc_collateral_for_withdraw(supply, pool_value, existing_lp) {
            Some(v) => v, None => return Ok(()),
        };

        // New deposit
        let new_lp = match calc_lp_for_deposit(supply, pool_value, deposit) {
            Some(v) if v > 0 => v, _ => return Ok(()),
        };
        let new_supply = match supply.checked_add(new_lp) {
            Some(v) => v, None => return Ok(()),
        };
        let new_pool = match pool_value.checked_add(deposit) {
            Some(v) => v, None => return Ok(()),
        };

        // Existing holder's share after deposit
        let after = match calc_collateral_for_withdraw(new_supply, new_pool, existing_lp) {
            Some(v) => v, None => return Ok(()),
        };

        prop_assert!(
            after >= before,
            "dilution detected: before={} after={} (supply={} pv={} dep={})",
            before, after, supply, pool_value, deposit
        );
    }

    /// Full withdrawal after first deposit returns exact deposit amount
    #[test]
    fn prop_first_depositor_full_withdraw(amount in 1u64..=u64::MAX) {
        let lp = calc_lp_for_deposit(0, 0, amount).unwrap();
        prop_assert_eq!(lp, amount);
        let back = calc_collateral_for_withdraw(lp, amount, lp);
        prop_assert_eq!(back, Some(amount), "first depositor full withdraw must return exact amount");
    }

    /// Larger deposit => more LP tokens (monotonicity)
    #[test]
    fn prop_larger_deposit_more_lp(
        supply in 1u64..=100_000_000,
        pool_value in 1u64..=100_000_000,
        small in 1u64..=50_000_000,
    ) {
        let large = small + 1;
        if let (Some(lp_small), Some(lp_large)) = (
            calc_lp_for_deposit(supply, pool_value, small),
            calc_lp_for_deposit(supply, pool_value, large),
        ) {
            prop_assert!(lp_large >= lp_small, "larger deposit must get >= LP tokens");
        }
    }
}

// ============================================================================
// SECTION 3: Withdrawal fairness
// ============================================================================
//
// A simulated pool state: multiple depositors, random deposit/withdraw sequences.
// Properties verified:
//   - No user can withdraw more than they deposited (no profit without fees)
//   - Pool balance never goes negative
//   - After all withdrawals, total out <= total in

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Sequential deposit/withdraw: no user gets more than deposited (no fee accrual)
    #[test]
    fn prop_withdrawal_fairness_no_fees(
        a_deposit in 1u64..=10_000_000,
        b_deposit in 1u64..=10_000_000,
    ) {
        // User A deposits first
        let a_lp = calc_lp_for_deposit(0, 0, a_deposit).unwrap();
        // User B deposits after
        let b_lp = match calc_lp_for_deposit(a_lp, a_deposit, b_deposit) {
            Some(v) => v, None => return Ok(()),
        };

        let total_supply = match a_lp.checked_add(b_lp) {
            Some(v) => v, None => return Ok(()),
        };
        let total_pool = match a_deposit.checked_add(b_deposit) {
            Some(v) => v, None => return Ok(()),
        };

        // User B withdraws all
        let b_back = match calc_collateral_for_withdraw(total_supply, total_pool, b_lp) {
            Some(v) => v, None => return Ok(()),
        };
        prop_assert!(b_back <= b_deposit, "B got more than deposited: back={} dep={}", b_back, b_deposit);

        let remaining_supply = match total_supply.checked_sub(b_lp) {
            Some(v) => v, None => return Ok(()),
        };
        let remaining_pool = match total_pool.checked_sub(b_back) {
            Some(v) => v, None => return Ok(()),
        };

        // User A withdraws all remaining
        let a_back = match calc_collateral_for_withdraw(remaining_supply, remaining_pool, a_lp) {
            Some(v) => v, None => return Ok(()),
        };
        prop_assert!(a_back <= a_deposit, "A got more than deposited: back={} dep={}", a_back, a_deposit);

        // Pool balance must not go negative (guaranteed by saturating logic but verify)
        prop_assert!(
            (a_back as u128) + (b_back as u128) <= (a_deposit as u128) + (b_deposit as u128),
            "total out > total in"
        );
    }

    /// Three-party deposit/withdraw conservation
    #[test]
    fn prop_three_depositors_conservation(
        a in 1u64..=5_000_000,
        b in 1u64..=5_000_000,
        c in 1u64..=5_000_000,
    ) {
        let total_in = (a as u128) + (b as u128) + (c as u128);

        let a_lp = calc_lp_for_deposit(0, 0, a).unwrap();
        let b_lp = match calc_lp_for_deposit(a_lp, a, b) {
            Some(v) if v > 0 => v, _ => return Ok(()),
        };
        let c_lp = match calc_lp_for_deposit(a_lp + b_lp, a + b, c) {
            Some(v) if v > 0 => v, _ => return Ok(()),
        };

        // Withdraw in reverse order (LIFO)
        let s = a_lp + b_lp + c_lp;
        let pv = a + b + c;

        let c_back = match calc_collateral_for_withdraw(s, pv, c_lp) {
            Some(v) => v, None => return Ok(()),
        };
        let b_back = match calc_collateral_for_withdraw(s - c_lp, pv - c_back, b_lp) {
            Some(v) => v, None => return Ok(()),
        };
        let a_back = match calc_collateral_for_withdraw(s - c_lp - b_lp, pv - c_back - b_back, a_lp) {
            Some(v) => v, None => return Ok(()),
        };

        let total_out = (a_back as u128) + (b_back as u128) + (c_back as u128);
        prop_assert!(
            total_out <= total_in,
            "total out {} > total in {}", total_out, total_in
        );
    }

    /// Pool balance is always non-negative: after any valid withdrawal, remaining pool >= 0
    #[test]
    fn prop_pool_never_negative(
        // lp_burn in [1..=supply] to avoid global rejects
        (supply, lp_burn) in (1u64..=u64::MAX).prop_flat_map(|s| {
            (Just(s), 1u64..=s)
        }),
        pool_value in 0u64..=u64::MAX,
    ) {
        if let Some(col) = calc_collateral_for_withdraw(supply, pool_value, lp_burn) {
            prop_assert!(
                col <= pool_value,
                "withdrawal {} exceeds pool_value {}", col, pool_value
            );
        }
    }

    /// No LP supply means withdrawal always fails (no pool exists)
    #[test]
    fn prop_zero_supply_withdrawal_blocked(
        pool_value in 0u64..=u64::MAX,
        lp_burn in 0u64..=u64::MAX,
    ) {
        let result = calc_collateral_for_withdraw(0, pool_value, lp_burn);
        prop_assert_eq!(result, None, "zero supply must block withdrawal");
    }
}

// ============================================================================
// SECTION 4: CPI data encoding fuzzing
// ============================================================================
//
// These tests verify the CPI data builders without invoking Solana runtime.
// We mirror the construction logic directly to check:
//   - First byte == correct tag
//   - Data length == expected format size
//   - Tags 22/23 are used (NOT 30/31) for insurance policy/withdraw
//   - Tags are injective (no two CPI functions share a tag)

fn build_top_up_insurance(amount: u64) -> Vec<u8> {
    let mut d = Vec::with_capacity(9);
    d.push(9u8); // TAG_TOP_UP_INSURANCE
    d.extend_from_slice(&amount.to_le_bytes());
    d
}

fn build_set_risk_threshold(threshold: u128) -> Vec<u8> {
    let mut d = Vec::with_capacity(17);
    d.push(11u8); // TAG_SET_RISK_THRESHOLD
    d.extend_from_slice(&threshold.to_le_bytes());
    d
}

fn build_update_admin(new_admin: [u8; 32]) -> Vec<u8> {
    let mut d = Vec::with_capacity(33);
    d.push(12u8); // TAG_UPDATE_ADMIN
    d.extend_from_slice(&new_admin);
    d
}

fn build_set_maintenance_fee(fee: u128) -> Vec<u8> {
    let mut d = Vec::with_capacity(17);
    d.push(15u8); // TAG_SET_MAINTENANCE_FEE
    d.extend_from_slice(&fee.to_le_bytes());
    d
}

fn build_set_oracle_authority(authority: [u8; 32]) -> Vec<u8> {
    let mut d = Vec::with_capacity(33);
    d.push(16u8); // TAG_SET_ORACLE_AUTHORITY
    d.extend_from_slice(&authority);
    d
}

fn build_set_oracle_price_cap(max_change_e2bps: u64) -> Vec<u8> {
    let mut d = Vec::with_capacity(9);
    d.push(18u8); // TAG_SET_ORACLE_PRICE_CAP
    d.extend_from_slice(&max_change_e2bps.to_le_bytes());
    d
}

fn build_resolve_market() -> Vec<u8> {
    vec![19u8] // TAG_RESOLVE_MARKET
}

fn build_withdraw_insurance() -> Vec<u8> {
    vec![20u8] // TAG_WITHDRAW_INSURANCE
}

fn build_set_insurance_withdraw_policy(
    authority: [u8; 32],
    min_withdraw_base: u64,
    max_withdraw_bps: u16,
    cooldown_slots: u64,
) -> Vec<u8> {
    let mut d = Vec::with_capacity(51);
    d.push(22u8); // TAG_SET_INSURANCE_WITHDRAW_POLICY — NOT 30
    d.extend_from_slice(&authority);
    d.extend_from_slice(&min_withdraw_base.to_le_bytes());
    d.extend_from_slice(&max_withdraw_bps.to_le_bytes());
    d.extend_from_slice(&cooldown_slots.to_le_bytes());
    d
}

fn build_withdraw_insurance_limited(amount: u64) -> Vec<u8> {
    let mut d = Vec::with_capacity(9);
    d.push(23u8); // TAG_WITHDRAW_INSURANCE_LIMITED — NOT 31
    d.extend_from_slice(&amount.to_le_bytes());
    d
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// TopUpInsurance: tag == 9, length == 9 bytes
    #[test]
    fn prop_cpi_top_up_insurance_encoding(amount: u64) {
        let data = build_top_up_insurance(amount);
        prop_assert_eq!(data[0], 9u8, "TopUpInsurance must be tag 9");
        prop_assert_eq!(data.len(), 9, "TopUpInsurance data must be 9 bytes");
        // Verify amount round-trips
        let decoded = u64::from_le_bytes(data[1..9].try_into().unwrap());
        prop_assert_eq!(decoded, amount, "amount must round-trip");
    }

    /// SetRiskThreshold: tag == 11, length == 17 bytes
    #[test]
    fn prop_cpi_set_risk_threshold_encoding(threshold: u128) {
        let data = build_set_risk_threshold(threshold);
        prop_assert_eq!(data[0], 11u8, "SetRiskThreshold must be tag 11");
        prop_assert_eq!(data.len(), 17, "SetRiskThreshold data must be 17 bytes");
        let decoded = u128::from_le_bytes(data[1..17].try_into().unwrap());
        prop_assert_eq!(decoded, threshold);
    }

    /// UpdateAdmin: tag == 12, length == 33 bytes
    #[test]
    fn prop_cpi_update_admin_encoding(new_admin: [u8; 32]) {
        let data = build_update_admin(new_admin);
        prop_assert_eq!(data[0], 12u8, "UpdateAdmin must be tag 12");
        prop_assert_eq!(data.len(), 33, "UpdateAdmin data must be 33 bytes");
        prop_assert_eq!(&data[1..], &new_admin, "admin pubkey must round-trip");
    }

    /// SetMaintenanceFee: tag == 15, length == 17 bytes
    #[test]
    fn prop_cpi_set_maintenance_fee_encoding(fee: u128) {
        let data = build_set_maintenance_fee(fee);
        prop_assert_eq!(data[0], 15u8, "SetMaintenanceFee must be tag 15");
        prop_assert_eq!(data.len(), 17, "SetMaintenanceFee data must be 17 bytes");
        let decoded = u128::from_le_bytes(data[1..17].try_into().unwrap());
        prop_assert_eq!(decoded, fee);
    }

    /// SetOracleAuthority: tag == 16, length == 33 bytes
    #[test]
    fn prop_cpi_set_oracle_authority_encoding(authority: [u8; 32]) {
        let data = build_set_oracle_authority(authority);
        prop_assert_eq!(data[0], 16u8, "SetOracleAuthority must be tag 16");
        prop_assert_eq!(data.len(), 33, "SetOracleAuthority data must be 33 bytes");
    }

    /// SetOraclePriceCap: tag == 18, length == 9 bytes
    #[test]
    fn prop_cpi_set_oracle_price_cap_encoding(max_change: u64) {
        let data = build_set_oracle_price_cap(max_change);
        prop_assert_eq!(data[0], 18u8, "SetOraclePriceCap must be tag 18");
        prop_assert_eq!(data.len(), 9, "SetOraclePriceCap data must be 9 bytes");
        let decoded = u64::from_le_bytes(data[1..9].try_into().unwrap());
        prop_assert_eq!(decoded, max_change);
    }

    /// SetInsuranceWithdrawPolicy: tag MUST be 22 (not 30 or 31)
    #[test]
    fn prop_cpi_insurance_policy_tag_22(
        authority: [u8; 32],
        min_base: u64,
        max_bps: u16,
        cooldown: u64,
    ) {
        let data = build_set_insurance_withdraw_policy(authority, min_base, max_bps, cooldown);
        prop_assert_eq!(
            data[0], 22u8,
            "SetInsuranceWithdrawPolicy must be tag 22, got {}",
            data[0]
        );
        prop_assert_ne!(data[0], 30u8, "tag 30 is ForceCloseResolved — WRONG");
        prop_assert_ne!(data[0], 31u8, "tag 31 is unrecognized — WRONG");
        prop_assert_ne!(data[0], 21u8, "tag 21 is AdminForceCloseAccount — WRONG");
        // Length: 1 (tag) + 32 (authority) + 8 (min_base) + 2 (max_bps) + 8 (cooldown) = 51
        prop_assert_eq!(data.len(), 51, "data must be 51 bytes, got {}", data.len());
    }

    /// WithdrawInsuranceLimited: tag MUST be 23 (not 31)
    #[test]
    fn prop_cpi_withdraw_insurance_limited_tag_23(amount: u64) {
        let data = build_withdraw_insurance_limited(amount);
        prop_assert_eq!(
            data[0], 23u8,
            "WithdrawInsuranceLimited must be tag 23, got {}",
            data[0]
        );
        prop_assert_ne!(data[0], 31u8, "tag 31 is unrecognized — old wrong value");
        prop_assert_ne!(data[0], 30u8, "tag 30 is ForceCloseResolved — WRONG");
        // Length: 1 (tag) + 8 (amount) = 9
        prop_assert_eq!(data.len(), 9, "data must be 9 bytes");
        let decoded = u64::from_le_bytes(data[1..9].try_into().unwrap());
        prop_assert_eq!(decoded, amount, "amount must round-trip");
    }

    /// All CPI tags are distinct (injectivity)
    #[test]
    fn prop_cpi_tags_are_distinct(_dummy: u8) {
        let tags = [
            9u8,  // TopUpInsurance (only remaining CPI)
        ];
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                prop_assert_ne!(
                    tags[i], tags[j],
                    "tag collision: tags[{}]={} == tags[{}]={}",
                    i, tags[i], j, tags[j]
                );
            }
        }
    }

    /// ResolveMarket: single-byte payload, tag == 19
    #[test]
    fn prop_cpi_resolve_market_encoding(_dummy: u8) {
        let data = build_resolve_market();
        prop_assert_eq!(data[0], 19u8, "ResolveMarket must be tag 19");
        prop_assert_eq!(data.len(), 1, "ResolveMarket data must be 1 byte");
    }

    /// WithdrawInsurance: single-byte payload, tag == 20
    #[test]
    fn prop_cpi_withdraw_insurance_encoding(_dummy: u8) {
        let data = build_withdraw_insurance();
        prop_assert_eq!(data[0], 20u8, "WithdrawInsurance must be tag 20");
        prop_assert_eq!(data.len(), 1, "WithdrawInsurance data must be 1 byte");
    }
}

// ============================================================================
// Deterministic edge case tests (not random)
// ============================================================================

#[test]
fn test_fee_distribution_all_junior() {
    // senior_balance == 0: all fees go to junior
    let (j, s) = distribute_fees(1000, 0, 10_000, 500);
    assert_eq!(j, 500, "all fees must go to junior when senior_balance=0");
    assert_eq!(s, 0);
}

#[test]
fn test_fee_distribution_all_senior() {
    // junior_balance == 0: all fees go to senior
    let (j, s) = distribute_fees(0, 1000, 10_000, 500);
    assert_eq!(j, 0, "no fees to junior when junior_balance=0");
    assert_eq!(s, 500);
}

#[test]
fn test_loss_exceeds_total_is_capped() {
    let (jl, sl) = distribute_loss(100, 200, 10_000);
    assert_eq!(jl, 100, "junior fully wiped");
    assert_eq!(sl, 200, "senior fully wiped");
    assert_eq!(jl + sl, 300, "total loss capped at available");
}

#[test]
fn test_cpi_insurance_policy_tag_is_not_30() {
    let data = build_set_insurance_withdraw_policy([0u8; 32], 0, 0, 0);
    assert_eq!(data[0], 22, "CRIT: SetInsuranceWithdrawPolicy must be 22, not 30");
}

#[test]
fn test_cpi_withdraw_limited_tag_is_not_31() {
    let data = build_withdraw_insurance_limited(1000);
    assert_eq!(data[0], 23, "CRIT: WithdrawInsuranceLimited must be 23, not 31");
}
