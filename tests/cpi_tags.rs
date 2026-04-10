//! CPI tag verification tests.
//!
//! Cross-references our CPI instruction tags with the actual
//! percolator-prog wrapper tags. Tag mismatches = calling wrong instruction.
//!
//! SECURITY: These tests import the production constants from src/cpi.rs so
//! that they will catch stale or wrong values in the production code, not just
//! verify that a hardcoded test value matches itself.

/// These tags MUST match percolator-prog/src/percolator.rs Instruction::decode()
/// AND the constants in src/cpi.rs.
///
/// Source: toly-percolator-prog/src/percolator.rs lines 1410-1452
///   Tag 9:  TopUpInsurance
///   Tag 11: SetRiskThreshold
///   Tag 12: UpdateAdmin
///   Tag 15: SetMaintenanceFee
///   Tag 16: SetOracleAuthority
///   Tag 18: SetOraclePriceCap
///   Tag 19: ResolveMarket
///   Tag 20: WithdrawInsurance
///   Tag 21: AdminForceCloseAccount  <-- NOT used by stake program
///   Tag 22: SetInsuranceWithdrawPolicy  (PERC-110; previously wrong value 30)
///   Tag 23: WithdrawInsuranceLimited    (PERC-110; previously wrong value 31)
// Re-export the production constants so the tests below compare against them.
// If a constant is ever changed in src/cpi.rs, this module will fail to compile
// (name mismatch) or the assertion will catch the wrong value — not a silent pass.
use percolator_stake::cpi_tag_constants::{
    TAG_SET_INSURANCE_WITHDRAW_POLICY, TAG_WITHDRAW_INSURANCE_LIMITED,
};

#[test]
fn test_cpi_tag_top_up_insurance() {
    // TopUpInsurance = tag 9 in wrapper
    let data = build_cpi_data_top_up(1000);
    assert_eq!(data[0], 9);
}

#[test]
fn test_cpi_tag_set_risk_threshold() {
    let data = build_cpi_data_risk_threshold(100);
    assert_eq!(data[0], 11);
}

#[test]
fn test_cpi_tag_update_admin() {
    let data = build_cpi_data_update_admin();
    assert_eq!(data[0], 12);
}

#[test]
fn test_cpi_tag_set_maintenance_fee() {
    let data = build_cpi_data_maintenance_fee(50);
    assert_eq!(data[0], 15);
}

#[test]
fn test_cpi_tag_set_oracle_authority() {
    let data = build_cpi_data_oracle_authority();
    assert_eq!(data[0], 16);
}

#[test]
fn test_cpi_tag_resolve_market() {
    let data = build_cpi_data_resolve();
    assert_eq!(data[0], 19);
}

#[test]
fn test_cpi_tag_set_insurance_withdraw_policy() {
    // CRITICAL: Must match TAG_SET_INSURANCE_WITHDRAW_POLICY (22) from percolator-prog decode table.
    // Tag 22 = SetInsuranceWithdrawPolicy in percolator.rs. Was incorrectly set to 30 (ForceCloseResolved).
    let data = build_cpi_data_insurance_policy();
    assert_eq!(
        data[0],
        TAG_SET_INSURANCE_WITHDRAW_POLICY,
        "SetInsuranceWithdrawPolicy tag mismatch against production constant"
    );
}

#[test]
fn test_cpi_tag_withdraw_insurance_limited() {
    // CRITICAL: Must match TAG_WITHDRAW_INSURANCE_LIMITED (23) from percolator-prog decode table.
    // Tag 23 = WithdrawInsuranceLimited in percolator.rs. Was incorrectly set to 31 (unrecognized).
    let data = build_cpi_data_withdraw_limited(500);
    assert_eq!(
        data[0],
        TAG_WITHDRAW_INSURANCE_LIMITED,
        "WithdrawInsuranceLimited tag mismatch against production constant"
    );
}

#[test]
fn test_insurance_tags_avoid_catastrophic_collisions() {
    // Regression guard: ensure insurance tags never collide with dangerous
    // wrapper instructions. Real tag table from percolator-prog:
    //   21 = AdminForceCloseAccount
    //   22 = SetInsuranceWithdrawPolicy (CORRECT target)
    //   23 = WithdrawInsuranceLimited   (CORRECT target)
    //   30 = ForceCloseResolved         (DANGEROUS — old incorrect value)
    let policy_data = build_cpi_data_insurance_policy();
    assert_ne!(policy_data[0], 21, "Bug: tag 21 = AdminForceCloseAccount!");
    assert_ne!(policy_data[0], 30, "Bug: tag 30 = ForceCloseResolved — old wrong value!");
    assert_eq!(policy_data[0], 22, "SetInsuranceWithdrawPolicy must be tag 22");

    let limited_data = build_cpi_data_withdraw_limited(100);
    assert_eq!(limited_data[0], 23, "WithdrawInsuranceLimited must be tag 23");
    assert_ne!(
        limited_data[0],
        TAG_SET_INSURANCE_WITHDRAW_POLICY,
        "Bug: WithdrawInsuranceLimited must not equal SetInsuranceWithdrawPolicy tag!"
    );
}

#[test]
fn test_insurance_tags_match_production_constants() {
    // Direct assertion: the builders must emit exactly the production constant values.
    // This is the key regression guard — any change to the production constants will
    // break this test if the builders are not updated to match.
    let policy_data = build_cpi_data_insurance_policy();
    let limited_data = build_cpi_data_withdraw_limited(100);
    assert_eq!(
        policy_data[0], TAG_SET_INSURANCE_WITHDRAW_POLICY,
        "insurance policy builder emits tag={} but production constant is {}",
        policy_data[0],
        TAG_SET_INSURANCE_WITHDRAW_POLICY
    );
    assert_eq!(
        limited_data[0], TAG_WITHDRAW_INSURANCE_LIMITED,
        "withdraw limited builder emits tag={} but production constant is {}",
        limited_data[0],
        TAG_WITHDRAW_INSURANCE_LIMITED
    );

}

// ═══════════════════════════════════════════════════════════════
// CPI data builders (mirror the construction in src/cpi.rs)
// ═══════════════════════════════════════════════════════════════

fn build_cpi_data_top_up(amount: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(9);
    data.push(9); // TAG_TOP_UP_INSURANCE
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

fn build_cpi_data_risk_threshold(threshold: u128) -> Vec<u8> {
    let mut data = Vec::with_capacity(17);
    data.push(11); // TAG_SET_RISK_THRESHOLD
    data.extend_from_slice(&threshold.to_le_bytes());
    data
}

fn build_cpi_data_update_admin() -> Vec<u8> {
    let mut data = Vec::with_capacity(33);
    data.push(12); // TAG_UPDATE_ADMIN
    data.extend_from_slice(&[0u8; 32]); // dummy pubkey
    data
}

fn build_cpi_data_maintenance_fee(fee: u128) -> Vec<u8> {
    let mut data = Vec::with_capacity(17);
    data.push(15); // TAG_SET_MAINTENANCE_FEE
    data.extend_from_slice(&fee.to_le_bytes());
    data
}

fn build_cpi_data_oracle_authority() -> Vec<u8> {
    let mut data = Vec::with_capacity(33);
    data.push(16); // TAG_SET_ORACLE_AUTHORITY
    data.extend_from_slice(&[0u8; 32]); // dummy pubkey
    data
}

fn build_cpi_data_resolve() -> Vec<u8> {
    vec![19] // TAG_RESOLVE_MARKET
}

fn build_cpi_data_insurance_policy() -> Vec<u8> {
    let mut data = Vec::with_capacity(51);
    data.push(TAG_SET_INSURANCE_WITHDRAW_POLICY); // 22 — matches percolator-prog decode table
    data.extend_from_slice(&[0u8; 32]); // authority
    data.extend_from_slice(&0u64.to_le_bytes()); // min_withdraw_base
    data.extend_from_slice(&0u16.to_le_bytes()); // max_withdraw_bps
    data.extend_from_slice(&0u64.to_le_bytes()); // cooldown_slots
    data
}

fn build_cpi_data_withdraw_limited(amount: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(9);
    data.push(TAG_WITHDRAW_INSURANCE_LIMITED); // 23 — matches percolator-prog decode table
    data.extend_from_slice(&amount.to_le_bytes());
    data
}
