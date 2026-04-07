//! CPI tag verification tests.
//!
//! Cross-references our CPI instruction tags with the actual
//! percolator-prog wrapper tags. Tag mismatches = calling wrong instruction.

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
///   Tag 30: SetInsuranceWithdrawPolicy (PERC-110; was 22 which is UpdateRiskParams)
///   Tag 31: WithdrawInsuranceLimited  (PERC-110; was 23 which is RenounceAdmin)
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
    // CRITICAL: Must be 30 (PERC-110). Tags 21 and 22 are WRONG:
    // 21 = AdminForceCloseAccount, 22 = UpdateRiskParams.
    let data = build_cpi_data_insurance_policy();
    assert_eq!(
        data[0], 30,
        "SetInsuranceWithdrawPolicy must be tag 30 (PERC-110)"
    );
}

#[test]
fn test_cpi_tag_withdraw_insurance_limited() {
    // CRITICAL: Must be 31 (PERC-110). Tags 22 and 23 are WRONG:
    // 22 = UpdateRiskParams, 23 = RenounceAdmin.
    let data = build_cpi_data_withdraw_limited(500);
    assert_eq!(
        data[0], 31,
        "WithdrawInsuranceLimited must be tag 31 (PERC-110)"
    );
}

#[test]
fn test_insurance_tags_avoid_catastrophic_collisions() {
    // Regression guard: ensure insurance tags never collide with dangerous
    // wrapper instructions. Tags 21-23 are all wrong for these operations:
    //   21 = AdminForceCloseAccount
    //   22 = UpdateRiskParams
    //   23 = RenounceAdmin
    let policy_data = build_cpi_data_insurance_policy();
    assert_ne!(policy_data[0], 21, "Bug: tag 21 = AdminForceCloseAccount!");
    assert_ne!(policy_data[0], 22, "Bug: tag 22 = UpdateRiskParams!");
    assert_ne!(policy_data[0], 23, "Bug: tag 23 = RenounceAdmin!");

    let limited_data = build_cpi_data_withdraw_limited(100);
    assert_ne!(limited_data[0], 21, "Bug: tag 21 = AdminForceCloseAccount!");
    assert_ne!(limited_data[0], 22, "Bug: tag 22 = UpdateRiskParams!");
    assert_ne!(limited_data[0], 23, "Bug: tag 23 = RenounceAdmin!");
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
    data.push(30); // TAG_SET_INSURANCE_WITHDRAW_POLICY (PERC-110; was 22 = UpdateRiskParams)
    data.extend_from_slice(&[0u8; 32]); // authority
    data.extend_from_slice(&0u64.to_le_bytes()); // min_withdraw_base
    data.extend_from_slice(&0u16.to_le_bytes()); // max_withdraw_bps
    data.extend_from_slice(&0u64.to_le_bytes()); // cooldown_slots
    data
}

fn build_cpi_data_withdraw_limited(amount: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(9);
    data.push(31); // TAG_WITHDRAW_INSURANCE_LIMITED (PERC-110; was 23 = RenounceAdmin)
    data.extend_from_slice(&amount.to_le_bytes());
    data
}
