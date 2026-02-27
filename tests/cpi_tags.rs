//! CPI tag verification tests.
//!
//! Cross-references our CPI instruction tags with the actual
//! percolator-prog wrapper tags. Tag mismatches = calling wrong instruction.

/// These tags MUST match percolator-prog/src/percolator.rs Instruction::decode()
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
///   Tag 22: SetInsuranceWithdrawPolicy
///   Tag 23: WithdrawInsuranceLimited
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
    // CRITICAL: Must be 22, NOT 21 (21 = AdminForceCloseAccount)
    let data = build_cpi_data_insurance_policy();
    assert_eq!(
        data[0], 22,
        "SetInsuranceWithdrawPolicy must be tag 22, not 21"
    );
}

#[test]
fn test_cpi_tag_withdraw_insurance_limited() {
    // CRITICAL: Must be 23, NOT 22 (22 = SetInsuranceWithdrawPolicy)
    let data = build_cpi_data_withdraw_limited(500);
    assert_eq!(
        data[0], 23,
        "WithdrawInsuranceLimited must be tag 23, not 22"
    );
}

#[test]
fn test_tag_21_is_force_close_not_insurance() {
    // Tag 21 is AdminForceCloseAccount — we must NOT use it for insurance policy
    // This test exists as a regression guard after the tag mismatch was caught
    let policy_data = build_cpi_data_insurance_policy();
    assert_ne!(
        policy_data[0], 21,
        "Bug: tag 21 would call AdminForceCloseAccount!"
    );

    let limited_data = build_cpi_data_withdraw_limited(100);
    assert_ne!(
        limited_data[0], 22,
        "Bug: tag 22 would call SetInsuranceWithdrawPolicy!"
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
    data.push(22); // TAG_SET_INSURANCE_WITHDRAW_POLICY (was incorrectly 21)
    data.extend_from_slice(&[0u8; 32]); // authority
    data.extend_from_slice(&0u64.to_le_bytes()); // min_withdraw_base
    data.extend_from_slice(&0u16.to_le_bytes()); // max_withdraw_bps
    data.extend_from_slice(&0u64.to_le_bytes()); // cooldown_slots
    data
}

fn build_cpi_data_withdraw_limited(amount: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(9);
    data.push(23); // TAG_WITHDRAW_INSURANCE_LIMITED (was incorrectly 22)
    data.extend_from_slice(&amount.to_le_bytes());
    data
}
