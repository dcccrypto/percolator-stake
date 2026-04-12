//! CPI tag verification tests.
//! Only one CPI remains: TopUpInsurance (tag 9).

#[test]
fn test_cpi_tag_top_up_insurance() {
    let mut data = Vec::with_capacity(9);
    data.push(9); // TAG_TOP_UP_INSURANCE
    data.extend_from_slice(&1000u64.to_le_bytes());
    assert_eq!(data[0], 9);
    assert_eq!(data.len(), 9);
}
