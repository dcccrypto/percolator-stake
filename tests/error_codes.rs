//! Error code uniqueness and completeness tests.

use percolator_stake::error::StakeError;
use solana_program::program_error::ProgramError;

#[test]
fn test_all_error_codes_unique() {
    let codes: Vec<u32> = vec![
        StakeError::AlreadyInitialized as u32,
        StakeError::NotInitialized as u32,
        StakeError::Unauthorized as u32,
        StakeError::CooldownNotElapsed as u32,
        StakeError::InsufficientLpTokens as u32,
        StakeError::ZeroAmount as u32,
        StakeError::Overflow as u32,
        StakeError::InvalidMint as u32,
        StakeError::MarketResolved as u32,
        StakeError::DepositCapExceeded as u32,
        StakeError::InvalidPda as u32,
        11u32, // deprecated: was AdminAlreadyTransferred
        12u32, // deprecated: was AdminNotTransferred
        StakeError::InsufficientVaultBalance as u32,
        StakeError::InvalidPercolatorProgram as u32,
        StakeError::CpiFailed as u32,
        StakeError::InvalidAccount as u32,
        StakeError::InvalidPoolMode as u32,
        StakeError::WithdrawalBelowHwmFloor as u32,
        StakeError::TrancheNotEnabled as u32,
        StakeError::JuniorBalanceInsufficient as u32,
        StakeError::WrongTranche as u32,
    ];

    // Check uniqueness
    let mut sorted = codes.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), codes.len(), "Duplicate error codes detected!");

    // Check sequential (0..21)
    for (i, &code) in codes.iter().enumerate() {
        assert_eq!(
            code, i as u32,
            "Error code {} expected {}, got {}",
            i, i, code
        );
    }
}

#[test]
fn test_error_to_program_error() {
    let err: ProgramError = StakeError::Unauthorized.into();
    match err {
        ProgramError::Custom(code) => assert_eq!(code, 2),
        _ => panic!("Expected Custom error"),
    }
}

#[test]
fn test_all_errors_are_custom() {
    let errors = [
        StakeError::AlreadyInitialized,
        StakeError::NotInitialized,
        StakeError::Unauthorized,
        StakeError::CooldownNotElapsed,
        StakeError::InsufficientLpTokens,
        StakeError::ZeroAmount,
        StakeError::Overflow,
        StakeError::InvalidMint,
        StakeError::MarketResolved,
        StakeError::DepositCapExceeded,
        StakeError::InvalidPda,
        // 11, 12 deprecated (AdminAlreadyTransferred, AdminNotTransferred)
        StakeError::InsufficientVaultBalance,
        StakeError::InvalidPercolatorProgram,
        StakeError::CpiFailed,
        StakeError::InvalidAccount,
        StakeError::InvalidPoolMode,
        StakeError::WithdrawalBelowHwmFloor,
        StakeError::TrancheNotEnabled,
        StakeError::JuniorBalanceInsufficient,
        StakeError::WrongTranche,
    ];

    for err in &errors {
        let pe: ProgramError = (*err).into();
        assert!(matches!(pe, ProgramError::Custom(_)));
    }
}
