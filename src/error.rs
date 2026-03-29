use solana_program::program_error::ProgramError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum StakeError {
    /// Pool already initialized for this slab
    AlreadyInitialized = 0,
    /// Pool not initialized
    NotInitialized = 1,
    /// Unauthorized — not admin
    Unauthorized = 2,
    /// Cooldown period not elapsed
    CooldownNotElapsed = 3,
    /// Insufficient LP tokens
    InsufficientLpTokens = 4,
    /// Zero amount
    ZeroAmount = 5,
    /// Arithmetic overflow
    Overflow = 6,
    /// Invalid mint — LP mint mismatch
    InvalidMint = 7,
    /// Market is resolved — no new deposits
    MarketResolved = 8,
    /// Deposit cap exceeded
    DepositCapExceeded = 9,
    /// Invalid PDA derivation
    InvalidPda = 10,
    /// Admin already transferred to pool PDA
    AdminAlreadyTransferred = 11,
    /// Admin not yet transferred — must call TransferAdmin first
    AdminNotTransferred = 12,
    /// Insufficient vault balance for withdrawal
    InsufficientVaultBalance = 13,
    /// Invalid percolator program ID
    InvalidPercolatorProgram = 14,
    /// CPI to percolator failed
    CpiFailed = 15,
    /// Invalid account ownership
    InvalidAccount = 16,
    /// Pool mode mismatch (e.g., AccrueFees on insurance pool)
    InvalidPoolMode = 17,
    /// Withdrawal blocked: would breach HWM floor
    WithdrawalBelowHwmFloor = 18,
    /// Tranches not enabled on this pool
    TrancheNotEnabled = 19,
    /// Junior tranche has insufficient balance for this operation
    JuniorBalanceInsufficient = 20,
    /// Wrong tranche — deposit PDA already belongs to a different tranche
    WrongTranche = 21,
}

impl From<StakeError> for ProgramError {
    fn from(e: StakeError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

/// Get user-friendly hint text for an error code.
/// Useful for off-chain clients and SDKs to provide actionable error guidance.
pub fn error_hint(code: u32) -> &'static str {
    match code {
        0 => "Pool already initialized — use a different slab address or check if InitPool was already called",
        1 => "Pool not initialized — call InitPool first to create the stake pool",
        2 => "Unauthorized — you must be the pool admin to perform this action",
        3 => "Cooldown not elapsed — wait for the cooldown period before withdrawing again",
        4 => "Insufficient LP tokens — you don't have enough LP tokens to burn",
        5 => "Zero amount — deposit and withdrawal amounts must be greater than zero",
        6 => "Arithmetic overflow — pool values exceeded u64 bounds, operation blocked",
        7 => "Invalid mint — LP mint doesn't match the pool's LP mint",
        8 => "Market is resolved — no new deposits allowed after resolution",
        9 => "Deposit cap exceeded — pool has reached its maximum deposit limit",
        10 => "Invalid PDA — account is not a valid PDA for the expected seed",
        11 => "Admin already transferred — transfer admin is a one-time operation",
        12 => "Admin not yet transferred — call TransferAdmin before performing admin operations",
        13 => "Insufficient vault balance — vault doesn't have enough collateral for this withdrawal",
        14 => "Invalid percolator program — percolator program ID doesn't match",
        15 => "CPI to percolator failed — the cross-program invoke to percolator failed",
        16 => "Invalid account — account is not owned by the expected program or is not writable",
        17 => "Pool mode mismatch — operation not valid for this pool's mode (e.g., AccrueFees on insurance pool)",
        18 => "Withdrawal blocked — would breach high-water mark floor protection",
        19 => "Tranches not enabled — senior/junior tranches are not enabled on this pool",
        20 => "Junior balance insufficient — junior tranche doesn't have enough balance for this operation",
        21 => "Wrong tranche — deposit already belongs to a different tranche",
        _ => "Unknown error — check the error code and pool state",
    }
}
