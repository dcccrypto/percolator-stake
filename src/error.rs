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
}

impl From<StakeError> for ProgramError {
    fn from(e: StakeError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
