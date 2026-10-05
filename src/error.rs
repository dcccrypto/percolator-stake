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
    /// Deprecated (was AdminAlreadyTransferred) — code kept for stable numbering
    _DeprecatedAdminAlreadyTransferred = 11,
    /// Deprecated (was AdminNotTransferred) — code kept for stable numbering
    _DeprecatedAdminNotTransferred = 12,
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
    /// S-4: A deposit would mint zero LP shares (amount too small relative to
    /// share price, or degenerate pool state). Rejected explicitly so a deposit
    /// can never silently mint 0 LP while collateral is transferred in. Distinct
    /// from ZeroAmount (which means the requested amount itself was 0).
    ZeroSharesMinted = 22,
    /// Two-step admin rotation: no pending admin proposal exists (or it was
    /// cancelled), so AcceptAdmin has nothing to accept.
    NoPendingAdmin = 23,
    /// Reused across multiple gates that share the same underlying condition:
    /// `total_flushed > total_returned` (flushed-but-unrecovered insurance).
    /// - Junior tranche deposits are paused while an insurance loss is outstanding:
    ///   a junior depositing during an open claim would inherit a pre-existing
    ///   loss it was never exposed to (and the mirror case could snipe the
    ///   recovery). Deposits resume once insurance is returned.
    /// - H-1 (security review): `AdminResolveMarket` (tag 24) and `SetMarketResolved`
    ///   (tag 18) both reject while this condition holds, because once the wrapper
    ///   market is resolved (mode != 0), `RecoverFlushedInsurance`'s only CPI
    ///   (wrapper tag 57 WithdrawInsuranceAsset) permanently rejects with
    ///   EngineLockActive — any outstanding flush would otherwise be stranded.
    ///   Call `RecoverFlushedInsurance` until fully caught up before resolving.
    InsuranceLossOutstanding = 24,
    /// #242 timelock: a `cooldown_slots` INCREASE must go through the two-phase
    /// timelock (ProposeCooldownIncrease → wait TIMELOCK_SLOTS → CommitCooldownIncrease),
    /// not the immediate UpdateConfig path. A decrease or unchanged value is still
    /// allowed via UpdateConfig.
    CooldownIncreaseRequiresTimelock = 25,
    /// #242 timelock: CommitCooldownIncrease was called before TIMELOCK_SLOTS had
    /// elapsed since the proposal. LP holders are still inside their exit window.
    TimelockNotElapsed = 26,
    /// #242 timelock: CommitCooldownIncrease / CancelCooldownIncrease with no active
    /// proposal (cooldown_proposed_at_slot == 0).
    NoPendingCooldownProposal = 27,
    /// N7 (CONSOLIDATED-PLAN §2.2): the pool's true genesis deposit (total_lp_supply
    /// == 0 && total_pool_value == 0) must exceed MINIMUM_LIQUIDITY so the
    /// permanently-locked dead-share amount can be carved out of it. Deposits at or
    /// below MINIMUM_LIQUIDITY at genesis are rejected rather than silently minting
    /// 0 (or underflowing) LP to the first depositor.
    DepositBelowMinimumLiquidity = 28,
    /// F3 (fee-flow audit 2026-09-29): `AccrueFees` refused because the pool's only
    /// LP supply is the N7 `MINIMUM_LIQUIDITY` dead-share floor
    /// (`total_lp_supply <= MINIMUM_LIQUIDITY`). Fees booked now would belong to
    /// shares nobody can redeem. Nothing is booked; the fee tokens stay in the vault
    /// and are booked by the first accrual after a real staker deposits.
    NoRealLpHolders = 29,
    /// F-9: `RecoverTerminalInsurance` (tag 29) requires the bound wrapper market to
    /// be TERMINAL: Resolved (engine mode 1) or closed to a CloseSlab tombstone. A
    /// Live or Recovery market is refused; while Live, use `RecoverFlushedInsurance`
    /// (tag 23). A non-zero `amount` additionally requires Resolved, not Closed,
    /// because a closed market has nothing left to withdraw.
    MarketNotTerminal = 30,
    /// F-9: `RecoverTerminalInsurance` moved no tokens and booked nothing: `amount`
    /// was 0, no stray account was swept, and the pool vault holds no unbooked
    /// surplus. The call is refused so a keeper can tell a no-op from a recovery.
    NothingToRecover = 31,
    /// F-9 (security INFO): the bound wrapper market account is not the wrapper
    /// layout this program has pinned (magic, VERSION 19, kind, minimum length,
    /// known mode value). Its engine `mode` byte cannot be trusted, so the terminal
    /// recovery, the CloseSlab proxy, and the mode-0 deposit path all refuse rather
    /// than guess. A wrapper layout bump needs a coordinated stake upgrade.
    UnsupportedWrapperLayout = 32,
    // ── v5 (Phase 4 item 6): first-loss insurance staking ─────────────────────
    /// A FIRST_LOSS deposit must carry `accept_first_loss_version == pool.consent_version`
    /// (the signed, on-chain consent to the risk text). Missing or stale consent is refused.
    ConsentRequired = 33,
    /// Removed on v5: `FlushToInsurance` (the creator-admin flush) and
    /// `RecoverFlushedInsurance`. Deployment is the permissionless `SyncInsuranceDeployment`.
    DeprecatedV5 = 34,
    /// The wrapper `InsuranceUnitsV20` account is missing, not the PDA of this market under
    /// the pool's wrapper, not owned by it, the wrong layout/version, or its snapshot is not
    /// from the current slot (the wrapper refresh CPI did not run).
    InsuranceUnitsInvalid = 35,
    /// A first-loss withdrawal larger than the pool's liquid (vault-resident) value: the
    /// deployed part returns on the next `SyncInsuranceDeployment` recovery (healthy market).
    LiquidityBufferExhausted = 36,
    /// `SyncInsuranceDeployment` ran less than `sync_cooldown_slots` ago.
    SyncCooldownActive = 37,
    /// A deploy target / buffer / hysteresis / risk mode outside the protocol bounds, or a
    /// target change the signer may not make (the admin may only LOWER the target).
    InvalidDeployConfig = 38,
    /// Raising the deploy target needs the stake program's upgrade authority (Squads on
    /// mainnet), proven by the program-data account.
    NotProtocolAuthority = 39,
    /// `CommitDeployTarget` with no pending proposal, or before the timelock elapsed.
    NoPendingDeployTarget = 40,
    /// Not available on a FIRST_LOSS pool: tranches, HWM, admin rotation of the insurance
    /// authority/operator (it would strand the stakers' insurance units).
    NotSupportedOnFirstLoss = 41,
    /// A sync top-up needs the asset admin burned (no admin key can rotate the insurance
    /// authority away from the pool afterwards).
    AssetAdminNotBurned = 42,
    /// The sync found nothing to do (inside the hysteresis band, or no spare liquidity).
    NothingToSync = 43,
    /// W-5 / S-3 (security review 2026-10-05): the wrapper's mint (entry) reading differs from
    /// its free (exit) reading (a G9 receivable or a reservation is outstanding). Moving value
    /// into or out of the deployed units at that spread would transfer it between unit holders,
    /// so the sync top-up / recovery and a deposit into a pool with deployed units wait.
    InsuranceReadingsDiverged = 44,
    /// S-1 (security review 2026-10-05): the wrapper minted (top-up) or burned (recovery) a
    /// different number of stake units than `floor(a*U/I_mint)` / `ceil(r*U/I_free)`, or zero.
    InsuranceUnitsMismatch = 45,
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
        22 => "Zero shares minted — deposit amount too small to mint any LP at the current share price; increase the amount",
        23 => "No pending admin — there is no admin transfer to accept (propose one first, or it was cancelled)",
        24 => "Insurance loss outstanding — total_flushed > total_returned. Junior tranche deposits are paused, and AdminResolveMarket/SetMarketResolved are blocked until RecoverFlushedInsurance fully returns the flushed insurance (resolving first would strand it — recovery requires LIVE mode)",
        25 => "Cooldown increase requires a timelock — raising the cooldown is not immediate; propose it first, then apply it once the timelock has elapsed (#242)",
        26 => "Timelock not elapsed — the proposed cooldown increase is not yet applicable; wait for the timelock window to pass (#242)",
        27 => "No pending cooldown proposal — there is no proposed cooldown increase to apply; propose one first, or it was cancelled (#242)",
        28 => "Deposit below minimum liquidity — the pool's first-ever deposit must exceed MINIMUM_LIQUIDITY so a permanent dead-share floor can be locked (N7 anti-inflation hardening); deposit a larger amount",
        29 => "No real LP holders — the pool's only LP supply is the MINIMUM_LIQUIDITY dead-share floor, so AccrueFees refuses to book fees nobody could redeem; the fees stay in the vault and are booked once a real staker deposits (F3)",
        30 => "Market not terminal — RecoverTerminalInsurance needs the bound wrapper market to be Resolved (or closed); while the market is Live use RecoverFlushedInsurance, and a non-zero amount needs a Resolved (not closed) market (F-9)",
        31 => "Nothing to recover — no terminal insurance was withdrawn, no stray vault_auth token account was swept, and the pool vault has no unbooked surplus (F-9)",
        32 => "Unsupported wrapper layout — the bound market account is not the pinned wrapper layout (magic, VERSION 19, kind, minimum length), so its resolved/live state cannot be read; the stake program must be upgraded together with the wrapper (F-9)",
        33 => "Consent required — a first-loss stake deposit must carry the current risk-consent version; review and accept the risk text in the app",
        34 => "Deprecated on v5 — FlushToInsurance / RecoverFlushedInsurance were removed; deployment is the permissionless SyncInsuranceDeployment",
        35 => "Insurance units invalid — pass the wrapper's InsuranceUnitsV20 account for this market (it is refreshed in the same instruction)",
        36 => "Liquidity buffer exhausted — this withdrawal exceeds the pool's liquid value; the deployed part returns after the next sync on a healthy market",
        37 => "Sync cooldown active — SyncInsuranceDeployment ran recently; retry after sync_cooldown_slots",
        38 => "Invalid deploy config — target/buffer/hysteresis out of bounds, or the admin tried to raise the target",
        39 => "Not protocol authority — raising the deploy target needs the stake program's upgrade authority",
        40 => "No pending deploy target — propose a target first, or wait for its timelock (the pool cooldown)",
        41 => "Not supported on first-loss pools — tranches, HWM and admin rotation of the insurance authority are disabled",
        42 => "Asset admin not burned — burn the asset admin (BurnAssetAdmin) before stake can be deployed into insurance",
        43 => "Nothing to sync — the deployed value is within the hysteresis band of the target, or there is no spare liquidity",
        44 => "Insurance readings diverged — the market's insurance has a backstop loan or reservation outstanding; deposits into deployed units and syncs wait until it is repaid",
        45 => "Insurance units mismatch — the wrapper did not mint or burn the expected stake units; the sync was reverted",
        _ => "Unknown error — check the error code and pool state",
    }
}
