use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program::invoke,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::{clock::Clock, Sysvar},
};

/// Verify the token program is the real SPL Token program.
/// CRITICAL: Without this check, an attacker can pass a fake token program,
/// receive PDA signer authority via invoke_signed, and drain the vault.
fn verify_token_program(token_program: &AccountInfo) -> ProgramResult {
    if *token_program.key != crate::spl_token::id() {
        msg!("Error: invalid token program {}", token_program.key);
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}

/// Create a program-owned PDA at `target`, robust to an attacker having pre-funded the
/// (deterministic) address with lamports.
///
/// A bare `system_instruction::create_account` aborts with `AccountAlreadyInUse` when the
/// destination already holds lamports. Because every PDA address here is deterministic,
/// a griefer could permanently block creation by sending 1 lamport to the address (a plain
/// `transfer`, which needs no signature from the destination). The *only* state a third
/// party can force on a not-yet-created PDA is `(lamports >= 0, data empty, System-owned)`:
/// they cannot `allocate`/`assign`/`create_account` it, because all three require the PDA
/// itself to sign, and only this program can produce that signature via `invoke_signed`
/// over the seeds. So:
///   - unfunded (lamports == 0): a single `create_account` (identical to the old behavior).
///   - pre-funded: top up to rent-exemption if short, then `allocate` then `assign`. The
///     order matters — `allocate` requires the account to still be System-owned, and
///     `assign` hands ownership to this program, so `allocate` MUST precede `assign`.
/// `allocate` zero-fills the data, so an adopted account is byte-identical to a freshly
/// created one. `need - have` is computed only under `have < need`, so it cannot underflow;
/// surplus lamports (over-funding) are simply retained by the PDA. `payer` must be a
/// transaction signer (the `transfer` uses a plain `invoke`); `signer_seeds` are the PDA
/// seeds incl. bump (used by every `invoke_signed`). Any sub-step error reverts the whole
/// transaction, so no half-created account can persist. Callers must run the
/// wrong-owner-with-data guard and the PDA address-binding check first.
fn create_or_adopt_pda<'a>(
    target: &AccountInfo<'a>,
    payer: &AccountInfo<'a>,
    system_program: &AccountInfo<'a>,
    owner: &Pubkey,
    space: usize,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    let rent = Rent::get()?;
    let need = rent.minimum_balance(space);

    if target.lamports() == 0 {
        // Pristine address — single atomic create_account (unchanged fast path).
        invoke_signed(
            &system_instruction::create_account(payer.key, target.key, need, space as u64, owner),
            &[payer.clone(), target.clone(), system_program.clone()],
            &[signer_seeds],
        )?;
        return Ok(());
    }

    // Pre-funded address (the squat case): the account is still System-owned with zero
    // data (a griefer can only have transferred lamports), so finish the create manually.
    let have = target.lamports();
    if have < need {
        // Top up the rent shortfall only. payer signs the tx, so a plain invoke suffices.
        invoke(
            &system_instruction::transfer(payer.key, target.key, need - have),
            &[payer.clone(), target.clone(), system_program.clone()],
        )?;
    }
    invoke_signed(
        &system_instruction::allocate(target.key, space as u64),
        &[target.clone(), system_program.clone()],
        &[signer_seeds],
    )?;
    invoke_signed(
        &system_instruction::assign(target.key, owner),
        &[target.clone(), system_program.clone()],
        &[signer_seeds],
    )?;
    Ok(())
}

/// Upper bound on cooldown_slots (~1 year at ~2.5 slots/sec ≈ 78.84M slots). Long
/// enough for any realistic withdrawal cooldown, but finite so an admin cannot set
/// cooldown_slots = u64::MAX (via InitPool/UpdateConfig) and permanently lock
/// withdrawals — `clock.slot` would never reach the saturating deadline (#121).
const MAX_COOLDOWN_SLOTS: u64 = 78_840_000;

/// Upper bound on `hwm_floor_bps` (90%). The high-water-mark floor is a per-epoch
/// drain RATE LIMITER, not a withdrawal kill switch. At 10_000 (100%) the floor
/// equals the full water mark, and because `refresh_hwm` keeps the mark at or above
/// current TVL (and re-anchors it to current TVL on every new epoch), ANY positive
/// withdrawal lands below the floor — a permanent, pool-wide withdrawal freeze that
/// even survives epoch rollover. Capping strictly below 100% guarantees the floor is
/// always below the mark; 90% in particular keeps at least 10% of peak TVL
/// withdrawable per epoch, so the feature stays a rate limiter while still allowing a
/// very aggressive anti-drain posture. This mirrors `MAX_COOLDOWN_SLOTS` (#121),
/// which finitely bounds the cooldown for the same "an admin must never be able to
/// permanently lock withdrawals" reason.
const MAX_HWM_FLOOR_BPS: u16 = 9_000;

/// Pool PDA account index in the InitPool-compatible account layout:
/// admin=0, slab=1, pool_pda=2.
const INIT_POOL_POOL_PDA_INDEX: usize = 2;

/// Validate cooldown_slots parameter: must be > 0 to enforce cooldown, and bounded
/// above so it cannot be used to permanently freeze withdrawals.
fn validate_cooldown_slots(cooldown_slots: u64) -> ProgramResult {
    if cooldown_slots == 0 {
        msg!("Invalid cooldown_slots: cannot be 0 (would disable cooldown protection)");
        return Err(ProgramError::InvalidArgument);
    }
    if cooldown_slots > MAX_COOLDOWN_SLOTS {
        msg!("Invalid cooldown_slots: exceeds maximum (~1 year of slots); would permanently lock withdrawals");
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

/// Validate HWM floor basis points: must be in range [1, MAX_HWM_FLOOR_BPS].
///
/// The upper bound is strictly below 100% (10_000): a 100% floor would equal the
/// high-water mark and, because `refresh_hwm` keeps the mark at or above current TVL
/// each epoch, would permanently freeze every withdrawal. Bounding it below 100%
/// keeps the floor a per-epoch drain rate limiter that always leaves exit headroom.
fn validate_hwm_floor_bps(hwm_floor_bps: u16) -> ProgramResult {
    if hwm_floor_bps == 0 || hwm_floor_bps > MAX_HWM_FLOOR_BPS {
        msg!(
            "Invalid hwm_floor_bps: must be 1-{}, got {}",
            MAX_HWM_FLOOR_BPS,
            hwm_floor_bps
        );
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

/// Validate that an account is owned by the expected program.
/// Returns InvalidAccount error if ownership doesn't match.
fn validate_account_owner(account: &AccountInfo, expected_owner: &Pubkey) -> ProgramResult {
    if *account.owner != *expected_owner {
        msg!(
            "Error: account {} owned by {}, expected {}",
            account.key,
            account.owner,
            expected_owner
        );
        return Err(StakeError::InvalidAccount.into());
    }
    Ok(())
}

/// Validate stake pool account version for forward compatibility.
/// Currently enforces current version only. In future, can add migration logic.
fn validate_pool_version(pool: &StakePool) -> ProgramResult {
    let version = pool.version();
    if version != StakePool::CURRENT_VERSION {
        msg!(
            "Error: pool version {} not supported (current: {})",
            version,
            StakePool::CURRENT_VERSION
        );
        return Err(StakeError::InvalidAccount.into());
    }
    Ok(())
}

/// Validate that an account is writable.
/// Returns InvalidAccount error if account is read-only.
fn validate_account_writable(account: &AccountInfo) -> ProgramResult {
    if !account.is_writable {
        msg!("Error: account {} must be writable", account.key);
        return Err(StakeError::InvalidAccount.into());
    }
    Ok(())
}

/// Validate that an account is NOT empty (has data or is initialized).
/// Returns InvalidAccount error if account is empty and shouldn't be.
fn validate_account_not_empty(account: &AccountInfo) -> ProgramResult {
    if account.data_is_empty() {
        msg!("Error: account {} is empty but expected data", account.key);
        return Err(StakeError::InvalidAccount.into());
    }
    Ok(())
}

/// #211: validate that the LP-mint recipient token account is owned by the
/// depositor (and has the pool's lp_mint). Without this, a deposit can mint LP
/// receipts to a token account the depositor does not control while the deposit
/// record stays keyed to the depositor — stranding the receipt / enabling
/// delegation-griefing. Mirrors the withdraw-side recipient checks.
fn validate_lp_recipient_account(
    user_lp_ata: &AccountInfo,
    expected_lp_mint: &[u8; 32],
    expected_owner: &Pubkey,
) -> ProgramResult {
    if *user_lp_ata.owner != crate::spl_token::id() {
        msg!("Error: user_lp_ata is not owned by the SPL Token program");
        return Err(StakeError::InvalidAccount.into());
    }

    let lp_ata_data = user_lp_ata.try_borrow_data()?;
    if lp_ata_data.len() < crate::spl_token::state::ACCOUNT_LEN {
        return Err(StakeError::InvalidAccount.into());
    }

    let mint_bytes: &[u8; 32] = lp_ata_data[0..32]
        .try_into()
        .map_err(|_| StakeError::InvalidAccount)?;
    if mint_bytes != expected_lp_mint {
        msg!("Error: user_lp_ata mint does not match pool lp_mint");
        return Err(StakeError::InvalidMint.into());
    }

    let owner_bytes: &[u8; 32] = lp_ata_data[32..64]
        .try_into()
        .map_err(|_| StakeError::InvalidAccount)?;
    if owner_bytes != expected_owner.as_ref() {
        msg!("Error: user_lp_ata is not owned by the depositor — delegation/griefing blocked");
        return Err(StakeError::Unauthorized.into());
    }

    Ok(())
}

/// Validate that an account is empty (no data, ready for creation).
/// Returns AlreadyInitialized error if account already has data.
#[allow(dead_code)]
fn validate_account_empty(account: &AccountInfo) -> ProgramResult {
    if !account.data_is_empty() {
        msg!("Error: account {} already initialized", account.key);
        return Err(StakeError::AlreadyInitialized.into());
    }
    Ok(())
}

use crate::cpi;
use crate::error::StakeError;
use crate::instruction::StakeInstruction;
use crate::state::{
    self, derive_vault_authority, StakeDeposit, StakePool, STAKE_DEPOSIT_SIZE, STAKE_POOL_SIZE,
};

// ─────────────────────────────────────────────────────────────────────────
// #199: length-checked bytemuck reinterpretation helpers.
//
// Every handler reinterprets an account's data as a StakePool / StakeDeposit by
// slicing `data[..SIZE]`. A program-owned but undersized account (e.g. an
// attacker's own StakeDeposit PDA, which is STAKE_DEPOSIT_SIZE < STAKE_POOL_SIZE,
// passed where a pool is expected) makes that bare slice PANIC instead of
// returning a clean ProgramError. These helpers centralize the `len() >= SIZE`
// guard so it can never be forgotten at a call site, and use `try_from_bytes` so
// they are also alignment-safe (never panic). Each takes the ALREADY-BORROWED
// slice (from `try_borrow_mut_data()` / `try_borrow_data()`), so the RefMut/Ref
// guard stays at the call site and the returned reference borrows that slice for
// the same scope — identical codegen to the previous inline form on the happy
// path, with an added early Err for short/misaligned data.
fn pool_from_data_mut(data: &mut [u8]) -> Result<&mut StakePool, ProgramError> {
    if data.len() < STAKE_POOL_SIZE {
        return Err(StakeError::InvalidAccount.into());
    }
    bytemuck::try_from_bytes_mut::<StakePool>(&mut data[..STAKE_POOL_SIZE])
        .map_err(|_| ProgramError::InvalidAccountData)
}

fn pool_from_data(data: &[u8]) -> Result<&StakePool, ProgramError> {
    if data.len() < STAKE_POOL_SIZE {
        return Err(StakeError::InvalidAccount.into());
    }
    bytemuck::try_from_bytes::<StakePool>(&data[..STAKE_POOL_SIZE])
        .map_err(|_| ProgramError::InvalidAccountData)
}

fn deposit_from_data_mut(data: &mut [u8]) -> Result<&mut StakeDeposit, ProgramError> {
    if data.len() < STAKE_DEPOSIT_SIZE {
        return Err(StakeError::InvalidAccount.into());
    }
    bytemuck::try_from_bytes_mut::<StakeDeposit>(&mut data[..STAKE_DEPOSIT_SIZE])
        .map_err(|_| ProgramError::InvalidAccountData)
}

fn deposit_from_data(data: &[u8]) -> Result<&StakeDeposit, ProgramError> {
    if data.len() < STAKE_DEPOSIT_SIZE {
        return Err(StakeError::InvalidAccount.into());
    }
    bytemuck::try_from_bytes::<StakeDeposit>(&data[..STAKE_DEPOSIT_SIZE])
        .map_err(|_| ProgramError::InvalidAccountData)
}

pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = StakeInstruction::unpack(instruction_data)?;

    match instruction {
        StakeInstruction::InitPool {
            cooldown_slots,
            deposit_cap,
        } => process_init_pool(program_id, accounts, cooldown_slots, deposit_cap),
        StakeInstruction::Deposit { amount } => process_deposit(program_id, accounts, amount),
        StakeInstruction::Withdraw { lp_amount } => {
            process_withdraw(program_id, accounts, lp_amount)
        }
        StakeInstruction::FlushToInsurance { amount } => {
            process_flush_to_insurance(program_id, accounts, amount)
        }
        StakeInstruction::UpdateConfig {
            new_cooldown_slots,
            new_deposit_cap,
        } => process_update_config(program_id, accounts, new_cooldown_slots, new_deposit_cap),
        StakeInstruction::ProposeAdmin { new_admin } => {
            process_propose_admin(program_id, accounts, new_admin)
        }
        StakeInstruction::AcceptAdmin => process_accept_admin(program_id, accounts),
        StakeInstruction::BindInsuranceAuthority => {
            process_bind_insurance_authority(program_id, accounts)
        }
        StakeInstruction::RotateInsuranceAuthority => {
            process_rotate_insurance_authority(program_id, accounts)
        }
        StakeInstruction::BurnAssetAdmin => {
            process_burn_asset_admin(program_id, accounts)
        }
        StakeInstruction::RotateInsuranceOperator => {
            process_rotate_insurance_operator(program_id, accounts)
        }
        StakeInstruction::ReturnInsurance { amount } => {
            process_return_insurance(program_id, accounts, amount)
        }
        StakeInstruction::AccrueFees => process_accrue_fees(program_id, accounts),
        StakeInstruction::InitTradingPool {
            cooldown_slots,
            deposit_cap,
        } => process_init_trading_pool(program_id, accounts, cooldown_slots, deposit_cap),
        StakeInstruction::AdminSetHwmConfig {
            enabled,
            hwm_floor_bps,
        } => process_admin_set_hwm_config(program_id, accounts, enabled, hwm_floor_bps),
        StakeInstruction::AdminSetTrancheConfig {
            junior_fee_mult_bps,
        } => process_admin_set_tranche_config(program_id, accounts, junior_fee_mult_bps),
        StakeInstruction::DepositJunior { amount } => {
            process_deposit_junior(program_id, accounts, amount)
        }
        StakeInstruction::SetMarketResolved => process_set_market_resolved(program_id, accounts),
    }
}

// ═══════════════════════════════════════════════════════════════
// 0: InitPool
// ═══════════════════════════════════════════════════════════════

fn process_init_pool(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    cooldown_slots: u64,
    deposit_cap: u64,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let admin = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let lp_mint = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;
    let vault_auth = next_account_info(accounts_iter)?;
    let collateral_mint = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;
    let rent_sysvar = next_account_info(accounts_iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Validate percolator_program against known-good allowlist.
    // Without this, a malicious admin could set percolator_program to an
    // attacker-controlled program, then drain the vault via FlushToInsurance CPI.
    {
        const PERCOLATOR_MAINNET: Pubkey =
            solana_program::pubkey!("ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv");
        const PERCOLATOR_DEVNET: Pubkey =
            solana_program::pubkey!("FxfD37s1AZTeWfFQps9Zpebi2dNQ9QSSDtfMKdbsfKrD");
        if *percolator_program.key != PERCOLATOR_MAINNET
            && *percolator_program.key != PERCOLATOR_DEVNET
        {
            msg!(
                "Error: invalid percolator program {}",
                percolator_program.key
            );
            return Err(StakeError::InvalidPercolatorProgram.into());
        }
    }

    // BUG-13: Validate cooldown_slots at InitPool time, consistent with UpdateConfig.
    // UpdateConfig already calls validate_cooldown_slots(), so allowing cooldown_slots=0
    // at init creates an inconsistency: a pool created with cooldown=0 could never be
    // updated to any non-zero value without a race window where it had no cooldown.
    validate_cooldown_slots(cooldown_slots)?;

    // Derive and verify pool PDA
    let (expected_pool, pool_bump) = state::derive_pool_pda(program_id, slab.key);
    if *pool_pda.key != expected_pool {
        return Err(StakeError::InvalidPda.into());
    }

    if !pool_pda.data_is_empty() {
        return Err(StakeError::AlreadyInitialized.into());
    }

    // Derive vault authority
    let (expected_vault_auth, vault_auth_bump) =
        state::derive_vault_authority(program_id, &expected_pool);
    if *vault_auth.key != expected_vault_auth {
        return Err(StakeError::InvalidPda.into());
    }

    // Prevent circular LP minting: if collateral_mint == lp_mint, a deposit would
    // accept LP tokens as collateral and mint more LP tokens in return, creating
    // an infinite-value inflation loop. E.g., attacker deposits 1 LP → mints 1 LP → repeat.
    if lp_mint.key == collateral_mint.key {
        msg!("Error: lp_mint and collateral_mint must differ — circular minting not allowed");
        return Err(StakeError::InvalidMint.into());
    }

    // Validate token program BEFORE any invoke_signed that grants PDA signer authority
    verify_token_program(token_program)?;

    // Validate the rent sysvar account early (it is still passed to the LP-mint/vault
    // initialize CPIs below); create_or_adopt_pda reads rent via Rent::get() internally.
    let _ = Rent::from_account_info(rent_sysvar)?;

    // Create pool PDA account. Robust against pool-PDA squatting (a griefer pre-funding
    // this deterministic address would make a bare create_account abort and block InitPool
    // for this slab). See #163.
    let pool_seeds: &[&[u8]] = &[b"stake_pool", slab.key.as_ref(), &[pool_bump]];
    create_or_adopt_pda(
        pool_pda,
        admin,
        system_program,
        program_id,
        STAKE_POOL_SIZE,
        pool_seeds,
    )?;

    // Create LP mint (mint authority = vault_auth PDA, freeze authority = None).
    // FINDING-4: Passing Some(vault_auth.key) as freeze authority would allow the
    // admin (who controls vault_auth) to freeze any LP holder's token account,
    // permanently preventing withdrawals. Freeze authority must NOT be retained —
    // the holder must always be able to redeem.
    //
    // #167 (LP is a NON-TRANSFERABLE position receipt, by decision): withdrawal is
    // gated by a per-(pool,user) StakeDeposit record that does NOT move with the LP
    // token, so transferring/selling the LP strands the underlying collateral (the
    // new holder has no record to redeem against; the old record is empty). We do
    // not enforce non-transferability on-chain (no freeze authority — see above; no
    // Token-2022 transfer hook); leaving freeze=None is purely the FINDING-4
    // anti-freeze guarantee and is NOT an endorsement of transferring. Clients must
    // treat the LP as a soulbound receipt. (Enforced non-transferability via a
    // transfer hook is the future hardening; tracked in #167.)
    // Read collateral mint decimals before creating the LP mint.
    // The collateral_mint account is already in scope and its key is
    // verified above (circular-mint guard + stored in pool state).
    let collateral_decimals = {
        let mint_data = collateral_mint.try_borrow_data()?;
        if mint_data.len() < crate::spl_token::state::Mint::LEN {
            return Err(StakeError::InvalidAccount.into());
        }
        crate::spl_token::state::Mint::unpack(&mint_data)?.decimals
    };

    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];
    invoke_signed(
        &crate::spl_token::initialize_mint(
            token_program.key,
            lp_mint.key,
            vault_auth.key,
            None, // freeze_authority: None — LP tokens must not be freezable
            collateral_decimals,
        )?,
        &[lp_mint.clone(), rent_sysvar.clone()],
        &[vault_auth_seeds],
    )?;

    // Initialize vault token account (authority = vault_auth PDA)
    invoke_signed(
        &crate::spl_token::initialize_account(
            token_program.key,
            vault.key,
            collateral_mint.key,
            vault_auth.key,
        )?,
        &[
            vault.clone(),
            collateral_mint.clone(),
            vault_auth.clone(),
            rent_sysvar.clone(),
        ],
        &[vault_auth_seeds],
    )?;

    // Write pool state
    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool = pool_from_data_mut(&mut pool_data[..])?;

    pool.is_initialized = 1;
    pool.bump = pool_bump;
    pool.vault_authority_bump = vault_auth_bump;
    pool.admin_transferred = 0; // deprecated field, always 0
    pool.slab = slab.key.to_bytes();
    pool.admin = admin.key.to_bytes();
    // FINDING-6 (SECURITY NOTE): collateral_mint is admin-provided and NOT verified
    // against slab on-chain data. We cannot read the slab's internal data layout from
    // this program without a hard dependency on percolator-prog. This is an admin-trust
    // assumption tracked in the threat model: the admin is responsible for passing the
    // correct collateral_mint that matches the slab's configured collateral token.
    pool.collateral_mint = collateral_mint.key.to_bytes();
    pool.lp_mint = lp_mint.key.to_bytes();
    pool.vault = vault.key.to_bytes();
    pool.total_deposited = 0;
    pool.total_lp_supply = 0;
    pool.cooldown_slots = cooldown_slots;
    pool.deposit_cap = deposit_cap;
    pool.total_flushed = 0;
    pool.total_returned = 0;
    pool.total_withdrawn = 0;
    pool.percolator_program = percolator_program.key.to_bytes();
    // PERC-272 + two-step admin: explicit zero (defense-in-depth). The PDA is
    // zero-filled at create_account so these are already 0, but explicit init
    // documents genesis state and guards against any future non-zeroed alloc.
    // In particular total_fees_earned MUST start at 0 so the first AccrueFees
    // pre-seed guard (total_lp_supply>0) cannot be bypassed by a stale field.
    pool.total_fees_earned = 0;
    pool.last_fee_accrual_slot = 0;
    pool.last_vault_snapshot = 0;
    pool.pool_mode = 0; // InitTradingPool overrides to 1 after this call
    pool.pending_admin = [0u8; 32];
    pool.set_discriminator();

    msg!(
        "StakePool initialized for slab {} (admin transfer pending)",
        slab.key
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 1: Deposit
// ═══════════════════════════════════════════════════════════════

fn process_deposit(program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    if amount == 0 {
        return Err(StakeError::ZeroAmount.into());
    }

    let accounts_iter = &mut accounts.iter();

    let user = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let user_ata = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;
    let lp_mint = next_account_info(accounts_iter)?;
    let user_lp_ata = next_account_info(accounts_iter)?;
    let vault_auth = next_account_info(accounts_iter)?;
    let deposit_pda = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;
    let clock_sysvar = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    if !user.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // I4: Validate pool account exists and is owned by stake program
    validate_account_not_empty(pool_pda)?;
    validate_account_owner(pool_pda, program_id)?;
    validate_account_writable(pool_pda)?;

    // Read and validate pool state
    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool = pool_from_data_mut(&mut pool_data[..])?;

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if !pool.validate_discriminator() {
        return Err(StakeError::InvalidAccount.into());
    }
    validate_pool_version(pool)?;
    if pool.lp_mint != lp_mint.key.to_bytes() {
        return Err(StakeError::InvalidMint.into());
    }
    if pool.vault != vault.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }

    // I7: Block deposits after market resolution
    if pool.market_resolved() {
        return Err(StakeError::MarketResolved.into());
    }

    // I5: Validate vault_auth PDA derivation
    let (expected_vault_auth, _) = derive_vault_authority(program_id, pool_pda.key);
    if *vault_auth.key != expected_vault_auth {
        return Err(StakeError::InvalidAccount.into());
    }

    // Check deposit cap against CURRENT pool value, not lifetime deposits.
    // Using total_deposited (monotonically increasing) would permanently lock
    // the pool once lifetime deposits hit the cap, even if 99% was withdrawn.
    // (H6 fix)
    if pool.deposit_cap > 0 {
        // #154: enforce the cap on PRINCIPAL TVL (no accrued fees), not total_pool_value();
        // otherwise fee appreciation on a mode-1 trading pool silently locks out new deposits.
        let current_value = pool.principal_tvl().ok_or(StakeError::Overflow)?;
        let new_value = current_value
            .checked_add(amount)
            .ok_or(StakeError::Overflow)?;
        if new_value > pool.deposit_cap {
            return Err(StakeError::DepositCapExceeded.into());
        }
    }

    // Validate token program BEFORE any invoke_signed that grants PDA signer authority.
    // Without this, attacker passes fake program → receives vault_auth signer → drains vault.
    verify_token_program(token_program)?;

    // Verify user_ata is owned by user (not just delegated) and holds the correct mint.
    // SPL token account layout: bytes [0..32] = mint, bytes [32..64] = owner.
    {
        // #195: the account must be SPL-Token-program-owned before we read its raw
        // layout — otherwise a non-token account with crafted bytes could satisfy the
        // mint/owner field checks below (the SPL CPI would later revert, but fail fast).
        if *user_ata.owner != crate::spl_token::id() {
            msg!("Error: user_ata is not owned by the SPL Token program");
            return Err(StakeError::InvalidAccount.into());
        }
        let ata_data = user_ata.try_borrow_data()?;
        if ata_data.len() < crate::spl_token::state::ACCOUNT_LEN {
            return Err(StakeError::InvalidAccount.into());
        }
        // Mint check: reject ATAs for wrong token (defense-in-depth; SPL would also catch
        // this on transfer, but an explicit check here gives a clear error and prevents
        // amount/balance reads from being made against the wrong token type).
        let mint_bytes: &[u8; 32] = ata_data[0..32]
            .try_into()
            .map_err(|_| StakeError::InvalidAccount)?;
        if mint_bytes != &pool.collateral_mint {
            msg!("Error: user_ata mint does not match pool collateral_mint");
            return Err(StakeError::InvalidMint.into());
        }
        let owner_bytes: &[u8; 32] = ata_data[32..64]
            .try_into()
            .map_err(|_| StakeError::InvalidAccount)?;
        if owner_bytes != user.key.as_ref() {
            msg!("Error: user_ata is not owned by the signer — delegation attack blocked");
            return Err(StakeError::Unauthorized.into());
        }
    }

    // #211: the LP mint destination (user_lp_ata) must be owned by the depositor
    // source. Otherwise LP receipts can land in a token account the depositor
    // does not control while the deposit record stays keyed to the depositor.
    validate_lp_recipient_account(user_lp_ata, &pool.lp_mint, user.key)?;

    // #136: crystallize pending trading-fee surplus into share price BEFORE pricing this
    // deposit (mode-1), so LP cannot be minted at the stale pre-accrual price and capture
    // fees earned before the depositor joined. Reads the vault balance before the
    // user->vault transfer below; pool.vault == vault.key was verified above.
    //
    // (Rebase note #160: KEEP main's pre_accrue_mode1 (PR #148 refactor) — #160's branch
    // predated it and carried the old inline accrue block, which is dropped here. The
    // senior recovery-snipe gate below is added AFTER it.)
    pre_accrue_mode1(pool, vault)?;

    // Insurance recovery-snipe gate (SENIOR path) — completes #150 for the senior tranche
    // (see #159). When tranches are on and a flushed loss has spilled PAST junior into
    // senior, the senior sub-pool is marked down (distribute_loss: senior_loss > 0 IFF
    // net_loss > junior_balance), so senior_balance() is depressed. A late senior depositor
    // could mint cheap LP here and redeem at the restored price after ReturnInsurance,
    // stealing the recovery from the incumbent seniors who actually bore the loss. Pause
    // exactly that window. The condition is PRECISE — not the junior gate's bare
    // flushed > returned — because senior_balance() is a pure function of current state, so
    // senior is depressed IFF net_loss > junior_balance(now). A junior-ABSORBED loss
    // (net_loss <= junior_balance) leaves senior_balance() unchanged and offers nothing to
    // snipe, so senior deposits stay open; gating it instead would DoS senior deposits for
    // the entire (possibly never-returned) life of a loss junior fully covers. Self-lifts as
    // ReturnInsurance raises total_returned. Tranche-only: the non-tranche/global path (#139)
    // is untouched. The senior WITHDRAW path is intentionally not changed here (separate
    // finding). junior_balance() is the raw stored balance — the same value distribute_loss
    // measures absorption against.
    //
    // #162 (permanent-loss freeze, BY DESIGN): if a loss is never returned (genuinely
    // realized — the market consumed the topped-up insurance), net_loss stays positive and
    // this gate never lifts, so senior deposits stay frozen. This is a deliberate, safe
    // consequence — the pool is fully backed and existing LPs withdraw at the marked-down
    // price; only NEW deposits are blocked. We do NOT auto-write-off after a clock/resolution:
    // (a) admin keys are burned so an admin write-off op is uncallable, (b) resolved markets
    // already block all deposits (see market_resolved gate above), so a resolution-keyed lift
    // is moot, and (c) a bare time-box would unfairly realize a still-recoverable loss and kill
    // the incumbents' legitimate recovery. The perfectly-fair admin-free fix is permissionless
    // reconciliation against the bound market's real insurance balance (deferred — tight
    // coupling, needs LiteSVM verification vs a live market). v17 ships Accept-&-document.
    if pool.tranche_enabled() {
        let net_loss = pool.total_flushed.saturating_sub(pool.total_returned);
        if net_loss > pool.junior_balance() {
            msg!(
                "DepositSenior paused: insurance loss spilled past junior (net_loss {} > junior_balance {}); flushed {} > returned {}",
                net_loss,
                pool.junior_balance(),
                pool.total_flushed,
                pool.total_returned
            );
            return Err(StakeError::InsuranceLossOutstanding.into());
        }
    }

    // Calculate LP tokens to mint.
    //
    // When tranches are enabled this is the SENIOR deposit path (junior deposits
    // go through process_deposit_junior). It MUST price against the senior
    // sub-pool (senior_balance / senior_total_lp) — the same basis the senior
    // WITHDRAW path values against (see calc_senior_collateral_for_withdraw) and
    // mirroring process_deposit_junior. Pricing senior deposits at the GLOBAL
    // ratio while redeeming at the senior ratio let an unprivileged user mint
    // cheap and redeem dear after a junior-absorbed loss, extracting value from
    // existing senior LPs.
    //
    // First-senior bootstrap and the orphaned-value (C9) guard are handled INSIDE
    // calc_senior_lp_for_deposit (it delegates to calc_lp_for_deposit) — NOT
    // special-cased here. A *true* first senior deposit has senior_balance == 0
    // (an empty pool, or a junior-first pool where junior captures 100% of fees,
    // so senior_balance stays 0), which mints 1:1. The ONLY state with
    // senior_total_lp == 0 while senior_balance > 0 is ORPHANED senior value (all
    // senior LP exited, then insurance was returned post-resolution): there the
    // C9 guard returns None and we REJECT, exactly as the non-tranche path does.
    // Seeding 1:1 against an orphan (an earlier version of this branch did) is a
    // C9 bypass — a 1-token deposit would mint 1 LP against the orphan and redeem
    // the whole orphaned balance. So senior_total_lp == 0 is NOT bootstrapped 1:1
    // unconditionally; it defers to the same guard the global path uses.
    let lp_to_mint = if pool.tranche_enabled() {
        let senior_lp = pool.senior_total_lp();
        let senior_bal = pool.senior_balance().ok_or(StakeError::Overflow)?;
        crate::math::calc_senior_lp_for_deposit(senior_lp, senior_bal, amount)
            .ok_or(StakeError::Overflow)?
    } else {
        pool.calc_lp_for_deposit(amount).ok_or(StakeError::Overflow)?
    };
    // S-4: reject a zero-share mint EXPLICITLY (dedicated variant, not the generic
    // ZeroAmount). A nonzero deposit that rounds to 0 LP at the current share price
    // must never transfer collateral in while minting nothing. Share price derives
    // from tracked counters (total_pool_value), never the raw vault balance, so a
    // direct token donation cannot inflate it — see math::calc_lp_for_deposit.
    if lp_to_mint == 0 {
        return Err(StakeError::ZeroSharesMinted.into());
    }

    // Transfer collateral: user ATA → stake vault
    invoke(
        &crate::spl_token::transfer(
            token_program.key,
            user_ata.key,
            vault.key,
            user.key,
            &[],
            amount,
        )?,
        &[
            user_ata.clone(),
            vault.clone(),
            user.clone(),
            token_program.clone(),
        ],
    )?;

    // Mint LP tokens to user
    let (_, vault_auth_bump) = state::derive_vault_authority(program_id, pool_pda.key);
    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];

    invoke_signed(
        &crate::spl_token::mint_to(
            token_program.key,
            lp_mint.key,
            user_lp_ata.key,
            vault_auth.key,
            &[],
            lp_to_mint,
        )?,
        &[
            lp_mint.clone(),
            user_lp_ata.clone(),
            vault_auth.clone(),
            token_program.clone(),
        ],
        &[vault_auth_seeds],
    )?;

    // Update pool totals
    pool.total_deposited = pool
        .total_deposited
        .checked_add(amount)
        .ok_or(StakeError::Overflow)?;
    pool.total_lp_supply = pool
        .total_lp_supply
        .checked_add(lp_to_mint)
        .ok_or(StakeError::Overflow)?;

    // PERC-313: Refresh high-water mark after deposit (TVL increased)
    let clock = Clock::from_account_info(clock_sysvar)?;
    if pool.hwm_enabled() {
        let current_tvl = pool.total_pool_value().ok_or(StakeError::Overflow)?;
        pool.refresh_hwm(clock.epoch, current_tvl);
    }

    // Create or update per-user deposit PDA (cooldown tracking)
    let (expected_deposit_pda, deposit_bump) =
        state::derive_deposit_pda(program_id, pool_pda.key, user.key);
    if *deposit_pda.key != expected_deposit_pda {
        return Err(StakeError::InvalidPda.into());
    }

    // I4: Verify deposit PDA ownership for existing accounts
    if !deposit_pda.data_is_empty() && *deposit_pda.owner != *program_id {
        return Err(StakeError::InvalidAccount.into());
    }

    if deposit_pda.data_is_empty() {
        let deposit_seeds: &[&[u8]] = &[
            b"stake_deposit",
            pool_pda.key.as_ref(),
            user.key.as_ref(),
            &[deposit_bump],
        ];
        // Robust against deposit-PDA squatting: a griefer who pre-funds this
        // deterministic address with lamports would make a bare create_account abort
        // (AccountAlreadyInUse) and permanently brick the user's first deposit. See #163.
        create_or_adopt_pda(
            deposit_pda,
            user,
            system_program,
            program_id,
            STAKE_DEPOSIT_SIZE,
            deposit_seeds,
        )?;
    }

    let mut deposit_data = deposit_pda.try_borrow_mut_data()?;
    let deposit = deposit_from_data_mut(&mut deposit_data[..])?;

    if deposit.is_initialized != 1 {
        deposit.set_discriminator();
    } else if !deposit.validate_discriminator() {
        // #194: an already-initialized record must carry the correct StakeDeposit
        // discriminator; reject a forged account that set is_initialized without init.
        return Err(StakeError::InvalidAccount.into());
    }

    // PERC-303: Prevent mixing senior and junior LP in the same deposit PDA.
    // If this deposit is flagged as junior, reject senior deposits regardless
    // of current LP balance. Without the lp_amount > 0 check bypass, an attacker
    // could: deposit junior → withdraw all → deposit senior into same PDA →
    // withdraw using junior rates (reserved[8] still set).
    if deposit._reserved[8] == 1 {
        return Err(StakeError::WrongTranche.into());
    }

    deposit.is_initialized = 1;
    deposit.bump = deposit_bump;
    deposit.pool = pool_pda.key.to_bytes();
    deposit.user = user.key.to_bytes();
    // BUG-8 (design note): Any deposit by a user resets last_deposit_slot for their ENTIRE
    // position, restarting the cooldown clock for all LP tokens they hold — not just the
    // newly minted ones.  This is intentional: it prevents users from avoiding cooldown by
    // making tiny "top-up" deposits while their main stake sits uncooled.  The trade-off is
    // that adding to an existing position extends the withdrawal wait for the whole balance.
    deposit.last_deposit_slot = clock.slot;
    deposit.lp_amount = deposit
        .lp_amount
        .checked_add(lp_to_mint)
        .ok_or(StakeError::Overflow)?;

    msg!(
        "Deposited {} collateral, minted {} LP tokens",
        amount,
        lp_to_mint
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 2: Withdraw
// ═══════════════════════════════════════════════════════════════

fn process_withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    lp_amount: u64,
) -> ProgramResult {
    if lp_amount == 0 {
        return Err(StakeError::ZeroAmount.into());
    }

    let accounts_iter = &mut accounts.iter();

    let user = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let user_lp_ata = next_account_info(accounts_iter)?;
    let lp_mint = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;
    let user_ata = next_account_info(accounts_iter)?;
    let vault_auth = next_account_info(accounts_iter)?;
    let deposit_pda = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;
    let clock_sysvar = next_account_info(accounts_iter)?;

    if !user.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // BUG-1: Validate pool account exists, is owned by the stake program, and is writable
    // (matching the same guards in process_deposit lines 389-391).
    validate_account_not_empty(pool_pda)?;
    validate_account_owner(pool_pda, program_id)?;
    validate_account_writable(pool_pda)?;

    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool = pool_from_data_mut(&mut pool_data[..])?;

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if !pool.validate_discriminator() {
        return Err(StakeError::InvalidAccount.into());
    }
    // BUG-2: Validate pool version, matching process_deposit line 403.
    validate_pool_version(pool)?;
    if pool.lp_mint != lp_mint.key.to_bytes() {
        return Err(StakeError::InvalidMint.into());
    }
    if pool.vault != vault.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }

    // Validate token program BEFORE any invoke_signed that grants PDA signer authority.
    verify_token_program(token_program)?;

    // Verify user_lp_ata is owned by the signer (not merely delegated) and holds the LP mint.
    // SPL token account layout: bytes [0..32] = mint, bytes [32..64] = owner.
    {
        let lp_ata_data = user_lp_ata.try_borrow_data()?;
        if lp_ata_data.len() < crate::spl_token::state::ACCOUNT_LEN {
            return Err(StakeError::InvalidAccount.into());
        }
        // Mint check: reject LP ATAs for a different mint (defense-in-depth).
        let mint_bytes: &[u8; 32] = lp_ata_data[0..32]
            .try_into()
            .map_err(|_| StakeError::InvalidAccount)?;
        if mint_bytes != &pool.lp_mint {
            msg!("Error: user_lp_ata mint does not match pool lp_mint");
            return Err(StakeError::InvalidMint.into());
        }
        // Delegation attack: if an attacker holds an Approve on a victim's LP ATA, they could
        // pass the victim's LP ATA as user_lp_ata, burn the victim's LP tokens, and receive
        // collateral from their OWN deposit record — effectively extracting double value while
        // the victim's LP is destroyed.
        let owner_bytes: &[u8; 32] = lp_ata_data[32..64]
            .try_into()
            .map_err(|_| StakeError::InvalidAccount)?;
        if owner_bytes != user.key.as_ref() {
            msg!("Error: user_lp_ata is not owned by the signer — delegation attack blocked");
            return Err(StakeError::Unauthorized.into());
        }
    }

    // Validate user_ata (collateral destination) is not the vault itself and
    // holds the correct mint.  Without the vault check, an attacker can pass
    // vault.key as user_ata — the SPL Transfer becomes a no-op self-transfer,
    // but LP is still burned and total_withdrawn still increments, desyncing
    // pool accounting from the actual vault balance.
    // NOTE: owner check is deliberately omitted — on withdrawal the user burns
    // their own LP and should be free to direct collateral to any address
    // (cold wallet, multisig, etc.).  This differs from process_deposit where
    // the owner check prevents draining a delegated victim's ATA.
    if user_ata.key == vault.key {
        msg!("Error: user_ata cannot be the pool vault — self-transfer blocked");
        return Err(StakeError::InvalidAccount.into());
    }
    {
        // #195: the account must be SPL-Token-program-owned before we read its raw
        // layout — otherwise a non-token account with crafted bytes could satisfy the
        // mint/owner field checks below (the SPL CPI would later revert, but fail fast).
        if *user_ata.owner != crate::spl_token::id() {
            msg!("Error: user_ata is not owned by the SPL Token program");
            return Err(StakeError::InvalidAccount.into());
        }
        let ata_data = user_ata.try_borrow_data()?;
        if ata_data.len() < crate::spl_token::state::ACCOUNT_LEN {
            return Err(StakeError::InvalidAccount.into());
        }
        let mint_bytes: &[u8; 32] = ata_data[0..32]
            .try_into()
            .map_err(|_| StakeError::InvalidAccount)?;
        if mint_bytes != &pool.collateral_mint {
            msg!("Error: user_ata mint does not match pool collateral_mint");
            return Err(StakeError::InvalidMint.into());
        }
    }

    // I5: Validate vault_auth PDA derivation
    let (expected_vault_auth, _) = derive_vault_authority(program_id, pool_pda.key);
    if *vault_auth.key != expected_vault_auth {
        return Err(StakeError::InvalidAccount.into());
    }

    // Validate deposit PDA derivation and ownership (defense-in-depth)
    let (expected_deposit_pda, _deposit_bump) =
        state::derive_deposit_pda(program_id, pool_pda.key, user.key);
    if *deposit_pda.key != expected_deposit_pda {
        return Err(StakeError::InvalidPda.into());
    }
    if *deposit_pda.owner != *program_id {
        return Err(StakeError::InvalidAccount.into());
    }
    if deposit_pda.data_len() < STAKE_DEPOSIT_SIZE {
        return Err(StakeError::InvalidAccount.into());
    }
    // N-10: deposit_pda is mutated later (lp_amount update); verify writability here
    // to match pool_pda (checked at line ~817) and give a clear StakeError rather than
    // an opaque runtime WritableAccountIsReadonly on a client-side bug.
    validate_account_writable(deposit_pda)?;

    // Check cooldown + read tranche flag in same borrow
    let clock = Clock::from_account_info(clock_sysvar)?;
    let is_junior;
    {
        let deposit_data_ref = deposit_pda.try_borrow_data()?;
        let deposit = deposit_from_data(&deposit_data_ref[..])?;

        // #194: validate the StakeDeposit discriminator before trusting the record.
        if !deposit.validate_discriminator() {
            return Err(StakeError::InvalidAccount.into());
        }
        if deposit.is_initialized != 1
            || deposit.user != user.key.to_bytes()
            || deposit.pool != pool_pda.key.to_bytes()
        {
            return Err(StakeError::Unauthorized.into());
        }
        if clock.slot
            < deposit
                .last_deposit_slot
                .saturating_add(pool.cooldown_slots)
        {
            return Err(StakeError::CooldownNotElapsed.into());
        }
        if lp_amount > deposit.lp_amount {
            return Err(StakeError::InsufficientLpTokens.into());
        }
        // Read tranche flag while we have the borrow
        is_junior = deposit._reserved[8] == 1;
    }

    // #136: crystallize pending trading-fee surplus into share price BEFORE pricing this
    // withdrawal (mode-1), so the withdrawer realizes their fair share of earned fees (and
    // the HWM floor sees true TVL) rather than redeeming at the stale pre-accrual price.
    // Reads the vault balance before the vault->user transfer below; pool.vault verified above.
    pre_accrue_mode1(pool, vault)?;

    // PERC-303: Determine withdrawal amount based on tranche
    let withdrawal_amount = if pool.tranche_enabled() && is_junior {
        // Junior withdrawal: valued against junior sub-pool after loss absorption.
        // effective_junior_balance() deducts insurance losses that junior absorbs first,
        // so junior LP holders correctly receive a reduced payout when the pool lost funds.
        let junior_lp = pool.junior_total_lp();
        let junior_bal = pool.effective_junior_balance();
        crate::math::calc_junior_collateral_for_withdraw(junior_lp, junior_bal, lp_amount)
            .ok_or(StakeError::Overflow)?
    } else if pool.tranche_enabled() {
        // Senior withdrawal when tranches are active: valued against senior
        // sub-pool only (senior_balance / senior_lp_supply), NOT the global pool.
        // Using global pool formula would mix junior collateral into the senior
        // valuation, allowing senior holders to extract junior-backed funds.
        let senior_lp = pool.senior_total_lp();
        let senior_bal = pool.senior_balance().ok_or(StakeError::Overflow)?;
        crate::math::calc_senior_collateral_for_withdraw(senior_lp, senior_bal, lp_amount)
            .ok_or(StakeError::Overflow)?
    } else {
        // No tranches: valued against full global pool
        pool.calc_collateral_for_withdraw(lp_amount)
            .ok_or(StakeError::Overflow)?
    };
    let fully_wiped_junior_exit = pool.tranche_enabled()
        && is_junior
        && pool.effective_junior_balance() == 0
        && withdrawal_amount == 0;

    if withdrawal_amount == 0 && !fully_wiped_junior_exit {
        return Err(StakeError::ZeroAmount.into());
    }

    // PERC-313: High-water mark floor enforcement.
    // A fully-wiped junior exit has zero collateral payout and cannot reduce TVL,
    // so HWM should not block the LP burn/deposit cleanup path.
    if pool.hwm_enabled() && !fully_wiped_junior_exit {
        let current_tvl = pool.total_pool_value().ok_or(StakeError::Overflow)?;
        let hwm = pool.refresh_hwm(clock.epoch, current_tvl);
        let post_tvl = current_tvl
            .checked_sub(withdrawal_amount)
            .ok_or(StakeError::Overflow)?;
        if !crate::math::hwm_withdrawal_allowed(post_tvl, hwm, pool.hwm_floor_bps()) {
            msg!(
                "HWM block: post_tvl={} < floor(hwm={}, bps={})",
                post_tvl,
                hwm,
                pool.hwm_floor_bps()
            );
            return Err(StakeError::WithdrawalBelowHwmFloor.into());
        }
    }

    // Burn LP tokens from user
    invoke(
        &crate::spl_token::burn(
            token_program.key,
            user_lp_ata.key,
            lp_mint.key,
            user.key,
            &[],
            lp_amount,
        )?,
        &[
            user_lp_ata.clone(),
            lp_mint.clone(),
            user.clone(),
            token_program.clone(),
        ],
    )?;

    // Transfer collateral: vault → user ATA (single transfer)
    // BUG-10: Use the vault_authority_bump stored in pool state rather than calling
    // find_program_address, which is a compute-intensive PDA search (iterates until
    // it finds a valid bump).  The bump is stored at InitPool time and never changes.
    // We add a debug assertion to catch any drift between stored and derived values.
    let vault_auth_bump = pool.vault_authority_bump;
    // FINDING-11: Always verify vault_authority_bump matches the derived value.
    // Previously this was gated on #[cfg(debug_assertions)] so production builds
    // would silently use a corrupted bump and produce an invalid PDA seed, causing
    // the invoke_signed to fail with an opaque error rather than a clear security check.
    // The cost of one find_program_address call per withdrawal is acceptable for security.
    {
        let (_, derived_bump) = state::derive_vault_authority(program_id, pool_pda.key);
        if vault_auth_bump != derived_bump {
            msg!(
                "Error: stored vault_authority_bump ({}) does not match derived bump ({}) — state corruption",
                vault_auth_bump,
                derived_bump
            );
            return Err(StakeError::InvalidPda.into());
        }
    }
    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];

    if withdrawal_amount > 0 {
        invoke_signed(
            &crate::spl_token::transfer(
                token_program.key,
                vault.key,
                user_ata.key,
                vault_auth.key,
                &[],
                withdrawal_amount,
            )?,
            &[
                vault.clone(),
                user_ata.clone(),
                vault_auth.clone(),
                token_program.clone(),
            ],
            &[vault_auth_seeds],
        )?;
    }

    // Update pool totals
    pool.total_withdrawn = pool
        .total_withdrawn
        .checked_add(withdrawal_amount)
        .ok_or(StakeError::Overflow)?;
    pool.total_lp_supply = pool
        .total_lp_supply
        .checked_sub(lp_amount)
        .ok_or(StakeError::Overflow)?;

    // Update tranche-specific state if junior
    if pool.tranche_enabled() && is_junior {
        let junior_lp_before = pool.junior_total_lp();
        let new_junior_lp = junior_lp_before
            .checked_sub(lp_amount)
            .ok_or(StakeError::Overflow)?;
        pool.set_junior_total_lp(new_junior_lp);

        if new_junior_lp == 0 {
            // #161 (fair-recovery): the LAST junior is exiting. Any insurance loss it
            // absorbed (L = junior_balance − effective_junior_balance) is now FORFEITED —
            // the junior took its marked-down payout and left, so a later ReturnInsurance
            // of that portion must NOT windfall to senior (which was protected). REALIZE it:
            // settle the junior portion (`total_returned += L`, capped at total_flushed so it
            // can never exceed it) and record it in `realized_junior_loss` (which
            // total_pool_value() subtracts). Net effect on total_pool_value() is zero at exit
            // (the +L from total_returned cancels the −L from realized_junior_loss), so senior
            // is unchanged here; but it caps any future return so the recovered tokens sit as
            // DEAD value instead of inflating senior. Also lifts the deposit gate for the
            // settled portion (net_loss drops). Must compute L BEFORE zeroing junior_balance.
            let net_loss = pool.total_flushed.saturating_sub(pool.total_returned);
            if net_loss > 0 {
                let forfeited = pool
                    .junior_balance()
                    .saturating_sub(pool.effective_junior_balance());
                // forfeited <= junior's share of net_loss <= net_loss, so total_returned + forfeited
                // <= total_flushed (no over-settle); cap defensively all the same.
                let forfeited = forfeited.min(net_loss);
                if forfeited > 0 {
                    pool.total_returned = pool
                        .total_returned
                        .checked_add(forfeited)
                        .ok_or(StakeError::Overflow)?;
                    pool.set_realized_junior_loss(
                        pool.realized_junior_loss()
                            .checked_add(forfeited)
                            .ok_or(StakeError::Overflow)?,
                    );
                    msg!(
                        "Last junior exit: realized (forfeited) junior loss {} (settled; not recoverable to senior)",
                        forfeited
                    );
                }
            }
            // All junior LP withdrawn — zero out the raw balance.
            // withdrawal_amount is derived from effective_junior_balance (loss-adjusted)
            // but junior_balance stores the raw (non-adjusted) value.  Subtracting
            // the loss-adjusted amount from the raw balance leaves a residual that
            // grows with each withdrawal during a loss period.  When insurance is
            // later returned, this orphaned balance blocks new junior deposits
            // (supply=0 but value>0) and locks tokens permanently in the vault.
            pool.set_junior_balance(0);
        } else {
            // Decrease junior_balance by withdrawal_amount (the loss-adjusted
            // collateral actually leaving the vault), NOT by a proportional share
            // of the raw balance.
            //
            // During active insurance loss, withdrawal_amount < proportional raw
            // share because it is based on effective_junior_balance (post-loss).
            // Using the larger proportional raw decrease causes gross_senior
            // (= gross_pool - junior_balance) to inflate after each junior
            // withdrawal, making distribute_loss over-penalize remaining juniors.
            // The last junior withdrawer can receive zero even though they hold
            // a fair share of the effective pool.
            //
            // By subtracting withdrawal_amount from both total_withdrawn (above)
            // and junior_balance here, gross_senior stays constant across partial
            // junior withdrawals, preserving per-LP effective value.
            pool.set_junior_balance(
                pool.junior_balance()
                    .checked_sub(withdrawal_amount)
                    .ok_or(StakeError::Overflow)?,
            );
        }
    }

    // Update deposit PDA
    let mut deposit_data_mut = deposit_pda.try_borrow_mut_data()?;
    let deposit_mut = deposit_from_data_mut(&mut deposit_data_mut[..])?;
    deposit_mut.lp_amount = deposit_mut
        .lp_amount
        .checked_sub(lp_amount)
        .ok_or(StakeError::InsufficientLpTokens)?;

    // #155: once the position is fully withdrawn, reset the record's init + tranche
    // flag so the (pool,user) PDA can be reused for EITHER tranche on the next deposit.
    // Without this, _reserved[8] (the junior flag) and is_initialized persist, so PERC-303's
    // anti-mixing guard permanently blocks the wallet from depositing into the OTHER tranche
    // (and a junior who fully exits can never go senior, or vice-versa). Safe vs PERC-303:
    // mixing requires a RESIDUAL liened position; with lp_amount == 0 there is nothing to mix.
    // Metadata-only — touches no token/LP/accounting field. The deposit re-init path
    // (process_deposit / process_deposit_junior) correctly re-initializes a zeroed record.
    if deposit_mut.lp_amount == 0 {
        deposit_mut.is_initialized = 0;
        deposit_mut._reserved[8] = 0;
    }

    if pool.tranche_enabled() && is_junior {
        msg!(
            "Junior withdrew {} collateral, burned {} LP tokens",
            withdrawal_amount,
            lp_amount
        );
    } else {
        msg!(
            "Withdrew {} collateral, burned {} LP tokens",
            withdrawal_amount,
            lp_amount
        );
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 3: FlushToInsurance — CPI into wrapper TopUpInsurance
// ═══════════════════════════════════════════════════════════════

fn process_flush_to_insurance(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    if amount == 0 {
        return Err(StakeError::ZeroAmount.into());
    }

    let accounts_iter = &mut accounts.iter();

    let caller = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;
    let vault_auth = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let wrapper_vault = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;

    if !caller.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // FINDING-2: Validate pool account ownership and non-emptiness before reading it.
    // Without these guards an attacker can pass a crafted account; bytemuck would
    // reinterpret foreign data as StakePool state and all subsequent field checks
    // operate on attacker-controlled bytes.
    validate_account_owner(pool_pda, program_id)?;
    validate_account_not_empty(pool_pda)?;

    // FINDING-2: Verify token program before the CPI call that grants PDA signer authority.
    // Without this check an attacker can pass a fake token program, receive the PDA
    // signer authority via invoke_signed, and drain the vault.
    verify_token_program(token_program)?;

    // Read pool
    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool = pool_from_data_mut(&mut pool_data[..])?;

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    // AUDIT HIGH-2: validate discriminator before trusting pool data
    if !pool.validate_discriminator() {
        return Err(StakeError::InvalidAccount.into());
    }
    // FINDING-5: Validate pool version on FlushToInsurance.
    validate_pool_version(pool)?;

    // CRITICAL (C10): FlushToInsurance must be admin-only.
    // Without this, ANY signer can drain the stake vault to wrapper insurance,
    // locking all LP holder withdrawals until market resolution.
    // This is a DoS vector that freezes depositor funds indefinitely.
    if pool.admin != caller.key.to_bytes() {
        return Err(StakeError::Unauthorized.into());
    }

    if pool.slab != slab.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }
    if pool.vault != vault.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }
    if pool.percolator_program != percolator_program.key.to_bytes() {
        return Err(StakeError::InvalidPercolatorProgram.into());
    }

    // FlushToInsurance moves vault funds to the wrapper insurance fund.
    // This operation is only meaningful on insurance LP pools (mode 0).
    // Trading LP pools (mode 1) use fee-based accounting; flushing would
    // undercount pool value in AccrueFees (total_deposited - total_withdrawn
    // formula doesn't subtract total_flushed) and leave the vault
    // permanently below the expected accounting balance.
    if pool.pool_mode != 0 {
        msg!("FlushToInsurance: not valid for trading LP pools (mode 1)");
        return Err(StakeError::InvalidPoolMode.into());
    }

    // Validate wrapper_vault holds the correct collateral mint (defense-in-depth).
    // The percolator CPI also validates this, but an explicit check here gives a clear
    // error and prevents tokens of the wrong type from being routed to the insurance vault.
    // SPL token account layout: bytes [0..32] = mint.
    {
        let wv_data = wrapper_vault.try_borrow_data()?;
        if wv_data.len() < crate::spl_token::state::ACCOUNT_LEN {
            return Err(StakeError::InvalidAccount.into());
        }
        let wv_mint: &[u8; 32] = wv_data[0..32]
            .try_into()
            .map_err(|_| StakeError::InvalidAccount)?;
        if wv_mint != &pool.collateral_mint {
            msg!("Error: wrapper_vault mint does not match pool collateral_mint");
            return Err(StakeError::InvalidMint.into());
        }
    }

    // Verify vault balance — can't flush more than the pool's value physically in the vault.
    //
    // #198: the previous inline chain `((D - W) - F) + R` (u64, left-to-right) UNDERFLOWED
    // at the intermediate `(D - W) - F` whenever `D - W < F` (equivalently total_pool_value()
    // < total_returned) and failed the flush with Overflow even though `D - W - F + R` was
    // positive and the tokens were in the vault — the same false-underflow brick that
    // total_pool_value() was widened to i128 to avoid (#169); this duplicate was missed.
    //
    // It ALSO over-counted by omitting `- realized_junior_loss`: the #161 last-junior-exit
    // booking raises total_returned by the forfeited loss WITHOUT a token movement (a phantom
    // return recorded in realized_junior_loss), so `D - W - F + R` exceeds the real vault
    // balance by realized_junior_loss. The vault physically holds exactly total_pool_value()
    // (= D - W - F + R - realized_junior_loss for a mode-0 pool; fees are 0 here because flush
    // is mode-0 only, gated above). Reuse the canonical i128-widened fn: it is the exact
    // flushable balance, can never report more than the vault holds, and returns None only on
    // genuine insolvency — which correctly fails the flush closed.
    let available = pool.total_pool_value().ok_or(StakeError::Overflow)?;
    if amount > available {
        return Err(StakeError::InsufficientVaultBalance.into());
    }

    // Derive vault authority for signing
    let (expected_vault_auth, vault_auth_bump) =
        state::derive_vault_authority(program_id, pool_pda.key);
    if *vault_auth.key != expected_vault_auth {
        return Err(StakeError::InvalidPda.into());
    }

    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];

    // CPI TopUpInsurance: vault_auth PDA signs, stake vault is the "signer_ata"
    // TopUpInsurance checks: verify_token_account(a_user_ata, a_user.key, &mint)
    // Our vault's owner (in SPL token terms) = vault_auth PDA = signer. ✓
    cpi::cpi_top_up_insurance(
        percolator_program,
        vault_auth, // signer (PDA, we invoke_signed)
        slab,
        vault,         // signer_ata (owned by vault_auth PDA)
        wrapper_vault, // percolator vault
        token_program,
        amount,
        vault_auth_seeds,
    )?;

    // Update pool tracking
    pool.total_flushed = pool
        .total_flushed
        .checked_add(amount)
        .ok_or(StakeError::Overflow)?;

    // PERC-313 HWM: a flush is a realized insurance LOSS — pool TVL drops by `amount`.
    // The high-water-mark withdrawal floor must track that loss, or LPs get frozen out
    // of a pool that just lost money. `refresh_hwm` only RAISES the mark within an epoch
    // and is never called here, so the mark must be lowered explicitly. Lower it by
    // exactly the flushed amount (the realized loss) so the floor recomputes against the
    // loss-adjusted peak (peak − Σ losses). This preserves anti-drain protection:
    // WITHDRAWALS never lower the mark (only refresh_hwm's raise and this flush do), so a
    // withdrawal-driven drain is still floored; only a real loss lowers the floor, and only
    // by the loss amount — no free withdrawal headroom is created (TVL dropped by the same
    // `amount`). saturating_sub is panic-free; if a stale/zero mark is below `amount` it
    // floors at 0 (floor 0 = no restriction), and the next withdraw's refresh_hwm re-bases
    // the mark to live TVL. Left ungated on hwm_enabled(): the mark is only ever READ in the
    // hwm_enabled branch, and a lowered mark is strictly more permissive, so tracking the
    // loss unconditionally keeps "mark = peak − losses" true and avoids a stale-high mark
    // re-freezing if HWM is toggled on mid-epoch after a flush. ReturnInsurance is left
    // untouched: recovery rides the existing same-epoch refresh_hwm raise (clamped to TVL).
    pool.set_epoch_high_water_tvl(pool.epoch_high_water_tvl().saturating_sub(amount));

    msg!(
        "Flushed {} collateral to percolator insurance via CPI",
        amount
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 4: UpdateConfig
// ═══════════════════════════════════════════════════════════════

fn process_update_config(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_cooldown_slots: Option<u64>,
    new_deposit_cap: Option<u64>,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // BUG-5: Validate pool account is owned by this program before reading it.
    // Without this, an attacker could pass a crafted account and manipulate config
    // without an authentic pool PDA.
    validate_account_owner(pool_pda, program_id)?;
    validate_account_not_empty(pool_pda)?;

    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool = pool_from_data_mut(&mut pool_data[..])?;

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    // AUDIT MED-4: validate discriminator on UpdateConfig
    if !pool.validate_discriminator() {
        return Err(StakeError::InvalidAccount.into());
    }
    // FINDING-5: Validate pool version on UpdateConfig.
    validate_pool_version(pool)?;
    if pool.admin != admin.key.to_bytes() {
        return Err(StakeError::Unauthorized.into());
    }

    if let Some(cooldown) = new_cooldown_slots {
        validate_cooldown_slots(cooldown)?;
        pool.cooldown_slots = cooldown;
    }
    if let Some(cap) = new_deposit_cap {
        // deposit_cap can be 0 (unlimited) or any positive value
        // no validation needed, u64 can't be negative
        pool.deposit_cap = cap;
    }

    msg!("Pool config updated");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 5: ProposeAdmin — step 1 of two-step admin rotation
// ═══════════════════════════════════════════════════════════════

/// The CURRENT admin proposes a new admin. Writes pool.pending_admin; grants the
/// proposed admin NO authority until they call AcceptAdmin. Proposing the zero
/// pubkey cancels an outstanding proposal. Mirrors the wrapper's authority-gated
/// rotation style (current authority must sign), using the safe propose/accept
/// idiom so a transfer can never strand the pool on a key nobody controls.
fn process_propose_admin(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_admin: [u8; 32],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Validate pool account before bytemuck reinterpretation (matches every
    // other admin path).
    validate_account_owner(pool_pda, program_id)?;
    validate_account_not_empty(pool_pda)?;

    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool = pool_from_data_mut(&mut pool_data[..])?;

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if !pool.validate_discriminator() {
        return Err(StakeError::InvalidAccount.into());
    }
    validate_pool_version(pool)?;
    if pool.admin != admin.key.to_bytes() {
        return Err(StakeError::Unauthorized.into());
    }

    pool.pending_admin = new_admin;

    if new_admin == [0u8; 32] {
        msg!("ProposeAdmin: pending admin proposal cancelled");
    } else {
        msg!("ProposeAdmin: new admin proposed (awaiting AcceptAdmin)");
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 6: AcceptAdmin — step 2 of two-step admin rotation
// ═══════════════════════════════════════════════════════════════

/// The PENDING admin accepts the rotation and becomes admin. Requires an
/// outstanding proposal (pending_admin != 0) and the signer to equal
/// pending_admin. Clears pending_admin on success. Because the new admin must
/// sign here, ownership can never be handed to a key that cannot act.
fn process_accept_admin(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let new_admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;

    if !new_admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    validate_account_owner(pool_pda, program_id)?;
    validate_account_not_empty(pool_pda)?;

    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool = pool_from_data_mut(&mut pool_data[..])?;

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if !pool.validate_discriminator() {
        return Err(StakeError::InvalidAccount.into());
    }
    validate_pool_version(pool)?;

    // There must be an outstanding proposal to accept.
    if pool.pending_admin == [0u8; 32] {
        return Err(StakeError::NoPendingAdmin.into());
    }
    // Only the proposed admin may accept.
    if pool.pending_admin != new_admin.key.to_bytes() {
        return Err(StakeError::Unauthorized.into());
    }

    pool.admin = pool.pending_admin;
    pool.pending_admin = [0u8; 32];

    msg!("AcceptAdmin: admin rotation complete");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 19: BindInsuranceAuthority — one-time bind of the v16 market's
// insurance_authority to our vault_auth PDA (see cpi::cpi_bind_insurance_authority)
// ═══════════════════════════════════════════════════════════════

/// Bind — two-CPI sequence that moves insurance_authority AND insurance_operator
/// to the vault_auth PDA. Together these close BOTH drain paths in tag-57
/// WithdrawInsuranceAsset:
///
///   (a) local_authorized = insurance_operator == operator → BLOCKED (operator=PDA≠admin)
///   (b) admin_shutdown_authorized path → BLOCKED by D-STAKE-1 guard when
///       insurance_authority != zero AND by the asset_index==0 guard.
///
/// After this call:
///   - insurance_authority == vault_auth PDA
///   - insurance_operator  == vault_auth PDA
///
/// The admin can still rotate these back IF they retain asset_admin. To irrevocably
/// close this path, call BurnAssetAdmin (tag 21) AFTER this instruction. Together
/// BindInsuranceAuthority + BurnAssetAdmin form the COMPLETE secure-bind sequence.
///
/// NOTE: the two CPIs are split from the admin-burn because BurnAssetAdmin is
/// irreversible and only needed once per market. On a redeploy, rotate authority
/// and operator back to admin first, bind from the new program, and only then call
/// BurnAssetAdmin when the new bind is final.
fn process_bind_insurance_authority(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let vault_auth = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Validate pool account before bytemuck reinterpretation.
    validate_account_owner(pool_pda, program_id)?;
    validate_account_not_empty(pool_pda)?;

    // Read pool (immutable — we don't mutate stake state here) and copy out the
    // fields we need so the borrow is released before the CPIs.
    let (pool_slab, pool_percolator) = {
        let pool_data = pool_pda.try_borrow_data()?;
        let pool = pool_from_data(&pool_data[..])?;
        if pool.is_initialized != 1 {
            return Err(StakeError::NotInitialized.into());
        }
        if !pool.validate_discriminator() {
            return Err(StakeError::InvalidAccount.into());
        }
        validate_pool_version(pool)?;
        // Admin-gated: only the pool admin may bind. At bind time the admin must
        // be the current insurance_authority and insurance_operator (bootstrapped
        // to marketauth=admin at InitMarket). Any divergence causes the wrapper
        // CPI to reject with Unauthorized.
        if pool.admin != admin.key.to_bytes() {
            return Err(StakeError::Unauthorized.into());
        }
        (pool.slab, pool.percolator_program)
    };

    // Bind to the pool's recorded market + wrapper program (prevents pointing the
    // bind at an attacker-supplied market/program).
    if pool_slab != slab.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }
    if pool_percolator != percolator_program.key.to_bytes() {
        return Err(StakeError::InvalidPercolatorProgram.into());
    }

    // Derive + verify the vault_auth PDA (the new authority for both CPIs).
    let (expected_vault_auth, vault_auth_bump) =
        state::derive_vault_authority(program_id, pool_pda.key);
    if *vault_auth.key != expected_vault_auth {
        return Err(StakeError::InvalidPda.into());
    }

    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];

    // CPI 1: bind insurance_authority (kind=1) → vault_auth PDA.
    // Admin is the current insurance_authority; PDA co-signs via invoke_signed.
    cpi::cpi_bind_insurance_authority(
        percolator_program,
        admin,      // current insurance_authority (== admin at bootstrap)
        vault_auth, // new authority (PDA), signed via invoke_signed
        slab,       // market
        vault_auth_seeds,
    )?;

    // CPI 2: bind insurance_operator (kind=2) → vault_auth PDA.
    // Admin is the current insurance_operator (bootstrapped to marketauth=admin).
    // PDA co-signs as the new operator via invoke_signed. After this, admin cannot
    // pass local_authorized in WithdrawInsuranceAsset (tag 57) because
    // insurance_operator != admin.
    cpi::cpi_bind_insurance_operator(
        percolator_program,
        admin,      // current insurance_operator (== admin at bootstrap)
        vault_auth, // new operator (PDA), signed via invoke_signed
        slab,       // market
        vault_auth_seeds,
    )?;

    msg!("BindInsuranceAuthority: insurance_authority + insurance_operator bound to vault_auth PDA — local_authorized drain path blocked. Call BurnAssetAdmin (tag 21) to irrevocably seal.");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 21: BurnAssetAdmin — irrevocably remove admin's rotate-back capability
// ═══════════════════════════════════════════════════════════════

/// BurnAssetAdmin burns the market's asset_admin (kind=0) to [0;32], permanently
/// removing the admin's ability to rotate insurance_operator (or any other per-asset
/// authority) back to an admin-controlled key.
///
/// This is the FINAL HARDENING step of the secure-bind sequence:
///   1. BindInsuranceAuthority — moves authority + operator to PDA
///   2. BurnAssetAdmin         — burns the admin's rotate-back escape hatch and
///      records the finality in stake state
///
/// After BurnAssetAdmin:
///   - asset_admin == [0;32] (no key can rotate per-asset authorities for this asset)
///   - Only the current holder of each authority can self-rotate it
///   - The PDA (vault_auth) stays the insurance_authority and insurance_operator
///     unless rotation happened before the burn
///
/// IRREVERSIBILITY: asset_admin [0;32] can never be restored. This is intentional.
/// Once burned, the secure state is locked. Only call this when committed.
///
/// IDEMPOTENT GUARD: call this EXACTLY ONCE per market. Calling it when asset_admin
/// is already zero causes a wrapper Unauthorized error (the wrapper's
/// expect_live_authority check fails on a zero key — it cannot sign).
///
/// Accounts:
///   0. `[signer, writable]` Admin (current asset_admin == pool.admin)
///   1. `[writable]` Pool PDA (records that asset_admin has been burned)
///   2. `[]` Vault authority PDA (placeholder new_authority slot — not checked for burn)
///   3. `[writable]` Slab / market account (wrapper-owned)
///   4. `[]` Percolator program
fn process_burn_asset_admin(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let vault_auth = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    validate_account_writable(pool_pda)?;
    validate_account_owner(pool_pda, program_id)?;
    validate_account_not_empty(pool_pda)?;

    let (pool_slab, pool_percolator) = {
        let pool_data = pool_pda.try_borrow_data()?;
        let pool = pool_from_data(&pool_data[..])?;
        if pool.is_initialized != 1 {
            return Err(StakeError::NotInitialized.into());
        }
        if !pool.validate_discriminator() {
            return Err(StakeError::InvalidAccount.into());
        }
        validate_pool_version(pool)?;
        if pool.admin != admin.key.to_bytes() {
            return Err(StakeError::Unauthorized.into());
        }
        if pool.asset_admin_burned() {
            msg!("BurnAssetAdmin: asset_admin already burned for this pool");
            return Err(StakeError::Unauthorized.into());
        }
        (pool.slab, pool.percolator_program)
    };

    if pool_slab != slab.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }
    if pool_percolator != percolator_program.key.to_bytes() {
        return Err(StakeError::InvalidPercolatorProgram.into());
    }

    // vault_auth is passed as a placeholder new_authority slot (not checked by the wrapper
    // when new_pubkey=[0;32]; only admin must sign as the current asset_admin).
    // We do NOT need vault_auth to be the actual vault_auth PDA here (any account works),
    // but we use it for consistency and to avoid introducing a new account slot.
    let (expected_vault_auth, _) = state::derive_vault_authority(program_id, pool_pda.key);
    if *vault_auth.key != expected_vault_auth {
        return Err(StakeError::InvalidPda.into());
    }

    cpi::cpi_burn_asset_admin(
        percolator_program,
        admin,      // current asset_admin; signer
        vault_auth, // placeholder slot (not checked for zero-burn)
        slab,       // market
    )?;

    {
        let mut pool_data = pool_pda.try_borrow_mut_data()?;
        let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);
        pool.set_asset_admin_burned(true);
    }

    msg!("BurnAssetAdmin: asset_admin burned to zero — stake rotate-back escape permanently disabled");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 22: RotateInsuranceOperator — PDA signs to move operator off
// ═══════════════════════════════════════════════════════════════

/// Admin-gated rotation of the market's `insurance_operator` OFF our `vault_auth`
/// PDA to an admin-specified `new_target`. CPIs UpdateAssetAuthority(kind=2,
/// new_target) with the PDA signing as the CURRENT operator (invoke_signed) and
/// `new_target` co-signing the outer tx as the NEW operator.
///
/// This is the migration escape for the insurance_operator, analogous to
/// RotateInsuranceAuthority (tag 20) for insurance_authority. The full no-lockout
/// migration sequence on a redeploy:
///   1. RotateInsuranceAuthority (tag 20): insurance_authority PDA_A → admin wallet
///   2. RotateInsuranceOperator  (tag 22): insurance_operator  PDA_A → admin wallet
///   3. Re-bind from NEW program: BindInsuranceAuthority (tags 19) binds both to PDA_B
///   4. BurnAssetAdmin once the new bind is final
///
/// Accounts:
///   0. `[signer]` Admin (must equal pool.admin — the stake-side gate)
///   1. `[]` Pool PDA
///   2. `[]` Vault authority PDA (the CURRENT operator; signed via CPI invoke_signed)
///   3. `[signer]` New target operator (co-signs the outer tx)
///   4. `[writable]` Slab / market account (wrapper-owned)
///   5. `[]` Percolator program
fn process_rotate_insurance_operator(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let vault_auth = next_account_info(accounts_iter)?;
    let new_target = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    // The wrapper requires the NEW operator to co-sign for non-zero keys.
    if !new_target.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    validate_account_owner(pool_pda, program_id)?;
    validate_account_not_empty(pool_pda)?;

    let (pool_slab, pool_percolator) = {
        let pool_data = pool_pda.try_borrow_data()?;
        let pool = pool_from_data(&pool_data[..])?;
        if pool.is_initialized != 1 {
            return Err(StakeError::NotInitialized.into());
        }
        if !pool.validate_discriminator() {
            return Err(StakeError::InvalidAccount.into());
        }
        validate_pool_version(pool)?;
        if pool.admin != admin.key.to_bytes() {
            return Err(StakeError::Unauthorized.into());
        }
        if pool.asset_admin_burned() {
            msg!("RotateInsuranceOperator: asset_admin burn is final; rotate-back is disabled");
            return Err(StakeError::Unauthorized.into());
        }
        (pool.slab, pool.percolator_program)
    };

    if pool_slab != slab.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }
    if pool_percolator != percolator_program.key.to_bytes() {
        return Err(StakeError::InvalidPercolatorProgram.into());
    }

    let (expected_vault_auth, vault_auth_bump) =
        state::derive_vault_authority(program_id, pool_pda.key);
    if *vault_auth.key != expected_vault_auth {
        return Err(StakeError::InvalidPda.into());
    }

    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];
    cpi::cpi_rotate_insurance_operator(
        percolator_program,
        vault_auth, // current operator (the PDA), signed via invoke_signed
        new_target, // new operator (admin-specified), co-signs the outer tx
        slab,       // market
        vault_auth_seeds,
    )?;

    msg!("RotateInsuranceOperator: insurance_operator rotated off vault_auth PDA to new target");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 20: RotateInsuranceAuthority — admin-gated escape from the bind
// ═══════════════════════════════════════════════════════════════

/// Admin-gated rotation of the market's `insurance_authority` OFF our `vault_auth`
/// PDA to an admin-specified `new_target`. CPIs UpdateAuthority(INSURANCE,
/// new_target) with the PDA signing as the CURRENT authority (invoke_signed) and
/// `new_target` co-signing the outer tx as the NEW authority. The escape from the
/// otherwise-permanent bind (a stake redeploy must rotate to the admin wallet from
/// the old program before decommissioning, then re-bind from the new program).
/// Only succeeds before BurnAssetAdmin has completed and while the PDA is the
/// current authority; otherwise stake or the wrapper rejects with Unauthorized.
fn process_rotate_insurance_authority(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let vault_auth = next_account_info(accounts_iter)?;
    let new_target = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    // The wrapper requires the NEW authority to co-sign; surface a clear error
    // here rather than an opaque CPI failure if it didn't sign.
    if !new_target.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    validate_account_owner(pool_pda, program_id)?;
    validate_account_not_empty(pool_pda)?;

    let (pool_slab, pool_percolator) = {
        let pool_data = pool_pda.try_borrow_data()?;
        let pool = pool_from_data(&pool_data[..])?;
        if pool.is_initialized != 1 {
            return Err(StakeError::NotInitialized.into());
        }
        if !pool.validate_discriminator() {
            return Err(StakeError::InvalidAccount.into());
        }
        validate_pool_version(pool)?;
        // Admin-gated: only the pool admin may rotate the insurance authority.
        if pool.admin != admin.key.to_bytes() {
            return Err(StakeError::Unauthorized.into());
        }
        if pool.asset_admin_burned() {
            msg!("RotateInsuranceAuthority: asset_admin burn is final; rotate-back is disabled");
            return Err(StakeError::Unauthorized.into());
        }
        (pool.slab, pool.percolator_program)
    };

    if pool_slab != slab.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }
    if pool_percolator != percolator_program.key.to_bytes() {
        return Err(StakeError::InvalidPercolatorProgram.into());
    }

    // Derive + verify the vault_auth PDA (the CURRENT authority we sign as).
    let (expected_vault_auth, vault_auth_bump) =
        state::derive_vault_authority(program_id, pool_pda.key);
    if *vault_auth.key != expected_vault_auth {
        return Err(StakeError::InvalidPda.into());
    }

    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];
    cpi::cpi_rotate_insurance_authority(
        percolator_program,
        vault_auth, // current authority (the PDA), signed via invoke_signed
        new_target, // new authority (admin-specified), co-signs the outer tx
        slab,       // market
        vault_auth_seeds,
    )?;

    msg!("RotateInsuranceAuthority: insurance_authority rotated off vault_auth PDA to new target");
    Ok(())
}

// ============================================================================
// PERC-272: LP Vault — Fee Accrual & Trading Pool Init
// ============================================================================

/// #136 pre-accrue guard — shared by EVERY path that prices against pool balances
/// (`process_deposit`, `process_withdraw`, `process_deposit_junior`). Crystallizes any
/// pending mode-1 trading-fee surplus into share price BEFORE pricing, so LP cannot be
/// minted/redeemed at the stale pre-accrual price and capture fees earned before joining.
///
/// MUST be called AFTER the caller has verified `pool.vault == vault.key` and BEFORE the
/// caller's user<->vault transfer, so the balance read reflects only the fee surplus and
/// NOT the operation's own collateral. Mode-0 is a no-op; idempotent (a second call folds
/// zero surplus). Centralized so the pricing paths cannot drift — this guard was previously
/// inline-duplicated and the junior path was the one that was missed (see #146).
fn pre_accrue_mode1(pool: &mut state::StakePool, vault: &AccountInfo) -> ProgramResult {
    if pool.pool_mode == 1 {
        if *vault.owner != crate::spl_token::id() {
            return Err(ProgramError::IllegalOwner);
        }
        let current_balance = {
            let vault_data = vault.try_borrow_data()?;
            crate::spl_token::state::Account::unpack(&vault_data)?.amount
        };
        accrue_fees_inner(pool, current_balance)?;
    }
    Ok(())
}

/// Crystallize any un-accrued vault surplus into pool share price. Shared by the
/// permissionless `AccrueFees` instruction AND the deposit/withdraw pre-accrue guard
/// (#136) so every pricing path applies byte-identical accounting.
///
/// `current_balance` MUST be the verified vault token-account balance read BEFORE any
/// deposit transfer in the calling instruction — otherwise the deposit's own collateral
/// would be mis-credited as fees. The caller must have already confirmed the vault key +
/// SPL-Token ownership. Mutates only `pool`. No-op when there is no surplus or no LP
/// holders, preserving the first-depositor bootstrap / anti-brick guard.
fn accrue_fees_inner(pool: &mut state::StakePool, current_balance: u64) -> ProgramResult {
    // total_pool_value() = deposited - withdrawn - flushed + returned + fees_earned (mode 1)
    // — the authoritative expected balance; any excess is un-accrued fee revenue.
    let pool_value = pool.total_pool_value().ok_or(StakeError::Overflow)?;

    // Only accrue when there are active LP holders. Accruing at total_lp_supply == 0
    // would set total_fees_earned > 0 at zero supply, tripping calc_lp_for_deposit's
    // orphaned-value guard and permanently bricking the first deposit (an attacker can
    // donate 1 token to the vault pre-first-deposit to trigger it).
    if current_balance > pool_value && pool.total_lp_supply > 0 {
        let fee_delta = current_balance - pool_value;

        // Snapshot pre-fee tranche balances BEFORE incrementing total_fees_earned.
        // senior_balance() derives from total_pool_value() which includes
        // total_fees_earned, so reading it post-increment would inflate the senior
        // weight in distribute_fees and systematically shortchange the junior tranche.
        let distribute_to_junior = pool.tranche_enabled() && pool.junior_total_lp() > 0;
        let (snapshot_junior_bal, snapshot_senior_bal) = if distribute_to_junior {
            (
                pool.junior_balance(),
                pool.senior_balance().ok_or(StakeError::Overflow)?,
            )
        } else {
            (0, 0)
        };

        pool.total_fees_earned = pool
            .total_fees_earned
            .checked_add(fee_delta)
            .ok_or(StakeError::Overflow)?;

        // PERC-303: distribute the fee delta between junior/senior sub-pools using the
        // junior fee multiplier. Senior implicitly receives the remainder since
        // senior_balance = total_pool_value() - junior_balance and total_fees_earned
        // was already incremented by the full fee_delta above.
        if distribute_to_junior {
            let (junior_fee, _) = crate::math::distribute_fees(
                snapshot_junior_bal,
                snapshot_senior_bal,
                pool.junior_fee_mult_bps(),
                fee_delta,
            );
            pool.set_junior_balance(
                pool.junior_balance()
                    .checked_add(junior_fee)
                    .ok_or(StakeError::Overflow)?,
            );
        }

        msg!(
            "AccrueFees: accrued {} fees, total_fees_earned={}",
            fee_delta,
            pool.total_fees_earned
        );
    }
    Ok(())
}

/// Accrue trading fees from the percolator engine to the LP vault.
/// Permissionless: reads vault token account balance and updates pool state.
///
/// Fee delta = current_vault_balance - last_vault_snapshot - net_deposits_since_last
/// To keep it simple and trustless: we track the vault token account balance directly.
/// Any increase in vault balance beyond deposits is fee revenue.
fn process_accrue_fees(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let caller = next_account_info(accounts_iter)?; // signer, permissionless
    if !caller.is_signer {
        msg!("AccrueFees: caller must be a signer");
        return Err(ProgramError::MissingRequiredSignature);
    }
    let pool_ai = next_account_info(accounts_iter)?;
    let vault_ai = next_account_info(accounts_iter)?;
    let clock_ai = next_account_info(accounts_iter)?;

    // BUG-3: Validate pool account ownership and non-emptiness before reading it.
    // Without these guards, an attacker can pass an arbitrary account as pool_ai;
    // bytemuck::try_from_bytes_mut would reinterpret foreign data as StakePool state.
    // Also validate writability since AccrueFees modifies pool state.
    validate_account_not_empty(pool_ai)?;
    validate_account_owner(pool_ai, program_id)?;
    validate_account_writable(pool_ai)?;

    // Validate pool PDA
    let mut pool_data = pool_ai.try_borrow_mut_data()?;
    let pool = pool_from_data_mut(&mut pool_data[..])?;

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if !pool.validate_discriminator() {
        return Err(StakeError::InvalidAccount.into());
    }
    // FINDING-5: Validate pool version on AccrueFees.
    validate_pool_version(pool)?;

    // BUG-3 (continued): Verify the pool PDA is correctly derived from its stored slab key.
    // Prevents a crafted pool account at a different address from being accepted.
    {
        let slab_key = pool.slab_pubkey();
        let (expected_pool, _) = state::derive_pool_pda(program_id, &slab_key);
        if *pool_ai.key != expected_pool {
            msg!("AccrueFees: pool PDA does not match derived address");
            return Err(StakeError::InvalidPda.into());
        }
    }

    // Only trading LP mode pools accrue fees
    if pool.pool_mode != 1 {
        msg!("AccrueFees: pool is not in trading LP mode");
        return Err(StakeError::InvalidPoolMode.into());
    }

    // FINDING-3: Verify vault key BEFORE reading vault data.
    // Reading the vault token account before verifying the key allows an attacker to
    // pass an arbitrary token account whose balance then drives fee accounting.
    // The key check must be the first thing done with vault_ai.
    if vault_ai.key.to_bytes() != pool.vault {
        msg!("AccrueFees: vault account does not match pool.vault");
        return Err(ProgramError::InvalidAccountData);
    }
    // NEW-5: Verify vault is owned by SPL Token program before unpacking.
    if *vault_ai.owner != crate::spl_token::id() {
        msg!("AccrueFees: vault account not owned by SPL Token program");
        return Err(ProgramError::IllegalOwner);
    }

    // Read vault token account balance (key and owner already verified above)
    let vault_data = vault_ai.try_borrow_data()?;
    let vault_state = crate::spl_token::state::Account::unpack(&vault_data)?;
    let current_balance = vault_state.amount;

    let clock = Clock::from_account_info(clock_ai)?;

    // BUG-7: Compute the expected vault balance using total_pool_value() rather than
    // manually reconstructing it.  The manual formula
    //   pool_value = total_deposited - total_withdrawn + total_fees_earned
    // omits total_flushed and total_returned.  For trading LP pools (mode 1), flush
    // operations should not occur (guarded in FlushToInsurance), but if total_flushed
    // or total_returned are ever non-zero the stale formula produces an incorrect
    // fee_delta, potentially double-counting or missing fees.
    // total_pool_value() = deposited - withdrawn - flushed + returned + fees_earned (mode 1)
    // which is the authoritative expected balance.
    // #136: fold any un-accrued vault surplus into share price via the shared helper,
    // so this permissionless instruction and the deposit/withdraw pre-accrue guard apply
    // byte-identical accounting (snapshot-before-increment + tranche distribution).
    accrue_fees_inner(pool, current_balance)?;

    pool.last_fee_accrual_slot = clock.slot;
    pool.last_vault_snapshot = current_balance;

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 14: AdminSetHwmConfig — PERC-313
// ═══════════════════════════════════════════════════════════════

/// Admin sets high-water mark configuration for LP vault drain protection.
fn process_admin_set_hwm_config(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    enabled: bool,
    hwm_floor_bps: u16,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // BUG-4: Validate pool account ownership and non-emptiness before reading it.
    validate_account_owner(pool_pda, program_id)?;
    validate_account_not_empty(pool_pda)?;

    // Validate hwm_floor_bps before modifying state
    if enabled {
        validate_hwm_floor_bps(hwm_floor_bps)?;
    }

    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool = pool_from_data_mut(&mut pool_data[..])?;

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    // AUDIT MED-5: validate discriminator on AdminSetHwmConfig
    if !pool.validate_discriminator() {
        return Err(StakeError::InvalidAccount.into());
    }
    // FINDING-5: Validate pool version on AdminSetHwmConfig.
    validate_pool_version(pool)?;
    if pool.admin != admin.key.to_bytes() {
        return Err(StakeError::Unauthorized.into());
    }

    // #185: only write the floor when ENABLING. Disabling must preserve the
    // previously stored floor — writing it unconditionally let a disable call
    // (which carries hwm_floor_bps=0 and skips validate_hwm_floor_bps) clobber
    // the stored floor, so re-enabling later silently lost the prior value.
    apply_hwm_config(pool, enabled, hwm_floor_bps);

    msg!(
        "HWM config updated: enabled={}, floor_bps={}",
        enabled,
        pool.hwm_floor_bps()
    );
    Ok(())
}

/// Apply a HWM config change to `pool`.
///
/// The enabled flag always tracks `enabled`. The floor is only written when
/// enabling — disabling preserves whatever floor was previously stored so a
/// subsequent re-enable does not silently reset it to the disable call's
/// (validation-skipped) `hwm_floor_bps` argument (#185).
fn apply_hwm_config(pool: &mut StakePool, enabled: bool, hwm_floor_bps: u16) {
    pool.set_hwm_enabled(enabled);
    if enabled {
        pool.set_hwm_floor_bps(hwm_floor_bps);
    }
}

// ═══════════════════════════════════════════════════════════════
// PERC-303: Senior/Junior LP Tranches
// ═══════════════════════════════════════════════════════════════

/// Admin enables/configures senior-junior tranches on a pool.
fn process_admin_set_tranche_config(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    junior_fee_mult_bps: u16,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let admin = next_account_info(accounts_iter)?;
    let pool_ai = next_account_info(accounts_iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // BUG-4: Validate pool account ownership and non-emptiness before reading it.
    validate_account_owner(pool_ai, program_id)?;
    validate_account_not_empty(pool_ai)?;

    let mut pool_data = pool_ai.try_borrow_mut_data()?;
    let pool = pool_from_data_mut(&mut pool_data[..])?;

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    // AUDIT MED-5: validate discriminator on AdminSetTrancheConfig
    if !pool.validate_discriminator() {
        return Err(StakeError::InvalidAccount.into());
    }
    // FINDING-5: Validate pool version on AdminSetTrancheConfig.
    validate_pool_version(pool)?;
    if pool.admin != admin.key.to_bytes() {
        return Err(StakeError::Unauthorized.into());
    }

    // Validate multiplier: minimum 10000 (1x), maximum 50000 (5x)
    if !(10_000..=50_000).contains(&junior_fee_mult_bps) {
        msg!(
            "AdminSetTrancheConfig: junior_fee_mult_bps must be 10000..50000, got {}",
            junior_fee_mult_bps
        );
        return Err(ProgramError::InvalidArgument);
    }

    // GOVERNANCE (#127): lock the multiplier once any junior LP exists.
    //
    // Junior depositors entered under the current junior_fee_mult_bps — it is the
    // economic term they accepted for taking first-loss exposure. Since
    // process_accrue_fees reads the multiplier live (see the distribute_fees call)
    // with no per-epoch snapshot, a mid-life change would either:
    //   - let the admin pump the multiplier right before AccrueFees to extract an
    //     outsized fee share into an admin-controlled junior position, or
    //   - let the admin depress the multiplier to silently cut junior yield below
    //     what depositors were promised at deposit time.
    //
    // Idempotent re-writes (same value) still succeed so admin tooling can re-apply
    // config. Once all juniors withdraw (junior_total_lp == 0), the multiplier is
    // freely configurable for the next cohort.
    //
    // NOTE: this guard was dropped in the v17 convergence (it post-dated the branch
    // point); restored here to match the audited pre-v17 behavior.
    if pool.junior_total_lp() > 0 && pool.junior_fee_mult_bps() != junior_fee_mult_bps {
        msg!(
            "AdminSetTrancheConfig: junior_fee_mult_bps is locked while juniors \
             exist (current={}, requested={}, junior_total_lp={})",
            pool.junior_fee_mult_bps(),
            junior_fee_mult_bps,
            pool.junior_total_lp()
        );
        return Err(StakeError::Unauthorized.into());
    }

    pool.set_tranche_enabled(true);
    pool.set_junior_fee_mult_bps(junior_fee_mult_bps);

    msg!(
        "Tranche config set: enabled=true, junior_fee_mult_bps={}",
        junior_fee_mult_bps
    );
    Ok(())
}

/// Deposit into the junior (first-loss) tranche.
fn process_deposit_junior(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    if amount == 0 {
        return Err(StakeError::ZeroAmount.into());
    }

    let accounts_iter = &mut accounts.iter();

    let user = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let user_ata = next_account_info(accounts_iter)?;
    let vault = next_account_info(accounts_iter)?;
    let lp_mint = next_account_info(accounts_iter)?;
    let user_lp_ata = next_account_info(accounts_iter)?;
    let vault_auth = next_account_info(accounts_iter)?;
    let deposit_pda = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;
    let clock_sysvar = next_account_info(accounts_iter)?;
    let system_program = next_account_info(accounts_iter)?;

    if !user.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // NEW-1: Validate pool account ownership before bytemuck reinterpretation.
    // Every other write path has this check — DepositJunior was the only gap.
    validate_account_not_empty(pool_pda)?;
    validate_account_owner(pool_pda, program_id)?;
    validate_account_writable(pool_pda)?;

    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool = pool_from_data_mut(&mut pool_data[..])?;

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if !pool.validate_discriminator() {
        return Err(StakeError::InvalidAccount.into());
    }
    // FINDING-9: Validate pool version on DepositJunior, matching process_deposit.
    validate_pool_version(pool)?;
    if !pool.tranche_enabled() {
        return Err(StakeError::TrancheNotEnabled.into());
    }
    if pool.lp_mint != lp_mint.key.to_bytes() {
        return Err(StakeError::InvalidMint.into());
    }
    if pool.vault != vault.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }
    if pool.market_resolved() {
        return Err(StakeError::MarketResolved.into());
    }

    let (expected_vault_auth, _) = derive_vault_authority(program_id, pool_pda.key);
    if *vault_auth.key != expected_vault_auth {
        return Err(StakeError::InvalidAccount.into());
    }

    if pool.deposit_cap > 0 {
        // #154: enforce the cap on PRINCIPAL TVL (no accrued fees), not total_pool_value();
        // otherwise fee appreciation on a mode-1 trading pool silently locks out new deposits.
        let current_value = pool.principal_tvl().ok_or(StakeError::Overflow)?;
        let new_value = current_value
            .checked_add(amount)
            .ok_or(StakeError::Overflow)?;
        if new_value > pool.deposit_cap {
            return Err(StakeError::DepositCapExceeded.into());
        }
    }

    verify_token_program(token_program)?;

    // Verify user_ata mint matches pool collateral and is owned by user.
    // AUDIT MED-3: DepositJunior was missing mint check (present in process_deposit).
    {
        // #195: the account must be SPL-Token-program-owned before we read its raw
        // layout — otherwise a non-token account with crafted bytes could satisfy the
        // mint/owner field checks below (the SPL CPI would later revert, but fail fast).
        if *user_ata.owner != crate::spl_token::id() {
            msg!("Error: user_ata is not owned by the SPL Token program");
            return Err(StakeError::InvalidAccount.into());
        }
        let ata_data = user_ata.try_borrow_data()?;
        if ata_data.len() < crate::spl_token::state::ACCOUNT_LEN {
            return Err(StakeError::InvalidAccount.into());
        }
        let mint_bytes: &[u8; 32] = ata_data[0..32]
            .try_into()
            .map_err(|_| StakeError::InvalidAccount)?;
        if mint_bytes != &pool.collateral_mint {
            msg!("Error: user_ata mint does not match pool collateral_mint");
            return Err(StakeError::InvalidAccount.into());
        }
        let owner_bytes: &[u8; 32] = ata_data[32..64]
            .try_into()
            .map_err(|_| StakeError::InvalidAccount)?;
        if owner_bytes != user.key.as_ref() {
            msg!("Error: user_ata is not owned by the signer — delegation attack blocked");
            return Err(StakeError::Unauthorized.into());
        }
    }

    // #211: same LP-recipient-ownership gap as process_deposit — DepositJunior
    // also mints LP to user_lp_ata without checking the depositor owns it.
    validate_lp_recipient_account(user_lp_ata, &pool.lp_mint, user.key)?;

    // #136 (junior): crystallize pending trading-fee surplus into share price BEFORE pricing
    // this junior deposit (mode-1). process_deposit (senior/global) and process_withdraw
    // already do this; the junior path was the one that was missed — without it a junior
    // depositor mints at the stale pre-fee price and a later permissionless AccrueFees hands
    // them a (multiplier-weighted) share of fees earned before they joined (see #146). Reads
    // the vault balance before the user->vault transfer below; pool.vault + token program
    // were verified above.
    //
    // (Rebase note #150: this pre_accrue_mode1 call is from PR #148 — KEEP it. The
    // InsuranceLossOutstanding gate below is added AFTER it, not in place of it, so #148's
    // JIT fee-snipe guard stays intact.)
    pre_accrue_mode1(pool, vault)?;

    // Pause junior deposits while an insurance loss is OUTSTANDING (flushed but not
    // yet returned). effective_junior_balance() applies the pool's CURRENT net_loss
    // to the junior tranche with no baseline for when the cohort began, so a junior
    // depositing during an open claim would inherit a loss it was never exposed to
    // (deterministic theft from the depositor; see the issue), and the mirror case
    // would snipe the recovery. Both directions require a junior deposit while
    // total_flushed > total_returned — so gate exactly that. total_flushed/returned
    // move only via admin Flush/Return (mode-0), so deposits resume once insurance is
    // returned. The SENIOR path is unaffected: a senior deposit prices against the
    // current marked-down senior_balance and never perturbs effective_junior_balance.
    //
    // #161 escape (admin-free, permissionless): when the LAST junior exits a junior-absorbed
    // loss, process_withdraw realizes the forfeited loss (total_returned += L), driving
    // net_loss to 0 and lifting THIS gate — so a fully-exited junior tranche always re-opens.
    // #162 residual freeze (BY DESIGN): if a junior keeps holding, or the loss spilled past
    // junior, net_loss stays positive and the gate stays closed for a permanent loss. Safe
    // (fully backed; existing LPs withdraw freely) and deliberate — see the senior-gate note
    // above for why no auto-write-off (admin burned / resolved blocks deposits / time-box unfair).
    if pool.total_flushed > pool.total_returned {
        msg!(
            "DepositJunior paused: insurance loss outstanding (flushed {} > returned {})",
            pool.total_flushed,
            pool.total_returned
        );
        return Err(StakeError::InsuranceLossOutstanding.into());
    }

    // Use effective_junior_balance() so that LP pricing reflects any insurance
    // losses already absorbed by the junior tranche.  Pricing against the raw
    // junior_balance() (stale, pre-loss) would charge new depositors a higher
    // price than the sub-pool actually warrants, transferring value from incoming
    // junior depositors to existing junior LP holders.
    let junior_lp = pool.junior_total_lp();
    let junior_bal = pool.effective_junior_balance();
    let lp_to_mint = crate::math::calc_junior_lp_for_deposit(junior_lp, junior_bal, amount)
        .ok_or(StakeError::Overflow)?;
    // S-4 (junior path): same dedicated zero-share reject as process_deposit.
    if lp_to_mint == 0 {
        return Err(StakeError::ZeroSharesMinted.into());
    }

    invoke(
        &crate::spl_token::transfer(
            token_program.key,
            user_ata.key,
            vault.key,
            user.key,
            &[],
            amount,
        )?,
        &[
            user_ata.clone(),
            vault.clone(),
            user.clone(),
            token_program.clone(),
        ],
    )?;

    let (_, vault_auth_bump) = state::derive_vault_authority(program_id, pool_pda.key);
    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];

    invoke_signed(
        &crate::spl_token::mint_to(
            token_program.key,
            lp_mint.key,
            user_lp_ata.key,
            vault_auth.key,
            &[],
            lp_to_mint,
        )?,
        &[
            lp_mint.clone(),
            user_lp_ata.clone(),
            vault_auth.clone(),
            token_program.clone(),
        ],
        &[vault_auth_seeds],
    )?;

    pool.total_deposited = pool
        .total_deposited
        .checked_add(amount)
        .ok_or(StakeError::Overflow)?;
    pool.total_lp_supply = pool
        .total_lp_supply
        .checked_add(lp_to_mint)
        .ok_or(StakeError::Overflow)?;
    pool.set_junior_total_lp(
        pool.junior_total_lp()
            .checked_add(lp_to_mint)
            .ok_or(StakeError::Overflow)?,
    );
    pool.set_junior_balance(
        pool.junior_balance()
            .checked_add(amount)
            .ok_or(StakeError::Overflow)?,
    );

    let clock = Clock::from_account_info(clock_sysvar)?;

    // PERC-313: Refresh high-water mark after junior deposit (TVL increased).
    // Matches the pattern in process_deposit (lines 564-569). Without this,
    // junior deposits raise TVL without ratcheting the epoch HWM, leaving the
    // withdrawal floor calculated against a stale (lower) peak.
    if pool.hwm_enabled() {
        let current_tvl = pool.total_pool_value().ok_or(StakeError::Overflow)?;
        pool.refresh_hwm(clock.epoch, current_tvl);
    }

    let (expected_deposit_pda, deposit_bump) =
        state::derive_deposit_pda(program_id, pool_pda.key, user.key);
    if *deposit_pda.key != expected_deposit_pda {
        return Err(StakeError::InvalidPda.into());
    }

    if !deposit_pda.data_is_empty() && *deposit_pda.owner != *program_id {
        return Err(StakeError::InvalidAccount.into());
    }

    if deposit_pda.data_is_empty() {
        let deposit_seeds: &[&[u8]] = &[
            b"stake_deposit",
            pool_pda.key.as_ref(),
            user.key.as_ref(),
            &[deposit_bump],
        ];
        // Robust against deposit-PDA squatting: a griefer who pre-funds this
        // deterministic address with lamports would make a bare create_account abort
        // (AccountAlreadyInUse) and permanently brick the user's first deposit. See #163.
        create_or_adopt_pda(
            deposit_pda,
            user,
            system_program,
            program_id,
            STAKE_DEPOSIT_SIZE,
            deposit_seeds,
        )?;
    }

    let mut deposit_data = deposit_pda.try_borrow_mut_data()?;
    let deposit = deposit_from_data_mut(&mut deposit_data[..])?;

    if deposit.is_initialized != 1 {
        deposit.set_discriminator();
    } else if !deposit.validate_discriminator() {
        // #194: an already-initialized record must carry the correct StakeDeposit
        // discriminator; reject a forged account that set is_initialized without init.
        return Err(StakeError::InvalidAccount.into());
    }

    // PERC-303: Prevent mixing. If deposit PDA is NOT flagged as junior
    // and was previously used for senior deposits, reject. Check regardless
    // of lp_amount to prevent bypass via full withdrawal then re-deposit.
    if deposit._reserved[8] != 1 && deposit.is_initialized == 1 {
        return Err(StakeError::WrongTranche.into());
    }

    // BUG-9: Set the junior flag BEFORE setting is_initialized = 1 so both writes
    // are committed together in the same account data mutation.  If we set
    // is_initialized = 1 first and the transaction aborts between the two writes
    // (e.g., compute budget exceeded), the PDA would appear initialized but lack
    // the junior flag, permanently bricking it: any future DepositJunior would
    // reject it (wrong tranche) and process_deposit would also reject it (senior
    // PDA already initialized without junior flag).
    deposit._reserved[8] = 1;
    deposit.is_initialized = 1;
    deposit.bump = deposit_bump;
    deposit.pool = pool_pda.key.to_bytes();
    deposit.user = user.key.to_bytes();
    deposit.last_deposit_slot = clock.slot;
    deposit.lp_amount = deposit
        .lp_amount
        .checked_add(lp_to_mint)
        .ok_or(StakeError::Overflow)?;

    msg!(
        "DepositJunior: {} collateral, minted {} LP tokens (junior tranche)",
        amount,
        lp_to_mint
    );
    Ok(())
}

/// Initialize a pool in trading LP vault mode (PERC-272).
/// Same mechanics as InitPool but sets pool_mode = 1.
fn process_init_trading_pool(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    cooldown_slots: u64,
    deposit_cap: u64,
) -> ProgramResult {
    // Reuse InitPool logic
    process_init_pool(program_id, accounts, cooldown_slots, deposit_cap)?;

    // Now update pool_mode to 1 (trading LP)
    // AUDIT HIGH-4: Validate pool_pda ownership instead of trusting hardcoded index
    let pool_ai = &accounts[INIT_POOL_POOL_PDA_INDEX];
    validate_account_owner(pool_ai, program_id)?;
    let mut pool_data = pool_ai.try_borrow_mut_data()?;
    let pool = pool_from_data_mut(&mut pool_data[..])?;
    if !pool.validate_discriminator() {
        return Err(StakeError::InvalidAccount.into());
    }
    pool.pool_mode = 1;

    msg!("InitTradingPool: pool_mode set to 1 (trading LP vault)");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 10: ReturnInsurance — admin returns insurance funds to pool vault
// ═══════════════════════════════════════════════════════════════

fn process_return_insurance(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    if amount == 0 {
        return Err(StakeError::ZeroAmount.into());
    }

    let accounts_iter = &mut accounts.iter();
    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let admin_ata = next_account_info(accounts_iter)?; // source
    let vault = next_account_info(accounts_iter)?; // destination
    let token_program = next_account_info(accounts_iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    verify_token_program(token_program)?;
    validate_account_owner(pool_pda, program_id)?;
    validate_account_not_empty(pool_pda)?;

    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool = pool_from_data_mut(&mut pool_data[..])?;

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if !pool.validate_discriminator() {
        return Err(StakeError::InvalidAccount.into());
    }
    validate_pool_version(pool)?;
    if pool.admin != admin.key.to_bytes() {
        return Err(StakeError::Unauthorized.into());
    }
    if pool.vault != vault.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }

    // Validate amount doesn't exceed outstanding insurance
    let outstanding = pool.total_flushed.saturating_sub(pool.total_returned);
    if amount > outstanding {
        msg!(
            "ReturnInsurance: amount {} exceeds outstanding insurance {}",
            amount,
            outstanding
        );
        return Err(ProgramError::InvalidArgument);
    }

    // Validate admin_ata is an SPL Token account for the pool collateral mint
    // and is owned by the admin signer.
    if *admin_ata.owner != crate::spl_token::id() {
        msg!("Error: admin_ata is not owned by the SPL Token program");
        return Err(StakeError::InvalidAccount.into());
    }

    {
        let ata_data = admin_ata.try_borrow_data()?;

        if ata_data.len() < crate::spl_token::state::ACCOUNT_LEN {
            return Err(StakeError::InvalidAccount.into());
        }

        let ata_mint: &[u8; 32] = ata_data[0..32]
            .try_into()
            .map_err(|_| StakeError::InvalidAccount)?;

        if ata_mint != &pool.collateral_mint {
            msg!("Error: admin_ata mint does not match pool collateral_mint");
            return Err(StakeError::InvalidMint.into());
        }

        let owner_bytes: &[u8; 32] = ata_data[32..64]
            .try_into()
            .map_err(|_| StakeError::InvalidAccount)?;

        if owner_bytes != admin.key.as_ref() {
            msg!("Error: admin_ata is not owned by the admin signer");
            return Err(StakeError::Unauthorized.into());
        }
    }

    // SPL Token transfer: admin_ata → vault (admin signs as token owner)
    let transfer_ix = crate::spl_token::transfer(
        token_program.key,
        admin_ata.key,
        vault.key,
        admin.key,
        &[],
        amount,
    )?;
    invoke(
        &transfer_ix,
        &[admin_ata.clone(), vault.clone(), admin.clone()],
    )?;

    // Update accounting
    pool.total_returned = pool
        .total_returned
        .checked_add(amount)
        .ok_or(StakeError::Overflow)?;

    msg!(
        "ReturnInsurance: {} tokens returned to pool vault (total_returned: {})",
        amount,
        pool.total_returned
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 18: SetMarketResolved — admin marks pool as resolved
// ═══════════════════════════════════════════════════════════════

fn process_set_market_resolved(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;

    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    validate_account_owner(pool_pda, program_id)?;
    // #184: mirror the #177/#183 fix — reject empty/undersized pool accounts
    // before bytemuck reinterprets the data (a too-short slice would panic).
    validate_account_not_empty(pool_pda)?;
    // #210: require the pool account be writable before mutating it, matching
    // every other state-mutating handler.
    validate_account_writable(pool_pda)?;

    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool = pool_from_data_mut(&mut pool_data[..])?;

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if !pool.validate_discriminator() {
        return Err(StakeError::InvalidAccount.into());
    }
    validate_pool_version(pool)?;
    if pool.admin != admin.key.to_bytes() {
        return Err(StakeError::Unauthorized.into());
    }

    if pool.market_resolved() {
        msg!("Market already resolved");
        return Err(StakeError::MarketResolved.into());
    }

    pool.set_market_resolved(true);

    msg!("SetMarketResolved: pool marked as resolved, deposits blocked");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytemuck::Zeroable;

    #[test]
fn return_insurance_rejects_admin_ata_not_owned_by_admin() {
    use solana_program::account_info::AccountInfo;

    let program_id = Pubkey::new_from_array([9u8; 32]);
    let admin_key = Pubkey::new_from_array([1u8; 32]);
    let pool_key = Pubkey::new_from_array([2u8; 32]);
    let admin_ata_key = Pubkey::new_from_array([3u8; 32]);
    let vault_key = Pubkey::new_from_array([4u8; 32]);
    let collateral_mint = Pubkey::new_from_array([5u8; 32]);
    let other_owner = Pubkey::new_from_array([6u8; 32]);

    let mut pool = StakePool::zeroed();
    pool.is_initialized = 1;
    pool.admin = admin_key.to_bytes();
    pool.vault = vault_key.to_bytes();
    pool.collateral_mint = collateral_mint.to_bytes();
    pool.total_flushed = 100;
    pool.total_returned = 0;
    pool.set_discriminator();

    let mut pool_data = bytemuck::bytes_of(&pool).to_vec();

    let mut admin_ata_data = vec![0u8; crate::spl_token::state::ACCOUNT_LEN];
    admin_ata_data[0..32].copy_from_slice(collateral_mint.as_ref());
    admin_ata_data[32..64].copy_from_slice(other_owner.as_ref());

    let mut vault_data = vec![0u8; crate::spl_token::state::ACCOUNT_LEN];

    let mut admin_lamports = 0u64;
    let mut pool_lamports = 0u64;
    let mut admin_ata_lamports = 0u64;
    let mut vault_lamports = 0u64;
    let mut token_program_lamports = 0u64;

    let mut admin_data = vec![];
    let mut token_program_data = vec![];

    let token_program_id = crate::spl_token::id();
    let system_program_id = solana_program::system_program::id();

    let accounts = vec![
        AccountInfo::new(
            &admin_key,
            true,
            false,
            &mut admin_lamports,
            &mut admin_data,
            &system_program_id,
            false,
            0,
        ),
        AccountInfo::new(
            &pool_key,
            false,
            true,
            &mut pool_lamports,
            &mut pool_data,
            &program_id,
            false,
            0,
        ),
        AccountInfo::new(
            &admin_ata_key,
            false,
            true,
            &mut admin_ata_lamports,
            &mut admin_ata_data,
            &token_program_id,
            false,
            0,
        ),
        AccountInfo::new(
            &vault_key,
            false,
            true,
            &mut vault_lamports,
            &mut vault_data,
            &token_program_id,
            false,
            0,
        ),
        AccountInfo::new(
            &token_program_id,
            false,
            false,
            &mut token_program_lamports,
            &mut token_program_data,
            &system_program_id,
            false,
            0,
        ),
    ];

    let result = process(
        &program_id,
        &accounts,
        &[
            10u8, // ReturnInsurance
            10, 0, 0, 0, 0, 0, 0, 0, // amount = 10u64 little-endian
        ],
    );

    assert!(
        matches!(result, Err(e) if e == StakeError::Unauthorized.into()),
        "ReturnInsurance should reject admin_ata when the token account owner is not the admin signer"
    );
}

    // #185 regression: disabling HWM must NOT clobber the stored floor, so that
    // a later re-enable preserves the operator's original floor. The disable
    // path skips validate_hwm_floor_bps and typically carries hwm_floor_bps=0;
    // before the fix that 0 overwrote the stored floor.
    #[test]
    fn test_apply_hwm_config_disable_preserves_floor() {
        let mut pool = StakePool::zeroed();

        // Enable with a real floor.
        apply_hwm_config(&mut pool, true, 5000);
        assert!(pool.hwm_enabled());
        assert_eq!(pool.hwm_floor_bps(), 5000);

        // Disable with the validation-skipped sentinel (0): floor must survive.
        apply_hwm_config(&mut pool, false, 0);
        assert!(!pool.hwm_enabled(), "disable must clear the enabled flag");
        assert_eq!(
            pool.hwm_floor_bps(),
            5000,
            "disabling HWM must preserve the previously stored floor"
        );

        // Re-enable without re-specifying the floor (0 again): the preserved
        // floor remains in effect because disable never wiped it.
        apply_hwm_config(&mut pool, true, 0);
        assert!(pool.hwm_enabled());
        // Re-enabling with an explicit 0 floor IS an intentional write (the
        // enable path is validated upstream), so the floor now tracks the arg.
        assert_eq!(pool.hwm_floor_bps(), 0);
    }

    // Enabling always writes the supplied (upstream-validated) floor.
    #[test]
    fn test_apply_hwm_config_enable_writes_floor() {
        let mut pool = StakePool::zeroed();

        apply_hwm_config(&mut pool, true, 7500);
        assert!(pool.hwm_enabled());
        assert_eq!(pool.hwm_floor_bps(), 7500);

        // Re-enable with a different floor overwrites it.
        apply_hwm_config(&mut pool, true, 9000);
        assert!(pool.hwm_enabled());
        assert_eq!(pool.hwm_floor_bps(), 9000);
    }

    // ── #196: hwm_floor_bps must be bounded strictly below 100% ──
    //
    // The HWM floor is a per-epoch drain rate limiter, not a kill switch. At exactly
    // 10_000 (100%) the floor equals the high-water mark and — because refresh_hwm
    // keeps the mark >= current TVL and re-anchors it every new epoch — EVERY positive
    // withdrawal is permanently blocked (a pool-wide freeze that survives epoch
    // rollover). validate_hwm_floor_bps must therefore reject 100% (and anything above
    // the cap) while still accepting the full legitimate rate-limiter range.

    #[test]
    fn test_validate_hwm_floor_bps_rejects_100_percent_and_above_cap() {
        // The exact freeze value from #196.
        assert!(
            validate_hwm_floor_bps(10_000).is_err(),
            "100% floor must be rejected: it permanently freezes all withdrawals (#196)"
        );
        // One basis point past the cap, and the u16 extreme, must also be rejected.
        assert!(validate_hwm_floor_bps(MAX_HWM_FLOOR_BPS + 1).is_err());
        assert!(validate_hwm_floor_bps(u16::MAX).is_err());
    }

    #[test]
    fn test_validate_hwm_floor_bps_rejects_zero() {
        // Unchanged: a 0 floor offers no anti-drain protection and is rejected on the
        // (validated) enable path.
        assert!(validate_hwm_floor_bps(0).is_err());
    }

    #[test]
    fn test_validate_hwm_floor_bps_accepts_legitimate_range_up_to_cap() {
        // Every legitimate rate-limiter floor, including the new maximum, is accepted.
        for bps in [1u16, 5_000, 7_500, MAX_HWM_FLOOR_BPS] {
            assert!(
                validate_hwm_floor_bps(bps).is_ok(),
                "{bps} bps is a valid non-freezing floor and must be accepted"
            );
        }
        // The cap is strictly below 100%, so a withdrawal margin always exists.
        assert!(MAX_HWM_FLOOR_BPS < 10_000);
    }

    // Behavioral proof through the same math the withdraw gate calls
    // (processor.rs withdraw path -> math::hwm_floor / hwm_withdrawal_allowed): at the
    // capped maximum a healthy pool still permits a positive withdrawal (the feature
    // stays a limiter), whereas the now-rejected 100% value blocked even a 1-unit exit.
    #[test]
    fn test_capped_floor_preserves_a_withdrawal_margin() {
        use crate::math::{hwm_floor, hwm_withdrawal_allowed};

        let tvl: u64 = 1_000_000;
        let hwm = tvl; // refresh_hwm invariant: hwm >= current_tvl

        let floor = hwm_floor(hwm, MAX_HWM_FLOOR_BPS).expect("floor computes");
        assert!(floor < tvl, "capped floor must leave a withdrawable margin");
        let margin = tvl - floor; // 100_000 at 9_000 bps (10% of peak)
        assert!(margin > 0);
        assert!(
            hwm_withdrawal_allowed(tvl - margin, hwm, MAX_HWM_FLOOR_BPS),
            "a withdrawal down to the floor must be allowed at the cap"
        );

        // Contrast: the rejected 100% value blocks even a single unit.
        assert!(
            !hwm_withdrawal_allowed(tvl - 1, hwm, 10_000),
            "100% floor (now rejected by the setter) would block every withdrawal"
        );
    }

    // ── #199: length-checked bytemuck reinterpretation helpers ──
    //
    // Every handler reinterprets account data via these helpers. They must return a
    // clean ProgramError on an undersized/zero-length buffer instead of panicking on
    // the `[..SIZE]` slice (the #199 bug), and must succeed on a correctly-sized buffer.
    // The attack shape: a StakeDeposit-sized buffer (STAKE_DEPOSIT_SIZE < STAKE_POOL_SIZE)
    // passed where a pool is expected.

    #[test]
    fn test_pool_helpers_reject_undersized_without_panic() {
        assert!(STAKE_DEPOSIT_SIZE < STAKE_POOL_SIZE, "deposit-sized buffer is a valid undersize");
        let mut deposit_sized = vec![0u8; STAKE_DEPOSIT_SIZE];
        assert!(pool_from_data_mut(&mut deposit_sized).is_err(), "mut: undersized -> Err, not panic");
        assert!(pool_from_data(&deposit_sized).is_err(), "ro: undersized -> Err, not panic");

        let mut one_short = vec![0u8; STAKE_POOL_SIZE - 1];
        assert!(pool_from_data_mut(&mut one_short).is_err());
        assert!(pool_from_data(&one_short).is_err());

        let mut empty: Vec<u8> = Vec::new();
        assert!(pool_from_data_mut(&mut empty).is_err());
        assert!(pool_from_data(&empty).is_err());
    }

    #[test]
    fn test_pool_helpers_accept_exact_and_oversized() {
        let mut buf = vec![0u8; STAKE_POOL_SIZE];
        let pool = pool_from_data_mut(&mut buf).expect("exact-size buffer must be Ok (mut)");
        assert_eq!(pool.is_initialized, 0);
        assert!(pool_from_data(&buf).is_ok(), "exact-size buffer must be Ok (ro)");
        // Real Solana accounts may carry trailing bytes; only the first SIZE are read.
        let mut over = vec![0u8; STAKE_POOL_SIZE + 32];
        assert!(pool_from_data_mut(&mut over).is_ok(), "oversized buffer must be Ok");
    }

    #[test]
    fn test_deposit_helpers_reject_undersized_without_panic() {
        let mut short = vec![0u8; STAKE_DEPOSIT_SIZE - 1];
        assert!(deposit_from_data_mut(&mut short).is_err());
        assert!(deposit_from_data(&short).is_err());
        let empty: Vec<u8> = Vec::new();
        assert!(deposit_from_data(&empty).is_err());
    }

    #[test]
    fn test_deposit_helpers_accept_exact_size() {
        let mut buf = vec![0u8; STAKE_DEPOSIT_SIZE];
        assert!(deposit_from_data_mut(&mut buf).is_ok());
        assert!(deposit_from_data(&buf).is_ok());
    }

    /// #210 PoC: `SetMarketResolved` must reject a non-writable pool account
    /// before mutating its state, like every other state-mutating handler.
    #[test]
    fn poc_set_market_resolved_should_reject_readonly_pool_account() {
        let program_id = Pubkey::new_from_array([9u8; 32]);
        let admin_key = Pubkey::new_from_array([1u8; 32]);
        let pool_key = Pubkey::new_from_array([2u8; 32]);
        let system_program_id = solana_program::system_program::id();

        let mut pool = StakePool::zeroed();
        pool.is_initialized = 1;
        pool.admin = admin_key.to_bytes();
        pool.set_discriminator();
        pool.set_market_resolved(false);

        let mut pool_data = bytemuck::bytes_of(&pool).to_vec();

        let mut admin_lamports = 0u64;
        let mut pool_lamports = 0u64;

        let mut admin_data = vec![];

        let accounts = vec![
            AccountInfo::new(
                &admin_key,
                true,
                false,
                &mut admin_lamports,
                &mut admin_data,
                &system_program_id,
                false,
                0,
            ),
            AccountInfo::new(
                &pool_key,
                false,
                false, // intentionally NOT writable
                &mut pool_lamports,
                &mut pool_data,
                &program_id,
                false,
                0,
            ),
        ];

        let result = process(&program_id, &accounts, &[18u8]);

        assert_eq!(
            result,
            Err(StakeError::InvalidAccount.into()),
            "SetMarketResolved should fail with InvalidAccount for a read-only pool account"
        );
    }
}
