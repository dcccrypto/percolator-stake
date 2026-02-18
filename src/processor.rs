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
    if *token_program.key != spl_token::id() {
        msg!("Error: invalid token program {}", token_program.key);
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}

use crate::cpi;
use crate::error::StakeError;
use crate::instruction::StakeInstruction;
use crate::state::{
    self, StakeDeposit, StakePool, STAKE_DEPOSIT_SIZE, STAKE_POOL_SIZE,
};

pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = StakeInstruction::unpack(instruction_data)?;

    match instruction {
        StakeInstruction::InitPool { cooldown_slots, deposit_cap } => {
            process_init_pool(program_id, accounts, cooldown_slots, deposit_cap)
        }
        StakeInstruction::Deposit { amount } => {
            process_deposit(program_id, accounts, amount)
        }
        StakeInstruction::Withdraw { lp_amount } => {
            process_withdraw(program_id, accounts, lp_amount)
        }
        StakeInstruction::FlushToInsurance { amount } => {
            process_flush_to_insurance(program_id, accounts, amount)
        }
        StakeInstruction::UpdateConfig { new_cooldown_slots, new_deposit_cap } => {
            process_update_config(program_id, accounts, new_cooldown_slots, new_deposit_cap)
        }
        StakeInstruction::TransferAdmin => {
            process_transfer_admin(program_id, accounts)
        }
        StakeInstruction::AdminSetOracleAuthority { new_authority } => {
            process_admin_set_oracle_authority(program_id, accounts, &new_authority)
        }
        StakeInstruction::AdminSetRiskThreshold { new_threshold } => {
            process_admin_set_risk_threshold(program_id, accounts, new_threshold)
        }
        StakeInstruction::AdminSetMaintenanceFee { new_fee } => {
            process_admin_set_maintenance_fee(program_id, accounts, new_fee)
        }
        StakeInstruction::AdminResolveMarket => {
            process_admin_resolve_market(program_id, accounts)
        }
        StakeInstruction::AdminWithdrawInsurance { amount } => {
            process_admin_withdraw_insurance(program_id, accounts, amount)
        }
        StakeInstruction::AdminSetInsurancePolicy {
            authority, min_withdraw_base, max_withdraw_bps, cooldown_slots
        } => {
            process_admin_set_insurance_policy(
                program_id, accounts, &authority, min_withdraw_base, max_withdraw_bps, cooldown_slots,
            )
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Helper: read pool, validate, return admin seeds
// ═══════════════════════════════════════════════════════════════

/// Validate pool is initialized, admin is signer, admin is transferred,
/// and percolator program matches stored value.
/// Returns the pool bump for PDA signing.
fn validate_admin_cpi(
    program_id: &Pubkey,
    pool_pda: &AccountInfo,
    admin: &AccountInfo,
    slab: &AccountInfo,
    percolator_program: &AccountInfo,
) -> Result<u8, ProgramError> {
    if !admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let pool_data = pool_pda.try_borrow_data()?;
    let pool: &StakePool = bytemuck::from_bytes(&pool_data[..STAKE_POOL_SIZE]);

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if pool.admin != admin.key.to_bytes() {
        return Err(StakeError::Unauthorized.into());
    }
    if pool.admin_transferred != 1 {
        return Err(StakeError::AdminNotTransferred.into());
    }
    if pool.slab != slab.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }
    if pool.percolator_program != percolator_program.key.to_bytes() {
        return Err(StakeError::InvalidPercolatorProgram.into());
    }

    // Verify pool PDA derivation
    let (expected_pool, bump) = state::derive_pool_pda(program_id, slab.key);
    if *pool_pda.key != expected_pool {
        return Err(StakeError::InvalidPda.into());
    }

    Ok(bump)
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

    // Derive and verify pool PDA
    let (expected_pool, pool_bump) = state::derive_pool_pda(program_id, slab.key);
    if *pool_pda.key != expected_pool {
        return Err(StakeError::InvalidPda.into());
    }

    if !pool_pda.data_is_empty() {
        return Err(StakeError::AlreadyInitialized.into());
    }

    // Derive vault authority
    let (expected_vault_auth, vault_auth_bump) = state::derive_vault_authority(program_id, &expected_pool);
    if *vault_auth.key != expected_vault_auth {
        return Err(StakeError::InvalidPda.into());
    }

    // Validate token program BEFORE any invoke_signed that grants PDA signer authority
    verify_token_program(token_program)?;

    let rent = Rent::from_account_info(rent_sysvar)?;

    // Create pool PDA account
    let pool_seeds: &[&[u8]] = &[b"stake_pool", slab.key.as_ref(), &[pool_bump]];
    invoke_signed(
        &system_instruction::create_account(
            admin.key,
            pool_pda.key,
            rent.minimum_balance(STAKE_POOL_SIZE),
            STAKE_POOL_SIZE as u64,
            program_id,
        ),
        &[admin.clone(), pool_pda.clone(), system_program.clone()],
        &[pool_seeds],
    )?;

    // Create LP mint (authority = vault_auth PDA)
    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];
    invoke_signed(
        &spl_token::instruction::initialize_mint(
            token_program.key,
            lp_mint.key,
            vault_auth.key,
            Some(vault_auth.key),
            6,
        )?,
        &[lp_mint.clone(), rent_sysvar.clone()],
        &[vault_auth_seeds],
    )?;

    // Initialize vault token account (authority = vault_auth PDA)
    invoke_signed(
        &spl_token::instruction::initialize_account(
            token_program.key,
            vault.key,
            collateral_mint.key,
            vault_auth.key,
        )?,
        &[vault.clone(), collateral_mint.clone(), vault_auth.clone(), rent_sysvar.clone()],
        &[vault_auth_seeds],
    )?;

    // Write pool state
    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);

    pool.is_initialized = 1;
    pool.bump = pool_bump;
    pool.vault_authority_bump = vault_auth_bump;
    pool.admin_transferred = 0; // Not yet — must call TransferAdmin
    pool.slab = slab.key.to_bytes();
    pool.admin = admin.key.to_bytes();
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

    msg!("StakePool initialized for slab {} (admin transfer pending)", slab.key);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 1: Deposit
// ═══════════════════════════════════════════════════════════════

fn process_deposit(
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

    // Read and validate pool state
    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if pool.lp_mint != lp_mint.key.to_bytes() {
        return Err(StakeError::InvalidMint.into());
    }
    if pool.vault != vault.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }

    // Check deposit cap against CURRENT pool value, not lifetime deposits.
    // Using total_deposited (monotonically increasing) would permanently lock
    // the pool once lifetime deposits hit the cap, even if 99% was withdrawn.
    // (H6 fix)
    if pool.deposit_cap > 0 {
        let current_value = pool.total_pool_value().unwrap_or(0);
        let new_value = current_value.checked_add(amount)
            .ok_or(StakeError::Overflow)?;
        if new_value > pool.deposit_cap {
            return Err(StakeError::DepositCapExceeded.into());
        }
    }

    // Validate token program BEFORE any invoke_signed that grants PDA signer authority.
    // Without this, attacker passes fake program → receives vault_auth signer → drains vault.
    verify_token_program(token_program)?;

    // Calculate LP tokens to mint
    let lp_to_mint = pool.calc_lp_for_deposit(amount)
        .ok_or(StakeError::Overflow)?;
    if lp_to_mint == 0 {
        return Err(StakeError::ZeroAmount.into());
    }

    // Transfer collateral: user ATA → stake vault
    invoke(
        &spl_token::instruction::transfer(
            token_program.key,
            user_ata.key,
            vault.key,
            user.key,
            &[],
            amount,
        )?,
        &[user_ata.clone(), vault.clone(), user.clone(), token_program.clone()],
    )?;

    // Mint LP tokens to user
    let (_, vault_auth_bump) = state::derive_vault_authority(program_id, pool_pda.key);
    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];

    invoke_signed(
        &spl_token::instruction::mint_to(
            token_program.key,
            lp_mint.key,
            user_lp_ata.key,
            vault_auth.key,
            &[],
            lp_to_mint,
        )?,
        &[lp_mint.clone(), user_lp_ata.clone(), vault_auth.clone(), token_program.clone()],
        &[vault_auth_seeds],
    )?;

    // Update pool totals
    pool.total_deposited = pool.total_deposited.checked_add(amount)
        .ok_or(StakeError::Overflow)?;
    pool.total_lp_supply = pool.total_lp_supply.checked_add(lp_to_mint)
        .ok_or(StakeError::Overflow)?;

    // Create or update per-user deposit PDA (cooldown tracking)
    let clock = Clock::from_account_info(clock_sysvar)?;
    let (expected_deposit_pda, deposit_bump) = state::derive_deposit_pda(program_id, pool_pda.key, user.key);
    if *deposit_pda.key != expected_deposit_pda {
        return Err(StakeError::InvalidPda.into());
    }

    if deposit_pda.data_is_empty() {
        let deposit_seeds: &[&[u8]] = &[
            b"stake_deposit", pool_pda.key.as_ref(), user.key.as_ref(), &[deposit_bump],
        ];
        let rent = Rent::get()?;
        invoke_signed(
            &system_instruction::create_account(
                user.key,
                deposit_pda.key,
                rent.minimum_balance(STAKE_DEPOSIT_SIZE),
                STAKE_DEPOSIT_SIZE as u64,
                program_id,
            ),
            &[user.clone(), deposit_pda.clone(), system_program.clone()],
            &[deposit_seeds],
        )?;
    }

    let mut deposit_data = deposit_pda.try_borrow_mut_data()?;
    let deposit: &mut StakeDeposit = bytemuck::from_bytes_mut(&mut deposit_data[..STAKE_DEPOSIT_SIZE]);

    deposit.is_initialized = 1;
    deposit.bump = deposit_bump;
    deposit.pool = pool_pda.key.to_bytes();
    deposit.user = user.key.to_bytes();
    deposit.last_deposit_slot = clock.slot;
    deposit.lp_amount = deposit.lp_amount.checked_add(lp_to_mint)
        .ok_or(StakeError::Overflow)?;

    msg!("Deposited {} collateral, minted {} LP tokens", amount, lp_to_mint);
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

    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if pool.lp_mint != lp_mint.key.to_bytes() {
        return Err(StakeError::InvalidMint.into());
    }
    if pool.vault != vault.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }

    // Validate token program BEFORE any invoke_signed that grants PDA signer authority.
    verify_token_program(token_program)?;

    // Check cooldown
    let clock = Clock::from_account_info(clock_sysvar)?;
    let deposit_data_ref = deposit_pda.try_borrow_data()?;
    let deposit: &StakeDeposit = bytemuck::from_bytes(&deposit_data_ref[..STAKE_DEPOSIT_SIZE]);

    if deposit.is_initialized != 1
        || deposit.user != user.key.to_bytes()
        || deposit.pool != pool_pda.key.to_bytes()
    {
        return Err(StakeError::Unauthorized.into());
    }
    if clock.slot < deposit.last_deposit_slot.saturating_add(pool.cooldown_slots) {
        return Err(StakeError::CooldownNotElapsed.into());
    }
    if lp_amount > deposit.lp_amount {
        return Err(StakeError::InsufficientLpTokens.into());
    }
    drop(deposit_data_ref);

    // Calculate collateral to return (proportional to LP burned)
    let collateral_amount = pool.calc_collateral_for_withdraw(lp_amount)
        .ok_or(StakeError::Overflow)?;
    if collateral_amount == 0 {
        return Err(StakeError::ZeroAmount.into());
    }

    // Burn LP tokens from user
    invoke(
        &spl_token::instruction::burn(
            token_program.key,
            user_lp_ata.key,
            lp_mint.key,
            user.key,
            &[],
            lp_amount,
        )?,
        &[user_lp_ata.clone(), lp_mint.clone(), user.clone(), token_program.clone()],
    )?;

    // Transfer collateral: vault → user ATA
    let (_, vault_auth_bump) = state::derive_vault_authority(program_id, pool_pda.key);
    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];

    invoke_signed(
        &spl_token::instruction::transfer(
            token_program.key,
            vault.key,
            user_ata.key,
            vault_auth.key,
            &[],
            collateral_amount,
        )?,
        &[vault.clone(), user_ata.clone(), vault_auth.clone(), token_program.clone()],
        &[vault_auth_seeds],
    )?;

    // Update pool totals
    pool.total_withdrawn = pool.total_withdrawn.checked_add(collateral_amount)
        .ok_or(StakeError::Overflow)?;
    pool.total_lp_supply = pool.total_lp_supply.checked_sub(lp_amount)
        .ok_or(StakeError::Overflow)?;

    // Update deposit PDA
    let mut deposit_data_mut = deposit_pda.try_borrow_mut_data()?;
    let deposit_mut: &mut StakeDeposit = bytemuck::from_bytes_mut(&mut deposit_data_mut[..STAKE_DEPOSIT_SIZE]);
    deposit_mut.lp_amount = deposit_mut.lp_amount.checked_sub(lp_amount)
        .ok_or(StakeError::InsufficientLpTokens)?;

    msg!("Withdrew {} collateral, burned {} LP tokens", collateral_amount, lp_amount);
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

    // Read pool
    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }

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

    // Verify vault balance — can't flush more than what's available in vault
    // Available = total_deposited - total_withdrawn - total_flushed
    // Use checked_sub for defense-in-depth (saturating_sub hides accounting bugs)
    let available = pool.total_deposited
        .checked_sub(pool.total_withdrawn)
        .and_then(|v| v.checked_sub(pool.total_flushed))
        .ok_or(StakeError::Overflow)?;
    if amount > available {
        return Err(ProgramError::InsufficientFunds);
    }

    // Derive vault authority for signing
    let (expected_vault_auth, vault_auth_bump) = state::derive_vault_authority(program_id, pool_pda.key);
    if *vault_auth.key != expected_vault_auth {
        return Err(StakeError::InvalidPda.into());
    }

    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];

    // CPI TopUpInsurance: vault_auth PDA signs, stake vault is the "signer_ata"
    // TopUpInsurance checks: verify_token_account(a_user_ata, a_user.key, &mint)
    // Our vault's owner (in SPL token terms) = vault_auth PDA = signer. ✓
    cpi::cpi_top_up_insurance(
        percolator_program,
        vault_auth,          // signer (PDA, we invoke_signed)
        slab,
        vault,               // signer_ata (owned by vault_auth PDA)
        wrapper_vault,       // percolator vault
        token_program,
        amount,
        vault_auth_seeds,
    )?;

    // Update pool tracking
    pool.total_flushed = pool.total_flushed.checked_add(amount)
        .ok_or(StakeError::Overflow)?;

    msg!("Flushed {} collateral to percolator insurance via CPI", amount);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 4: UpdateConfig
// ═══════════════════════════════════════════════════════════════

fn process_update_config(
    _program_id: &Pubkey,
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

    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    if pool.admin != admin.key.to_bytes() {
        return Err(StakeError::Unauthorized.into());
    }

    if let Some(cooldown) = new_cooldown_slots {
        pool.cooldown_slots = cooldown;
    }
    if let Some(cap) = new_deposit_cap {
        pool.deposit_cap = cap;
    }

    msg!("Pool config updated");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 5: TransferAdmin — one-time setup, transfers wrapper admin to pool PDA
// ═══════════════════════════════════════════════════════════════

fn process_transfer_admin(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let current_admin = next_account_info(accounts_iter)?; // Human (current wrapper admin)
    let pool_pda = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;

    if !current_admin.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut pool_data = pool_pda.try_borrow_mut_data()?;
    let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);

    if pool.is_initialized != 1 {
        return Err(StakeError::NotInitialized.into());
    }
    // M7: Verify caller is pool admin (defense-in-depth).
    // The wrapper CPI will also check, but we should reject early if the
    // caller isn't even our admin — prevents non-admin from triggering
    // admin transfer on wrapper if they happen to be the wrapper admin.
    if pool.admin != current_admin.key.to_bytes() {
        return Err(StakeError::Unauthorized.into());
    }
    if pool.admin_transferred == 1 {
        return Err(StakeError::AdminAlreadyTransferred.into());
    }
    if pool.slab != slab.key.to_bytes() {
        return Err(StakeError::InvalidPda.into());
    }
    if pool.percolator_program != percolator_program.key.to_bytes() {
        return Err(StakeError::InvalidPercolatorProgram.into());
    }

    // Verify the pool PDA is correctly derived
    let (expected_pool, _) = state::derive_pool_pda(program_id, slab.key);
    if *pool_pda.key != expected_pool {
        return Err(StakeError::InvalidPda.into());
    }

    // CPI UpdateAdmin: current_admin signs, sets new admin = pool PDA
    // The current_admin must be the signer of the outer transaction
    // and must currently be the wrapper slab's admin.
    cpi::cpi_update_admin(
        percolator_program,
        current_admin,
        slab,
        pool_pda.key, // new admin = pool PDA
    )?;

    pool.admin_transferred = 1;

    msg!(
        "Wrapper admin transferred to pool PDA {} for slab {}",
        pool_pda.key,
        slab.key,
    );
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 6: AdminSetOracleAuthority
// ═══════════════════════════════════════════════════════════════

fn process_admin_set_oracle_authority(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_authority: &Pubkey,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;

    let bump = validate_admin_cpi(program_id, pool_pda, admin, slab, percolator_program)?;
    let admin_seeds: &[&[u8]] = &[b"stake_pool", slab.key.as_ref(), &[bump]];

    cpi::cpi_set_oracle_authority(
        percolator_program,
        pool_pda,
        slab,
        new_authority,
        admin_seeds,
    )?;

    msg!("SetOracleAuthority forwarded via CPI");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 7: AdminSetRiskThreshold
// ═══════════════════════════════════════════════════════════════

fn process_admin_set_risk_threshold(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_threshold: u128,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;

    let bump = validate_admin_cpi(program_id, pool_pda, admin, slab, percolator_program)?;
    let admin_seeds: &[&[u8]] = &[b"stake_pool", slab.key.as_ref(), &[bump]];

    cpi::cpi_set_risk_threshold(
        percolator_program,
        pool_pda,
        slab,
        new_threshold,
        admin_seeds,
    )?;

    msg!("SetRiskThreshold forwarded via CPI");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 8: AdminSetMaintenanceFee
// ═══════════════════════════════════════════════════════════════

fn process_admin_set_maintenance_fee(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_fee: u128,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;

    let bump = validate_admin_cpi(program_id, pool_pda, admin, slab, percolator_program)?;
    let admin_seeds: &[&[u8]] = &[b"stake_pool", slab.key.as_ref(), &[bump]];

    cpi::cpi_set_maintenance_fee(
        percolator_program,
        pool_pda,
        slab,
        new_fee,
        admin_seeds,
    )?;

    msg!("SetMaintenanceFee forwarded via CPI");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 9: AdminResolveMarket
// ═══════════════════════════════════════════════════════════════

fn process_admin_resolve_market(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;

    let bump = validate_admin_cpi(program_id, pool_pda, admin, slab, percolator_program)?;
    let admin_seeds: &[&[u8]] = &[b"stake_pool", slab.key.as_ref(), &[bump]];

    cpi::cpi_resolve_market(
        percolator_program,
        pool_pda,
        slab,
        admin_seeds,
    )?;

    msg!("ResolveMarket forwarded via CPI");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 10: AdminWithdrawInsurance — after resolution, get insurance back to vault
// ═══════════════════════════════════════════════════════════════

fn process_admin_withdraw_insurance(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let vault_auth = next_account_info(accounts_iter)?;    // vault_auth PDA (signer for CPI)
    let stake_vault = next_account_info(accounts_iter)?;   // receives insurance (owned by vault_auth ✓)
    let wrapper_vault = next_account_info(accounts_iter)?; // wrapper insurance vault
    let wrapper_vault_pda = next_account_info(accounts_iter)?; // wrapper's vault authority PDA
    let percolator_program = next_account_info(accounts_iter)?;
    let token_program = next_account_info(accounts_iter)?;
    let clock = next_account_info(accounts_iter)?;

    // Validate admin authority
    let pool_bump = validate_admin_cpi(program_id, pool_pda, admin, slab, percolator_program)?;
    let _ = pool_bump; // pool_pda not signing this CPI

    // Derive vault_auth PDA and its seeds
    // vault_auth = PDA([b"vault_auth", pool_pda])
    let (expected_vault_auth, vault_auth_bump) = Pubkey::find_program_address(
        &[b"vault_auth", pool_pda.key.as_ref()],
        program_id,
    );
    if vault_auth.key != &expected_vault_auth {
        return Err(solana_program::program_error::ProgramError::InvalidArgument);
    }

    let vault_auth_seeds: &[&[u8]] = &[b"vault_auth", pool_pda.key.as_ref(), &[vault_auth_bump]];

    // CPI: WithdrawInsuranceLimited (Tag 23)
    // - vault_auth is the policy authority (set via AdminSetInsurancePolicy Tag 22 beforehand)
    // - stake_vault is owned by vault_auth → passes verify_token_account check
    // - Requires market to be RESOLVED + all positions closed
    // - Requires SetInsuranceWithdrawPolicy called first with vault_auth as authority
    cpi::cpi_withdraw_insurance_limited(
        percolator_program,
        vault_auth,
        slab,
        stake_vault,
        wrapper_vault,
        token_program,
        wrapper_vault_pda,
        clock,
        amount,
        vault_auth_seeds,
    )?;

    // Update pool accounting — returned insurance increases pool value for LP holders
    {
        let mut pool_data = pool_pda.try_borrow_mut_data()?;
        let pool: &mut StakePool = bytemuck::from_bytes_mut(&mut pool_data[..STAKE_POOL_SIZE]);
        pool.total_returned = pool.total_returned.checked_add(amount)
            .ok_or(StakeError::Overflow)?;
    }

    msg!("Insurance {} tokens withdrawn from wrapper to stake_vault via vault_auth CPI", amount);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// 11: AdminSetInsurancePolicy
// ═══════════════════════════════════════════════════════════════

fn process_admin_set_insurance_policy(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    authority: &Pubkey,
    min_withdraw_base: u64,
    max_withdraw_bps: u16,
    cooldown_slots: u64,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    let admin = next_account_info(accounts_iter)?;
    let pool_pda = next_account_info(accounts_iter)?;
    let slab = next_account_info(accounts_iter)?;
    let percolator_program = next_account_info(accounts_iter)?;

    let bump = validate_admin_cpi(program_id, pool_pda, admin, slab, percolator_program)?;
    let admin_seeds: &[&[u8]] = &[b"stake_pool", slab.key.as_ref(), &[bump]];

    cpi::cpi_set_insurance_withdraw_policy(
        percolator_program,
        pool_pda,
        slab,
        authority,
        min_withdraw_base,
        max_withdraw_bps,
        cooldown_slots,
        admin_seeds,
    )?;

    msg!("SetInsuranceWithdrawPolicy forwarded via CPI");
    Ok(())
}
