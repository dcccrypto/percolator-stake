//! Regression test for issue #166 / #163 -- PDA-squatting DoS on stake pool creation and
//! user deposits.
//!
//! -- The bug --
//! Every PDA used by this program (`pool_pda`, `deposit_pda`, etc.) is derived
//! deterministically from public inputs (slab pubkey, user pubkey). Any party can
//! learn these addresses and pre-fund them with lamports via a plain
//! `system_instruction::transfer` (which needs no signature from the destination).
//!
//! Before the fix, `process_init_pool` and `process_deposit` called
//! `system_instruction::create_account` directly. That syscall aborts with
//! `AccountAlreadyInUse` whenever the destination holds any lamports -- so a griefer
//! sending 1 lamport to the deposit PDA would permanently brick that user's ability
//! to deposit into ANY pool.
//!
//! -- The fix (`create_or_adopt_pda`, processor.rs:47) --
//! The fix distinguishes two cases:
//!   * lamports == 0: pristine address -- single atomic `create_account` (fast path).
//!   * lamports > 0, System-owned, zero data: top up to rent-exemption if needed,
//!     then `allocate` (zero-fills data) then `assign` (transfers ownership).
//!     The allocate -> assign ordering is critical because `allocate` requires the
//!     account to still be System-owned.
//!
//! -- What this test exercises --
//! Both tests below set up a pre-funded PDA (the squat state) BEFORE running the
//! instruction that would create it, then assert that the instruction SUCCEEDS and
//! that the PDA is now program-owned with the correct data size. The squat state
//! is proven by the pre-state assertions (lamports > 0, System-owned, data empty)
//! before the instruction runs, which would have been rejected (AccountAlreadyInUse)
//! WITHOUT the fix.
//!
//! Non-hollow guarantee: the pre-state assertions pin the exact squat condition
//! (lamports > 0, System-owned, data.len() == 0) that triggers the `have > 0`
//! branch in `create_or_adopt_pda` (processor.rs:70). If the pre-state assertions
//! are removed the test degenerates to the normal create_account path and exercises
//! nothing of value.
//!
//! Because this exercises `target/deploy/percolator_stake.so`, rebuild the SBF
//! artifact with `cargo build-sbf --no-default-features` after changing source code;
//! otherwise a stale artifact can report stale results.

use bytemuck::Zeroable;
use litesvm::LiteSVM;
use percolator_stake::state::{
    derive_deposit_pda, derive_pool_pda, derive_vault_authority, StakePool, STAKE_DEPOSIT_SIZE,
    STAKE_POOL_SIZE,
};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
    system_program,
    transaction::Transaction,
};
use std::path::PathBuf;
use std::str::FromStr;

// ---- Program IDs ----
const STAKE_ID: &str = "9tbLt8fs1C7cJRXAyiGY7Ub88AT7MLWpxLqFNVCkqzA6";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

// ---- Artifact path ----

fn stake_so() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_stake.so");
    p
}

// ---- SPL Token data helpers (hand-packed, stable layouts) ----

/// 82-byte SPL Mint with an explicit mint_authority.
///
/// Layout (SPL Token mint account):
///   [0..4]   COption discriminant: 1 = Some
///   [4..36]  mint_authority pubkey
///   [36..44] supply u64 = 0
///   [44]     decimals = 6
///   [45]     is_initialized = 1
///   [46..50] freeze_authority COption = None (0)
///   [50..82] freeze_authority pubkey = zeroed
fn mint_data_with_authority(mint_authority: &Pubkey) -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[0..4].copy_from_slice(&1u32.to_le_bytes()); // COption::Some
    d[4..36].copy_from_slice(mint_authority.as_ref());
    // [36..44] supply = 0 (already zero)
    d[44] = 6; // decimals
    d[45] = 1; // is_initialized = true
    // freeze_authority = None (bytes 46..82 already zero)
    d
}

/// 82-byte SPL Mint with no mint authority (fixed supply, for collateral mint).
fn mint_data_no_authority() -> Vec<u8> {
    let mut d = vec![0u8; 82];
    // [0..4] COption discriminant = 0 (None) -- already zero
    // [4..36] pubkey -- zeroed
    // [36..44] supply = 0 -- zeroed
    d[44] = 6; // decimals
    d[45] = 1; // is_initialized = true
    d
}

/// 165-byte SPL token account: initialized, given mint and owner, amount tokens.
///
/// Layout (SPL Token account):
///   [0..32]   mint
///   [32..64]  owner
///   [64..72]  amount
///   [72..108] delegate COption = None
///   [108]     state = 1 (Initialized)
///   [109..121] is_native COption = None
///   [121..129] delegated_amount = 0
///   [129..165] close_authority COption = None
fn token_data(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    // delegate = None (bytes 72..108 already zero)
    d[108] = 1; // state = Initialized
    // is_native = None, delegated_amount = 0, close_authority = None (zero)
    d
}

/// Inject an SPL collateral mint (no mint authority -- fixed supply) at `key`.
fn set_collateral_mint(svm: &mut LiteSVM, key: Pubkey) {
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    svm.set_account(
        key,
        Account {
            lamports: 1_461_600, // rent-exempt for 82 bytes
            data: mint_data_no_authority(),
            owner: token_program,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

/// Inject an SPL LP mint with `mint_authority` at `key`.
/// The LP mint MUST have vault_auth as mint authority so MintTo CPIs succeed.
fn set_lp_mint(svm: &mut LiteSVM, key: Pubkey, mint_authority: &Pubkey) {
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    svm.set_account(
        key,
        Account {
            lamports: 1_461_600, // rent-exempt for 82 bytes
            data: mint_data_with_authority(mint_authority),
            owner: token_program,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

/// Inject a fully-initialized SPL token account at `key`.
fn set_token_account(svm: &mut LiteSVM, key: Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) {
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    svm.set_account(
        key,
        Account {
            lamports: 2_039_280, // rent-exempt for 165 bytes
            data: token_data(mint, owner, amount),
            owner: token_program,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

/// Read an SPL token account's `amount` field (bytes 64..72).
fn token_amount(svm: &LiteSVM, key: &Pubkey) -> u64 {
    let acct = svm.get_account(key).expect("token account exists");
    u64::from_le_bytes(acct.data[64..72].try_into().unwrap())
}

/// Inject a fully-initialized StakePool into the SVM without going through InitPool.
/// Mirrors the `add_stake_pool` helpers in v16/v17 e2e tests.
///
/// Returns (pool_pda, vault_auth).
fn inject_pool(
    svm: &mut LiteSVM,
    stake_id: Pubkey,
    slab: Pubkey,
    admin: &Pubkey,
    collateral_mint: Pubkey,
    lp_mint: Pubkey,
    vault: Pubkey,
) -> (Pubkey, Pubkey) {
    let (pool_pda, pool_bump) = derive_pool_pda(&stake_id, &slab);
    let (vault_auth, vault_auth_bump) = derive_vault_authority(&stake_id, &pool_pda);

    let mut pool = StakePool::zeroed();
    pool.is_initialized = 1;
    pool.bump = pool_bump;
    pool.vault_authority_bump = vault_auth_bump;
    pool.slab = slab.to_bytes();
    pool.admin = admin.to_bytes();
    pool.collateral_mint = collateral_mint.to_bytes();
    pool.lp_mint = lp_mint.to_bytes();
    pool.vault = vault.to_bytes();
    pool.total_deposited = 0;
    pool.total_lp_supply = 0;
    pool.cooldown_slots = 100;
    pool.deposit_cap = 0; // no cap
    pool.pool_mode = 0;
    // set_discriminator writes STAKE_POOL_DISCRIMINATOR + CURRENT_VERSION so
    // validate_discriminator() and validate_pool_version() both pass.
    pool.set_discriminator();

    let mut bytes = vec![0u8; STAKE_POOL_SIZE];
    bytes.copy_from_slice(bytemuck::bytes_of(&pool));
    svm.set_account(
        pool_pda,
        Account {
            lamports: 1_000_000_000,
            data: bytes,
            owner: stake_id,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    (pool_pda, vault_auth)
}

/// Build and send a transaction; on failure the FailedTransactionMetadata
/// (which contains program logs) is returned.
fn send(
    svm: &mut LiteSVM,
    payer: &Keypair,
    signers: &[&Keypair],
    ix: Instruction,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let mut all: Vec<&Keypair> = vec![payer];
    all.extend_from_slice(signers);
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &all,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).map(|_| ())
}

// ==================================================================================
// Test 1 -- deposit_pda squat (Deposit path, processor.rs:894-911)
//
// The deposit_pda is derived from ["stake_deposit", pool_pda, user].  A griefer
// can pre-fund this address before the user ever calls Deposit.  Before #163 this
// permanently bricked the user's first deposit.  After the fix the program adopts
// the pre-funded PDA via `allocate` + `assign` and the deposit succeeds.
// ==================================================================================

/// Build a Deposit (tag 1) instruction.
///
/// Account order (processor.rs:624-635):
///   0. user [signer, writable]
///   1. pool_pda [writable]
///   2. user_ata [writable]     -- source collateral
///   3. vault [writable]        -- destination collateral
///   4. lp_mint [writable]
///   5. user_lp_ata [writable]  -- destination LP tokens
///   6. vault_auth []           -- mint authority PDA
///   7. deposit_pda [writable]  -- per-user record (created by this instruction)
///   8. token_program []
///   9. clock_sysvar []
///  10. system_program []
fn deposit_ix(
    stake_id: Pubkey,
    user: &Pubkey,
    pool_pda: Pubkey,
    user_ata: Pubkey,
    vault: Pubkey,
    lp_mint: Pubkey,
    user_lp_ata: Pubkey,
    vault_auth: Pubkey,
    deposit_pda: Pubkey,
    amount: u64,
) -> Instruction {
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    let mut data = vec![1u8]; // tag = Deposit
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: stake_id,
        accounts: vec![
            AccountMeta::new(*user, true),                       // 0. user [signer, writable]
            AccountMeta::new(pool_pda, false),                   // 1. pool_pda [writable]
            AccountMeta::new(user_ata, false),                   // 2. user_ata [writable]
            AccountMeta::new(vault, false),                      // 3. vault [writable]
            AccountMeta::new(lp_mint, false),                    // 4. lp_mint [writable]
            AccountMeta::new(user_lp_ata, false),                // 5. user_lp_ata [writable]
            AccountMeta::new_readonly(vault_auth, false),        // 6. vault_auth
            AccountMeta::new(deposit_pda, false),                // 7. deposit_pda [writable]
            AccountMeta::new_readonly(token_program, false),     // 8. token_program
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false), // 9. clock
            AccountMeta::new_readonly(system_program::id(), false), // 10. system_program
        ],
        data,
    }
}

#[test]
fn deposit_pda_squat_adoption() {
    let so = stake_so();
    if !so.exists() {
        eprintln!(
            "SKIP deposit_pda_squat_adoption: stake .so missing at {} \
             -- run `cargo build-sbf --no-default-features` first",
            so.display()
        );
        return;
    }

    // ---- LiteSVM setup ----
    let mut svm = LiteSVM::new().with_spl_programs();
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
    svm.add_program_from_file(stake_id, so).unwrap();

    let payer = Keypair::new();
    let user = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    svm.airdrop(&user.pubkey(), 10_000_000_000).unwrap();

    // ---- Account setup ----

    // Collateral mint (fixed supply -- no mint authority needed for collateral).
    let collateral_mint = Pubkey::new_unique();
    set_collateral_mint(&mut svm, collateral_mint);

    // Fake slab pubkey.
    let slab = Pubkey::new_unique();

    // We need vault_auth before creating the LP mint (LP mint authority = vault_auth).
    // Derive the pool PDA first, then vault_auth from pool_pda.
    let (pool_pda_derived, _) = derive_pool_pda(&stake_id, &slab);
    let (vault_auth_derived, _) = derive_vault_authority(&stake_id, &pool_pda_derived);

    // LP mint -- vault_auth PDA is the mint authority (required for MintTo CPI to succeed).
    let lp_mint = Pubkey::new_unique();
    set_lp_mint(&mut svm, lp_mint, &vault_auth_derived);

    // Pool vault: SPL token account, owned by vault_auth, holding collateral.
    let vault = Pubkey::new_unique();

    // Inject the StakePool PDA.
    let (pool_pda, vault_auth) = inject_pool(
        &mut svm,
        stake_id,
        slab,
        &user.pubkey(),
        collateral_mint,
        lp_mint,
        vault,
    );
    // Sanity: derived addresses must match.
    assert_eq!(pool_pda, pool_pda_derived);
    assert_eq!(vault_auth, vault_auth_derived);

    // Vault: empty token account for collateral, authority = vault_auth.
    set_token_account(&mut svm, vault, &collateral_mint, &vault_auth, 0);

    // User's collateral ATA: holds 1_000 tokens (enough to deposit 500).
    let user_ata = Pubkey::new_unique();
    set_token_account(&mut svm, user_ata, &collateral_mint, &user.pubkey(), 1_000);

    // User's LP ATA: empty, owned by user, mint = lp_mint.
    let user_lp_ata = Pubkey::new_unique();
    set_token_account(&mut svm, user_lp_ata, &lp_mint, &user.pubkey(), 0);

    // ---- Deposit PDA squat: inject 1 lamport, System-owned, empty data ----
    let (deposit_pda, _deposit_bump) = derive_deposit_pda(&stake_id, &pool_pda, &user.pubkey());

    // Inject the pre-funded squatted PDA.
    // A real griefer would call `system_instruction::transfer(griefer, deposit_pda, 1)`
    // which requires no signature from `deposit_pda`. We replicate that state directly
    // using svm.set_account (which can inject arbitrary account state in a test harness).
    let squat_lamports: u64 = 1;
    svm.set_account(
        deposit_pda,
        Account {
            lamports: squat_lamports,
            owner: system_program::id(), // System-owned: griefer can only transfer, not allocate/assign
            data: vec![],               // empty data: griefer cannot allocate data
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    // ---- PRE-STATE ASSERTIONS (pin the squat condition) ----
    //
    // These assertions prove the PDA is in the squatted state BEFORE the instruction
    // runs. Without the fix in `create_or_adopt_pda` (processor.rs:47), this exact
    // state would cause `system_instruction::create_account` to abort with
    // AccountAlreadyInUse, permanently bricking the user's deposit.
    //
    // The fix handles this at processor.rs:70:
    //   `let have = target.lamports();`  (the `lamports == 0` fast path is skipped)
    // then proceeds to `allocate` + `assign` instead.
    let pre = svm
        .get_account(&deposit_pda)
        .expect("deposit_pda must exist after set_account");
    assert!(
        pre.lamports > 0,
        "PRE-STATE: deposit_pda must have lamports > 0 (squat condition)"
    );
    assert_eq!(
        pre.owner,
        system_program::id(),
        "PRE-STATE: deposit_pda must be System-owned (griefer cannot assign)"
    );
    assert_eq!(
        pre.data.len(),
        0,
        "PRE-STATE: deposit_pda must have empty data (griefer cannot allocate)"
    );

    // ---- Run Deposit (exercises the squat-adoption branch) ----
    let deposit_amount: u64 = 500;
    let ix = deposit_ix(
        stake_id,
        &user.pubkey(),
        pool_pda,
        user_ata,
        vault,
        lp_mint,
        user_lp_ata,
        vault_auth,
        deposit_pda,
        deposit_amount,
    );

    send(&mut svm, &payer, &[&user], ix).unwrap_or_else(|e| {
        panic!(
            "Deposit MUST succeed even though deposit_pda was pre-funded (squat adoption).\n\
             Error: {:?}\nLogs:\n{}",
            e.err,
            e.meta.logs.join("\n")
        )
    });

    // ---- POST-STATE ASSERTIONS ----

    // deposit_pda is now owned by the stake program (adopt path completed the allocation).
    let post = svm
        .get_account(&deposit_pda)
        .expect("deposit_pda must exist after Deposit");
    assert_eq!(
        post.owner, stake_id,
        "POST-STATE: deposit_pda must be owned by stake program after adoption"
    );
    assert!(
        post.data.len() >= STAKE_DEPOSIT_SIZE,
        "POST-STATE: deposit_pda must have at least STAKE_DEPOSIT_SIZE ({}) bytes, got {}",
        STAKE_DEPOSIT_SIZE,
        post.data.len()
    );

    // The original squat lamports are retained in the PDA (adoption carries them forward).
    assert!(
        post.lamports >= squat_lamports,
        "POST-STATE: deposit_pda lamports must be >= original squat lamports"
    );

    // Collateral transferred: user_ata lost deposit_amount, vault gained it.
    assert_eq!(
        token_amount(&svm, &user_ata),
        1_000 - deposit_amount,
        "POST-STATE: user_ata must have lost the deposited collateral"
    );
    assert_eq!(
        token_amount(&svm, &vault),
        deposit_amount,
        "POST-STATE: vault must have received the deposited collateral"
    );

    // LP tokens minted 1:1 (first depositor into an empty pool gets 1 LP per collateral).
    assert_eq!(
        token_amount(&svm, &user_lp_ata),
        deposit_amount,
        "POST-STATE: user_lp_ata must have received LP tokens (1:1 for first depositor)"
    );
}

// ==================================================================================
// Test 2 -- clean (no-squat) Deposit path (control)
//
// A deposit into a pristine deposit_pda (lamports == 0) takes the `create_account`
// fast path in `create_or_adopt_pda`. This control verifies the fix did not break
// the normal path.
// ==================================================================================

#[test]
fn deposit_pda_clean_path_unaffected() {
    let so = stake_so();
    if !so.exists() {
        eprintln!(
            "SKIP deposit_pda_clean_path_unaffected: stake .so missing at {} \
             -- run `cargo build-sbf --no-default-features` first",
            so.display()
        );
        return;
    }

    let mut svm = LiteSVM::new().with_spl_programs();
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
    svm.add_program_from_file(stake_id, so).unwrap();

    let payer = Keypair::new();
    let user = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
    svm.airdrop(&user.pubkey(), 10_000_000_000).unwrap();

    let collateral_mint = Pubkey::new_unique();
    set_collateral_mint(&mut svm, collateral_mint);

    let slab = Pubkey::new_unique();
    let (pool_pda_derived, _) = derive_pool_pda(&stake_id, &slab);
    let (vault_auth_derived, _) = derive_vault_authority(&stake_id, &pool_pda_derived);

    let lp_mint = Pubkey::new_unique();
    set_lp_mint(&mut svm, lp_mint, &vault_auth_derived);

    let vault = Pubkey::new_unique();
    let (pool_pda, vault_auth) = inject_pool(
        &mut svm,
        stake_id,
        slab,
        &user.pubkey(),
        collateral_mint,
        lp_mint,
        vault,
    );
    assert_eq!(pool_pda, pool_pda_derived);
    assert_eq!(vault_auth, vault_auth_derived);

    set_token_account(&mut svm, vault, &collateral_mint, &vault_auth, 0);

    let user_ata = Pubkey::new_unique();
    set_token_account(&mut svm, user_ata, &collateral_mint, &user.pubkey(), 1_000);

    let user_lp_ata = Pubkey::new_unique();
    set_token_account(&mut svm, user_lp_ata, &lp_mint, &user.pubkey(), 0);

    let (deposit_pda, _) = derive_deposit_pda(&stake_id, &pool_pda, &user.pubkey());

    // Control: do NOT pre-fund deposit_pda. The account must not exist.
    assert!(
        svm.get_account(&deposit_pda).is_none(),
        "CONTROL: deposit_pda must not exist before Deposit (clean path)"
    );

    send(
        &mut svm,
        &payer,
        &[&user],
        deposit_ix(
            stake_id,
            &user.pubkey(),
            pool_pda,
            user_ata,
            vault,
            lp_mint,
            user_lp_ata,
            vault_auth,
            deposit_pda,
            500,
        ),
    )
    .unwrap_or_else(|e| {
        panic!(
            "Deposit MUST succeed on clean (unfunded) deposit_pda.\n\
             Error: {:?}\nLogs:\n{}",
            e.err,
            e.meta.logs.join("\n")
        )
    });

    let post = svm
        .get_account(&deposit_pda)
        .expect("deposit_pda created by Deposit");
    assert_eq!(
        post.owner, stake_id,
        "POST-STATE (clean): deposit_pda must be owned by stake program"
    );
    assert!(
        post.data.len() >= STAKE_DEPOSIT_SIZE,
        "POST-STATE (clean): deposit_pda must have at least STAKE_DEPOSIT_SIZE ({}) bytes",
        STAKE_DEPOSIT_SIZE
    );
    assert_eq!(
        token_amount(&svm, &user_lp_ata),
        500,
        "POST-STATE (clean): LP tokens minted 1:1 for first depositor"
    );
}
