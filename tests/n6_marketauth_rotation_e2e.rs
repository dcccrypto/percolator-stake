//! Issue #6 lineage reconciliation — InitPool marketauth-rotation CPI e2e.
//!
//! Ports the deployed `percolator-vault@eb3ebe8` behavior into this program: InitPool
//! (tag 0) now issues a wrapper `UpdateAuthority` (tag 32) CPI that irreversibly
//! rotates the market's `cfg.marketauth` from the human admin wallet to this pool's
//! PDA, atomically with pool creation. See `src/cpi.rs::cpi_update_authority` and
//! `src/processor.rs::process_init_pool`.
//!
//! Loads the REAL stake .so + the REAL v17 wrapper .so into one LiteSVM instance
//! (mirroring `v17_stake_insurance_e2e.rs`) and exercises InitPool through the
//! actual instruction dispatcher — every other test in this crate that needs a
//! StakePool account injects it directly via `svm.set_account` (see
//! `add_stake_pool` in v17_stake_insurance_e2e.rs / `inject_pool` in
//! regression_166_pda_squat.rs) and therefore never calls `process_init_pool` at
//! all. This file closes that gap for the newly-ported CPI specifically.
//!
//! Covers:
//! 1. `initpool_rotates_marketauth_to_pool_pda` — GREEN: marketauth flips from
//!    admin to the pool PDA, and the OLD admin key can no longer call a
//!    marketauth-gated wrapper instruction directly afterward (proves the handoff
//!    is real, not just a log message).
//! 2. `initpool_reverts_atomically_if_caller_is_not_marketauth` — RED control:
//!    a non-admin caller's InitPool fails closed, and — critically — the pool PDA
//!    account created earlier in the SAME instruction is rolled back too (Solana
//!    single-instruction atomicity), proving there is no partial-state exposure.
//! 3. `initpool_requires_writable_slab` — the explicit fail-fast guard added
//!    alongside the CPI (a non-writable slab would otherwise fail deep inside the
//!    wrapper's `expect_writable` with a confusing error).

use litesvm::LiteSVM;
use percolator_stake::state::{derive_pool_pda, derive_vault_authority};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
    transaction::{Transaction, TransactionError},
};
use std::path::PathBuf;
use std::str::FromStr;

const WRAPPER_MAINNET: &str = "ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv";
const STAKE_ID: &str = "9tbLt8fs1C7cJRXAyiGY7Ub88AT7MLWpxLqFNVCkqzA6";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const MARKET_LEN_V17_CAP1: usize = 3067; // dump_sizes MARKET_ACCOUNT_LEN as of percolator-prog HEAD (1d4594a5)
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;

fn stake_so() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_stake.so");
    p
}

fn wrapper_so() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("percolator-prog/target/deploy/percolator_prog.so");
    p
}

fn mint_data() -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[44] = 0; // decimals
    d[45] = 1; // is_initialized
    d
}

fn encode_init_market_v17() -> Vec<u8> {
    let mut out = Vec::with_capacity(219);
    out.push(0u8); // tag InitMarket
    out.extend_from_slice(&1u16.to_le_bytes()); // max_portfolio_assets
    out.extend_from_slice(&0u64.to_le_bytes()); // h_min
    out.extend_from_slice(&10u64.to_le_bytes()); // h_max
    out.extend_from_slice(&100u64.to_le_bytes()); // initial_price
    out.extend_from_slice(&1u128.to_le_bytes()); // min_nonzero_mm_req
    out.extend_from_slice(&2u128.to_le_bytes()); // min_nonzero_im_req
    out.extend_from_slice(&10_000u64.to_le_bytes()); // maintenance_margin_bps
    out.extend_from_slice(&10_000u64.to_le_bytes()); // initial_margin_bps
    out.extend_from_slice(&10_000u64.to_le_bytes()); // max_trading_fee_bps
    out.extend_from_slice(&0u64.to_le_bytes()); // trade_fee_base_bps
    out.extend_from_slice(&0u64.to_le_bytes()); // liquidation_fee_bps
    out.extend_from_slice(&0u128.to_le_bytes()); // liquidation_fee_cap
    out.extend_from_slice(&0u128.to_le_bytes()); // min_liquidation_abs
    out.extend_from_slice(&10_000u64.to_le_bytes()); // max_price_move_bps_per_slot
    out.extend_from_slice(&1u64.to_le_bytes()); // max_accrual_dt_slots
    out.extend_from_slice(&0u64.to_le_bytes()); // max_abs_funding_e9_per_slot
    out.extend_from_slice(&1u64.to_le_bytes()); // min_funding_lifetime_slots
    out.extend_from_slice(&1u64.to_le_bytes()); // max_account_b_settlement_chunks
    out.extend_from_slice(&1u64.to_le_bytes()); // max_bankrupt_close_chunks
    out.extend_from_slice(&100u64.to_le_bytes()); // max_bankrupt_close_lifetime_slots
    out.extend_from_slice(&MAX_VAULT_TVL.to_le_bytes()); // public_b_chunk_atoms
    out.extend_from_slice(&0u128.to_le_bytes()); // maintenance_fee_per_slot
    debug_assert_eq!(out.len(), 219, "InitMarket wire must be 219 bytes");
    out
}

fn send(
    svm: &mut LiteSVM,
    payer: &Keypair,
    signers: &[&Keypair],
    ix: Instruction,
) -> Result<(), TransactionError> {
    let mut all: Vec<&Keypair> = vec![payer];
    all.extend_from_slice(signers);
    let cb_heap =
        solana_sdk::compute_budget::ComputeBudgetInstruction::request_heap_frame(128 * 1024);
    let cb_cu =
        solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let tx = Transaction::new_signed_with_payer(
        &[cb_heap, cb_cu, ix],
        Some(&payer.pubkey()),
        &all,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err)
}

/// Build a Live v17 market (allocate + InitMarket). Returns (market, mint).
/// `admin` becomes the market's `cfg.marketauth` (InitMarket bootstraps
/// marketauth to the init signer — v16_program.rs InitMarket handler).
fn build_live_market_v17(
    svm: &mut LiteSVM,
    wrapper_id: Pubkey,
    token_program: Pubkey,
    admin: &Keypair,
    payer: &Keypair,
) -> (Pubkey, Pubkey) {
    let market = Pubkey::new_unique();
    let mint = Pubkey::new_unique();

    svm.set_account(
        mint,
        Account {
            lamports: 1_000_000_000,
            data: mint_data(),
            owner: token_program,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    svm.set_account(
        market,
        Account {
            lamports: 1_000_000_000,
            data: vec![0u8; MARKET_LEN_V17_CAP1],
            owner: wrapper_id,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    let init_ix = Instruction {
        program_id: wrapper_id,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
            AccountMeta::new_readonly(mint, false),
        ],
        data: encode_init_market_v17(),
    };
    send(svm, payer, &[admin], init_ix).expect("InitMarket v17");
    (market, mint)
}

/// Pre-allocate an EMPTY (uninitialized, zeroed) SPL account of the given size,
/// owned by the token program — mirrors what a client's prior `CreateAccount`
/// instruction would produce before InitPool's `initialize_mint`/`initialize_account`
/// CPIs run. InitPool does NOT create these accounts itself (only `pool_pda` gets
/// `create_or_adopt_pda`), so the caller must pre-allocate them.
fn preallocate_empty_spl_account(svm: &mut LiteSVM, key: Pubkey, token_program: Pubkey, size: usize) {
    svm.set_account(
        key,
        Account {
            lamports: 1_000_000_000,
            data: vec![0u8; size],
            owner: token_program,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn encode_init_pool(cooldown_slots: u64, deposit_cap: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(17);
    out.push(0u8); // tag InitPool
    out.extend_from_slice(&cooldown_slots.to_le_bytes());
    out.extend_from_slice(&deposit_cap.to_le_bytes());
    out
}

struct InitPoolAccounts {
    admin: Pubkey,
    slab: Pubkey,
    pool_pda: Pubkey,
    lp_mint: Pubkey,
    vault: Pubkey,
    vault_auth: Pubkey,
    collateral_mint: Pubkey,
    percolator_program: Pubkey,
    token_program: Pubkey,
}

fn init_pool_ix(stake_id: Pubkey, a: &InitPoolAccounts, cooldown_slots: u64, deposit_cap: u64) -> Instruction {
    Instruction {
        program_id: stake_id,
        accounts: vec![
            AccountMeta::new(a.admin, true),
            AccountMeta::new(a.slab, false), // MUST be writable: the marketauth CPI needs it
            AccountMeta::new(a.pool_pda, false),
            AccountMeta::new(a.lp_mint, false),
            AccountMeta::new(a.vault, false),
            AccountMeta::new_readonly(a.vault_auth, false),
            AccountMeta::new_readonly(a.collateral_mint, false),
            AccountMeta::new_readonly(a.percolator_program, false),
            AccountMeta::new_readonly(a.token_program, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
        ],
        data: encode_init_pool(cooldown_slots, deposit_cap),
    }
}

fn find_pubkey_offset(data: &[u8], needle: &[u8; 32]) -> Option<usize> {
    data.windows(32).position(|w| w == needle)
}

fn read_32_at(svm: &LiteSVM, market: &Pubkey, off: usize) -> [u8; 32] {
    let d = svm.get_account(market).unwrap().data;
    d[off..off + 32].try_into().unwrap()
}

/// Common setup: live market (marketauth=admin) + pre-allocated (but not yet
/// InitPool'd) lp_mint/vault/pool_pda accounts, ready for an InitPool call.
fn setup(svm: &mut LiteSVM, wrapper_id: Pubkey, stake_id: Pubkey, token_program: Pubkey, admin: &Keypair, payer: &Keypair) -> (Pubkey, InitPoolAccounts) {
    let (market, mint) = build_live_market_v17(svm, wrapper_id, token_program, admin, payer);

    let (pool_pda, _) = derive_pool_pda(&stake_id, &market);
    let (vault_auth, _) = derive_vault_authority(&stake_id, &pool_pda);
    let lp_mint = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    preallocate_empty_spl_account(svm, lp_mint, token_program, 82);
    preallocate_empty_spl_account(svm, vault, token_program, 165);

    let accts = InitPoolAccounts {
        admin: admin.pubkey(),
        slab: market,
        pool_pda,
        lp_mint,
        vault,
        vault_auth,
        collateral_mint: mint,
        percolator_program: wrapper_id,
        token_program,
    };
    (market, accts)
}

/// GREEN: InitPool succeeds, and cfg.marketauth flips from admin to pool_pda.
/// Also proves the handoff is REAL (not cosmetic) by attempting a marketauth-gated
/// wrapper call (UpdateAuthority itself, tag 32) signed by the OLD admin key
/// afterward and asserting it now fails — only the pool PDA (which cannot sign a
/// top-level tx) holds marketauth from this point on.
#[test]
fn initpool_rotates_marketauth_to_pool_pda() {
    let so = stake_so();
    let wso = wrapper_so();
    if !so.exists() || !wso.exists() {
        eprintln!(
            "SKIP initpool_rotates_marketauth_to_pool_pda: .so missing (stake={} wrapper={}) \
             -- run `cargo build-sbf --no-default-features` in percolator-stake and \
             percolator-prog first",
            so.display(),
            wso.display()
        );
        return;
    }

    let mut svm = LiteSVM::new().with_spl_programs();
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
    let wrapper_id = Pubkey::from_str(WRAPPER_MAINNET).unwrap();
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    svm.add_program_from_file(stake_id, so).unwrap();
    svm.add_program_from_file(wrapper_id, wso).unwrap();

    let admin = Keypair::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.airdrop(&admin.pubkey(), 20_000_000_000).unwrap();

    let (market, accts) = setup(&mut svm, wrapper_id, stake_id, token_program, &admin, &payer);

    // PRE-STATE: locate cfg.marketauth by searching for admin's pubkey in the raw
    // market bytes (InitMarket bootstraps marketauth to the init signer).
    let admin_bytes = admin.pubkey().to_bytes();
    let market_data_pre = svm.get_account(&market).unwrap().data;
    let marketauth_off = find_pubkey_offset(&market_data_pre, &admin_bytes)
        .expect("admin pubkey (== marketauth after InitMarket) must appear in market data");
    assert_eq!(
        read_32_at(&svm, &market, marketauth_off),
        admin_bytes,
        "PRE-STATE: marketauth == admin before InitPool"
    );

    // Run the real InitPool instruction.
    send(&mut svm, &payer, &[&admin], init_pool_ix(stake_id, &accts, 5, 0)).unwrap_or_else(|e| {
        panic!("InitPool must succeed when admin == current marketauth.\nError: {e:?}")
    });

    // POST-STATE: marketauth now equals the pool PDA, not admin.
    let pool_pda_bytes = accts.pool_pda.to_bytes();
    assert_eq!(
        read_32_at(&svm, &market, marketauth_off),
        pool_pda_bytes,
        "POST-STATE: marketauth must be rotated to the pool PDA after InitPool"
    );
    assert_ne!(
        read_32_at(&svm, &market, marketauth_off),
        admin_bytes,
        "POST-STATE: marketauth must no longer be the admin wallet"
    );

    // Pool PDA account was actually created and initialized.
    let pool_acct = svm.get_account(&accts.pool_pda).unwrap();
    assert_eq!(pool_acct.owner, stake_id, "pool_pda must be owned by the stake program");

    // BEHAVIORAL proof the handoff is real: the OLD admin key can no longer call
    // wrapper UpdateAuthority (tag 32) directly — it would need to co-sign as
    // BOTH current (marketauth) and new authority, but marketauth is now the pool
    // PDA, which cannot sign a plain top-level transaction. A second attempt by
    // admin should fail (Unauthorized / signature mismatch), not succeed.
    let re_rotate_attempt = Instruction {
        program_id: wrapper_id,
        accounts: vec![
            AccountMeta::new_readonly(admin.pubkey(), true), // claims to be "current" — WRONG now
            AccountMeta::new_readonly(admin.pubkey(), true), // "new" == admin (irrelevant, fails earlier)
            AccountMeta::new(market, false),
        ],
        data: {
            let mut d = vec![32u8];
            d.extend_from_slice(&admin.pubkey().to_bytes());
            d
        },
    };
    svm.expire_blockhash();
    let err = send(&mut svm, &payer, &[&admin], re_rotate_attempt)
        .expect_err("admin must NOT be able to re-rotate marketauth after InitPool moved it to the pool PDA");
    match err {
        TransactionError::InstructionError(_, InstructionError::Custom(_)) => {
            // expect_live_authority(&cfg.marketauth, admin.key) fails: Unauthorized.
        }
        other => panic!("expected a Custom program error rejecting the stale admin, got {other:?}"),
    }
}

/// RED control: a non-admin caller (not the current marketauth) cannot InitPool —
/// the wrapper CPI fails closed and the WHOLE instruction reverts atomically,
/// including the pool PDA creation earlier in the same instruction (Solana
/// single-instruction atomicity — no partial state is left behind).
#[test]
fn initpool_reverts_atomically_if_caller_is_not_marketauth() {
    let so = stake_so();
    let wso = wrapper_so();
    if !so.exists() || !wso.exists() {
        eprintln!("SKIP initpool_reverts_atomically_if_caller_is_not_marketauth: .so missing");
        return;
    }

    let mut svm = LiteSVM::new().with_spl_programs();
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
    let wrapper_id = Pubkey::from_str(WRAPPER_MAINNET).unwrap();
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    svm.add_program_from_file(stake_id, so).unwrap();
    svm.add_program_from_file(wrapper_id, wso).unwrap();

    let admin = Keypair::new();
    let attacker = Keypair::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.airdrop(&admin.pubkey(), 20_000_000_000).unwrap();
    svm.airdrop(&attacker.pubkey(), 20_000_000_000).unwrap();

    // Market's marketauth is `admin`; attacker (not admin) attempts InitPool,
    // signing as the (wrong) admin account of a pool derived from the SAME slab.
    let (market, mut accts) = setup(&mut svm, wrapper_id, stake_id, token_program, &admin, &payer);
    // Attacker pays and signs as "admin" of the pool — but is not the wrapper's
    // current marketauth, so the CPI must reject them.
    accts.admin = attacker.pubkey();

    let pool_pda_before = svm.get_account(&accts.pool_pda);
    assert!(pool_pda_before.is_none(), "PRE-STATE: pool_pda must not exist yet");

    let err = send(
        &mut svm,
        &payer,
        &[&attacker],
        init_pool_ix(stake_id, &accts, 5, 0),
    )
    .expect_err("InitPool by a non-marketauth caller must fail closed");
    match err {
        TransactionError::InstructionError(_, InstructionError::Custom(_)) => {}
        other => panic!("expected a Custom program error from the wrapper CPI rejecting the attacker, got {other:?}"),
    }

    // ATOMICITY: pool_pda must NOT exist afterward — the earlier create_or_adopt_pda
    // in the SAME instruction rolled back with the rest of the failed instruction.
    let pool_pda_after = svm.get_account(&accts.pool_pda);
    assert!(
        pool_pda_after.is_none(),
        "POST-STATE: pool_pda creation must roll back atomically when the marketauth CPI fails"
    );

    // Market's marketauth is untouched (still admin, not attacker, not any PDA).
    let admin_bytes = admin.pubkey().to_bytes();
    let market_data = svm.get_account(&market).unwrap().data;
    let off = find_pubkey_offset(&market_data, &admin_bytes)
        .expect("admin pubkey must still be present as marketauth — nothing rotated");
    assert_eq!(read_32_at(&svm, &market, off), admin_bytes);
}

/// The explicit `slab.is_writable` fail-fast guard: an InitPool call where the
/// slab account meta is marked read-only must be rejected BEFORE crossing the CPI
/// boundary, with a clear error — not a confusing failure deep inside the
/// wrapper's `expect_writable(market_ai)`.
#[test]
fn initpool_requires_writable_slab() {
    let so = stake_so();
    let wso = wrapper_so();
    if !so.exists() || !wso.exists() {
        eprintln!("SKIP initpool_requires_writable_slab: .so missing");
        return;
    }

    let mut svm = LiteSVM::new().with_spl_programs();
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
    let wrapper_id = Pubkey::from_str(WRAPPER_MAINNET).unwrap();
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    svm.add_program_from_file(stake_id, so).unwrap();
    svm.add_program_from_file(wrapper_id, wso).unwrap();

    let admin = Keypair::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.airdrop(&admin.pubkey(), 20_000_000_000).unwrap();

    let (_market, accts) = setup(&mut svm, wrapper_id, stake_id, token_program, &admin, &payer);

    // Build the InitPool ix by hand with slab marked READ-ONLY (index 1).
    let mut ix = init_pool_ix(stake_id, &accts, 5, 0);
    ix.accounts[1] = AccountMeta::new_readonly(accts.slab, false);

    let err = send(&mut svm, &payer, &[&admin], ix)
        .expect_err("InitPool with a non-writable slab must be rejected");
    match err {
        TransactionError::InstructionError(_, InstructionError::InvalidArgument) => {}
        other => panic!("expected InvalidArgument from the slab.is_writable guard, got {other:?}"),
    }
}
