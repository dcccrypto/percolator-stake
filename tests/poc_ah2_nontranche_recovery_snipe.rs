//! A-H2 — non-tranche recovery snipe: PoC and regression.
//!
//! While collateral sits flushed, `total_pool_value()` is marked down, so the global
//! `Deposit` path mints LP cheap. `RecoverFlushedInsurance` (tag 23) is permissionless,
//! so any caller can then restore that value and capture the step-up pro-rata from the
//! incumbents who bore the markdown.
//!
//! The gates that cover the tranche paths (#149, #159) were written on 2026-06-18 and
//! were sound as written; `c3edb7f` (#171) made `total_returned` unprivileged six days
//! later, and the global path was never re-derived against that.
//!
//! Three tests fail on the parent commit and pass here; three are controls that pass on
//! both. `ah2_gate_tracks_wrapper_recoverable_not_flushed_minus_returned` is the one to
//! preserve if this file is ever trimmed — it pins the quantity, and a gate written
//! against `total_flushed - total_returned` reopens the hole because `ReturnInsurance`
//! credits that counter from the admin's own wallet without moving wrapper tokens.
//!
//! Drives the real `percolator_stake.so` against the real `percolator_prog.so` through
//! LiteSVM dispatch; no pool state is hand-set. Conventions follow
//! `mode0_pre_accrue_dilution_e2e.rs` and `v17_stake_insurance_e2e.rs`.
//!
//! AUD-T2-3 (2026-10-18): the five PoC / regression tests built on a real FlushToInsurance / RecoverFlushedInsurance were
//! permanently `#[ignore]`d (v5 answers tags 3 and 23 with DeprecatedV5 = 34) and have been
//! deleted. First-loss behaviour is covered by tests/v5_first_loss.rs and the wrapper
//! p4_wave_d cross-program tests.

use litesvm::LiteSVM;
use percolator_stake::state::{
    derive_deposit_pda, derive_pool_pda, derive_vault_authority, StakePool, STAKE_POOL_SIZE,
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

const WRAPPER_MAINNET: &str = "ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv";
const STAKE_ID: &str = "9tbLt8fs1C7cJRXAyiGY7Ub88AT7MLWpxLqFNVCkqzA6";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const MARKET_LEN_V17_CAP1: usize = 4059; // v2.2 variant -rem cap-1 market (592 + 806 + 2661 [#287 +32]: slot = 2325 + 112 band/rent + 160 funding drift tail + 32 R1 words); was 3147 (v17), 3675 (v2.1)
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;

const GENESIS: u64 = 1_000_000;
const ATTACK: u64 = 100_000;

// ── artifacts ────────────────────────────────────────────────────────────────

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

// ── token helpers ────────────────────────────────────────────────────────────

fn mint_data() -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[44] = 0; // decimals
    d[45] = 1; // is_initialized
    d
}

fn token_data(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1; // state = Initialized
    d
}

fn set_token_account(svm: &mut LiteSVM, key: Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) {
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    svm.set_account(
        key,
        Account {
            lamports: 2_039_280,
            data: token_data(mint, owner, amount),
            owner: token_program,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn token_amount(svm: &LiteSVM, key: &Pubkey) -> u64 {
    let acct = svm.get_account(key).expect("token account exists");
    u64::from_le_bytes(acct.data[64..72].try_into().unwrap())
}

fn preallocate_empty_spl_account(
    svm: &mut LiteSVM,
    key: Pubkey,
    token_program: Pubkey,
    size: usize,
) {
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

/// Canonical wrapper vault ATA — v17's `verify_vault_token_account` requires it.
fn canonical_vault_ata(vault_authority: &Pubkey, mint: &Pubkey) -> Pubkey {
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    let ata_program = Pubkey::from_str(ATA_PROGRAM).unwrap();
    Pubkey::find_program_address(
        &[
            vault_authority.as_ref(),
            token_program.as_ref(),
            mint.as_ref(),
        ],
        &ata_program,
    )
    .0
}

// ── transaction plumbing ─────────────────────────────────────────────────────

fn send_batch(
    svm: &mut LiteSVM,
    payer: &Keypair,
    signers: &[&Keypair],
    ixs: Vec<Instruction>,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let mut all: Vec<&Keypair> = vec![payer];
    all.extend_from_slice(signers);
    let cb_heap =
        solana_sdk::compute_budget::ComputeBudgetInstruction::request_heap_frame(128 * 1024);
    let cb_cu =
        solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let mut all_ixs = vec![cb_heap, cb_cu];
    all_ixs.extend(ixs);
    let tx = Transaction::new_signed_with_payer(
        &all_ixs,
        Some(&payer.pubkey()),
        &all,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).map(|_| ())
}

fn send(
    svm: &mut LiteSVM,
    payer: &Keypair,
    signers: &[&Keypair],
    ix: Instruction,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    send_batch(svm, payer, signers, vec![ix])
}

// ── wrapper market ───────────────────────────────────────────────────────────

fn encode_init_market_v17() -> Vec<u8> {
    let mut out = Vec::with_capacity(219);
    out.push(0u8); // tag InitMarket
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&10u64.to_le_bytes());
    out.extend_from_slice(&100u64.to_le_bytes());
    out.extend_from_slice(&1u128.to_le_bytes());
    out.extend_from_slice(&2u128.to_le_bytes());
    out.extend_from_slice(&10_000u64.to_le_bytes());
    out.extend_from_slice(&10_000u64.to_le_bytes());
    out.extend_from_slice(&10_000u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u128.to_le_bytes());
    out.extend_from_slice(&0u128.to_le_bytes());
    out.extend_from_slice(&10_000u64.to_le_bytes());
    out.extend_from_slice(&1u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&1u64.to_le_bytes());
    out.extend_from_slice(&1u64.to_le_bytes());
    out.extend_from_slice(&1u64.to_le_bytes());
    out.extend_from_slice(&100u64.to_le_bytes());
    out.extend_from_slice(&MAX_VAULT_TVL.to_le_bytes());
    out.extend_from_slice(&0u128.to_le_bytes());
    debug_assert_eq!(out.len(), 219, "InitMarket wire must be 219 bytes");
    out
}

fn build_live_market_v17(
    svm: &mut LiteSVM,
    wrapper_id: Pubkey,
    token_program: Pubkey,
    admin: &Keypair,
    payer: &Keypair,
) -> (Pubkey, Pubkey, Pubkey, Pubkey) {
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

    let wrapper_vault_auth =
        Pubkey::find_program_address(&[b"vault", market.as_ref()], &wrapper_id).0;
    let wrapper_vault = canonical_vault_ata(&wrapper_vault_auth, &mint);
    set_token_account(svm, wrapper_vault, &mint, &wrapper_vault_auth, 0);

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
    (market, mint, wrapper_vault, wrapper_vault_auth)
}

// ── stake instruction encoders ───────────────────────────────────────────────

struct Ctx {
    stake_id: Pubkey,
    wrapper_id: Pubkey,
    token_program: Pubkey,
    market: Pubkey,
    mint: Pubkey,
    pool_pda: Pubkey,
    vault_auth: Pubkey,
    vault: Pubkey,
    lp_mint: Pubkey,
}

fn init_pool_ix(c: &Ctx, admin: &Pubkey, cooldown_slots: u64, deposit_cap: u64) -> Instruction {
    let mut data = vec![0u8];
    data.extend_from_slice(&cooldown_slots.to_le_bytes());
    data.extend_from_slice(&deposit_cap.to_le_bytes());
    // v5: the 16-byte InitPool creates a FIRST_LOSS pool (consent-gated deposits, no tranches). This
    // PoC suite tests the pre-v5 fee-only pool, which is v5 risk mode FEE_ONLY (no deployment).
    data.push(2u8); // risk_mode FEE_ONLY
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&3_000u16.to_le_bytes());
    data.extend_from_slice(&500u16.to_le_bytes());
    Instruction {
        program_id: c.stake_id,
        accounts: vec![
            AccountMeta::new(*admin, true),
            AccountMeta::new(c.market, false), // writable: marketauth rotation CPI
            AccountMeta::new(c.pool_pda, false),
            AccountMeta::new(c.lp_mint, false),
            AccountMeta::new(c.vault, false),
            AccountMeta::new_readonly(c.vault_auth, false),
            AccountMeta::new_readonly(c.mint, false),
            AccountMeta::new_readonly(c.wrapper_id, false),
            AccountMeta::new_readonly(c.token_program, false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
        ],
        data,
    }
}

fn deposit_ix(
    c: &Ctx,
    user: &Pubkey,
    user_ata: Pubkey,
    user_lp_ata: Pubkey,
    amount: u64,
) -> Instruction {
    let (deposit_pda, _) = derive_deposit_pda(&c.stake_id, &c.pool_pda, user);
    let mut data = vec![1u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: c.stake_id,
        accounts: vec![
            AccountMeta::new(*user, true),
            AccountMeta::new(c.pool_pda, false),
            AccountMeta::new(user_ata, false),
            AccountMeta::new(c.vault, false),
            AccountMeta::new(c.lp_mint, false),
            AccountMeta::new(user_lp_ata, false),
            AccountMeta::new_readonly(c.vault_auth, false),
            AccountMeta::new(deposit_pda, false),
            AccountMeta::new_readonly(c.token_program, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(c.market, false), // #290: wrapper market
        ],
        data,
    }
}

fn bind_ix(c: &Ctx, admin: &Pubkey) -> Instruction {
    Instruction {
        program_id: c.stake_id,
        accounts: vec![
            AccountMeta::new(*admin, true),
            AccountMeta::new(c.pool_pda, false), // writable: a FEE_ONLY bind records the creator seed
            AccountMeta::new_readonly(c.vault_auth, false),
            AccountMeta::new(c.market, false),
            AccountMeta::new_readonly(c.wrapper_id, false),
        ],
        data: vec![19u8],
    }
}

fn read_pool(svm: &LiteSVM, pool_pda: &Pubkey) -> StakePool {
    let data = svm.get_account(pool_pda).unwrap().data;
    *bytemuck::from_bytes::<StakePool>(&data[..STAKE_POOL_SIZE])
}

// ── world ────────────────────────────────────────────────────────────────────

struct World {
    svm: LiteSVM,
    c: Ctx,
    payer: Keypair,
}

/// Real InitMarket -> real InitPool (mode 0, NON-TRANCHE) -> real bind.
/// Nothing about the pool is forged; `InitPool` writes it.
fn world(cooldown_slots: u64, deposit_cap: u64) -> World {
    let mut svm = LiteSVM::new().with_spl_programs();
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
    let wrapper_id = Pubkey::from_str(WRAPPER_MAINNET).unwrap();
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    svm.add_program_from_file(stake_id, stake_so())
        .expect("stake .so — run `cargo build-sbf --no-default-features` first");
    svm.add_program_from_file(wrapper_id, wrapper_so())
        .expect("wrapper .so — build ../percolator-prog first");

    let admin = Keypair::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&admin.pubkey(), 10_000_000_000).unwrap();

    let (market, mint, _wrapper_vault, _wrapper_vault_auth) =
        build_live_market_v17(&mut svm, wrapper_id, token_program, &admin, &payer);

    let (pool_pda, _) = derive_pool_pda(&stake_id, &market);
    let (vault_auth, _) = derive_vault_authority(&stake_id, &pool_pda);
    let lp_mint = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    preallocate_empty_spl_account(&mut svm, lp_mint, token_program, 82);
    preallocate_empty_spl_account(&mut svm, vault, token_program, 165);

    let c = Ctx {
        stake_id,
        wrapper_id,
        token_program,
        market,
        mint,
        pool_pda,
        vault_auth,
        vault,
        lp_mint,
    };

    send(
        &mut svm,
        &payer,
        &[&admin],
        init_pool_ix(&c, &admin.pubkey(), cooldown_slots, deposit_cap),
    )
    .expect("InitPool");
    send(&mut svm, &payer, &[&admin], bind_ix(&c, &admin.pubkey()))
        .expect("BindInsuranceAuthority");

    World {
        svm,
        c,
        payer,
    }
}

/// Fund a fresh user with `amount` collateral and an empty LP ATA.
fn new_user(w: &mut World, amount: u64) -> (Keypair, Pubkey, Pubkey) {
    let user = Keypair::new();
    w.svm.airdrop(&user.pubkey(), 10_000_000_000).unwrap();
    let ata = Pubkey::new_unique();
    let lp_ata = Pubkey::new_unique();
    set_token_account(&mut w.svm, ata, &w.c.mint, &user.pubkey(), amount);
    set_token_account(&mut w.svm, lp_ata, &w.c.lp_mint, &user.pubkey(), 0);
    (user, ata, lp_ata)
}

fn deposit(w: &mut World, u: &Keypair, ata: Pubkey, lp_ata: Pubkey, amount: u64) {
    let ix = deposit_ix(&w.c, &u.pubkey(), ata, lp_ata, amount);
    send(&mut w.svm, &w.payer.insecure_clone(), &[u], ix).expect("Deposit");
}

// ── tests ────────────────────────────────────────────────────────────────────

/// Inertness: a pool that has never flushed is completely unaffected by the gate.
/// This is the state of every pool in normal operation before any flush.
#[test]
fn ah2_unflushed_pool_is_unaffected() {
    let mut w = world(1, 0);

    let (a, a_ata, a_lp_ata) = new_user(&mut w, GENESIS);
    deposit(&mut w, &a, a_ata, a_lp_ata, GENESIS);
    w.svm.expire_blockhash();

    let p = read_pool(&w.svm, &w.c.pool_pda);
    assert_eq!(p.wrapper_recoverable(), 0);

    let (b, b_ata, b_lp_ata) = new_user(&mut w, ATTACK);
    deposit(&mut w, &b, b_ata, b_lp_ata, ATTACK);

    let p = read_pool(&w.svm, &w.c.pool_pda);
    assert_eq!(p.total_deposited, GENESIS + ATTACK);
    assert!(
        token_amount(&w.svm, &b_lp_ata) > 0,
        "second LP minted normally"
    );
}
