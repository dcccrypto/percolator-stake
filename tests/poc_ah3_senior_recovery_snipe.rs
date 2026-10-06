//! A-H3 — senior recovery snipe: PoC and regression.
//!
//! `ReturnInsurance` (tag 10) credits `total_returned` from the admin's own wallet and
//! moves no wrapper tokens, so after a return `net_loss` reads 0 and the #159 gate opens
//! while `wrapper_recoverable()` is still the whole flush and the permissionless tag 23
//! is still armed. Because `effective_junior_balance()` saturates at raw
//! `junior_balance()` once `net_loss` is 0, that recovery lands entirely on senior.
//!
//! Two tests carry most of the weight if this file is ever trimmed:
//!
//! - `ah3_junior_absorbed_loss_does_not_gate_senior` — fails if the gate is ever
//!   simplified back to `wrapper_recoverable() > 0`, which over-blocks the region where
//!   a recovery cannot move `senior_balance()` at all.
//! - `ah3_enabling_tranches_must_not_reopen_the_ah2_gate` — `AdminSetTrancheConfig`
//!   switches execution from the non-tranche arm to this one, so the two must agree at
//!   `junior_balance() == 0` or enabling tranches reopens A-H2.
//!
//! Drives the real `percolator_stake.so` against the real `percolator_prog.so` through
//! LiteSVM; every asserted number is read back out of accounts the programs wrote.

use bytemuck::Zeroable;
use litesvm::LiteSVM;
use percolator_stake::state::{
    derive_deposit_pda, derive_pool_pda, derive_vault_authority, StakePool, STAKE_POOL_SIZE,
};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
    system_program,
    transaction::{Transaction, TransactionError},
};
use std::path::PathBuf;
use std::str::FromStr;

const WRAPPER_MAINNET: &str = "ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv";
const STAKE_ID: &str = "9tbLt8fs1C7cJRXAyiGY7Ub88AT7MLWpxLqFNVCkqzA6";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const MARKET_LEN_V17_CAP1: usize = 3835; // v2.2 cap-1 market (592 + 806 + 2437); was 3147 (v17), 3675 (v2.1)
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;

/// `StakeError::InsuranceLossOutstanding` (src/error.rs).
const ERR_INSURANCE_LOSS_OUTSTANDING: u32 = 24;

const JUNIOR: u64 = 300_000;
const SENIOR: u64 = 700_000;
/// Junior-ABSORBED: strictly below `JUNIOR`, so #159 correctly stays open.
const FLUSH_ABSORBED: u64 = 200_000;
/// SPILLS past junior — the state #159 was written for.
const FLUSH_SPILL: u64 = 500_000;
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
    d[44] = 0;
    d[45] = 1;
    d
}

fn token_data(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
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

fn custom_code(err: &litesvm::types::FailedTransactionMetadata) -> Option<u32> {
    match err.err {
        TransactionError::InstructionError(_, InstructionError::Custom(c)) => Some(c),
        _ => None,
    }
}

// ── wrapper market ───────────────────────────────────────────────────────────

fn encode_init_market_v17() -> Vec<u8> {
    let mut out = Vec::with_capacity(219);
    out.push(0u8);
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
    wrapper_vault: Pubkey,
    wrapper_vault_auth: Pubkey,
}

fn init_pool_ix(c: &Ctx, admin: &Pubkey, cooldown_slots: u64, deposit_cap: u64) -> Instruction {
    let mut data = vec![0u8];
    data.extend_from_slice(&cooldown_slots.to_le_bytes());
    data.extend_from_slice(&deposit_cap.to_le_bytes());
    Instruction {
        program_id: c.stake_id,
        accounts: vec![
            AccountMeta::new(*admin, true),
            AccountMeta::new(c.market, false),
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

/// Tags 1 (`Deposit`, i.e. SENIOR when tranches are on) and 16 (`DepositJunior`)
/// share an account list.
fn deposit_like_ix(
    c: &Ctx,
    tag: u8,
    user: &Pubkey,
    user_ata: Pubkey,
    user_lp_ata: Pubkey,
    amount: u64,
) -> Instruction {
    let (deposit_pda, _) = derive_deposit_pda(&c.stake_id, &c.pool_pda, user);
    let mut data = vec![tag];
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

fn deposit_senior_ix(
    c: &Ctx,
    user: &Pubkey,
    user_ata: Pubkey,
    user_lp_ata: Pubkey,
    amount: u64,
) -> Instruction {
    deposit_like_ix(c, 1, user, user_ata, user_lp_ata, amount)
}

fn deposit_junior_ix(
    c: &Ctx,
    user: &Pubkey,
    user_ata: Pubkey,
    user_lp_ata: Pubkey,
    amount: u64,
) -> Instruction {
    deposit_like_ix(c, 16, user, user_ata, user_lp_ata, amount)
}

fn withdraw_ix(
    c: &Ctx,
    user: &Pubkey,
    user_ata: Pubkey,
    user_lp_ata: Pubkey,
    lp_amount: u64,
) -> Instruction {
    let (deposit_pda, _) = derive_deposit_pda(&c.stake_id, &c.pool_pda, user);
    let mut data = vec![2u8];
    data.extend_from_slice(&lp_amount.to_le_bytes());
    Instruction {
        program_id: c.stake_id,
        accounts: vec![
            AccountMeta::new(*user, true),
            AccountMeta::new(c.pool_pda, false),
            AccountMeta::new(user_lp_ata, false),
            AccountMeta::new(c.lp_mint, false),
            AccountMeta::new(c.vault, false),
            AccountMeta::new(user_ata, false),
            AccountMeta::new_readonly(c.vault_auth, false),
            AccountMeta::new(deposit_pda, false),
            AccountMeta::new_readonly(c.token_program, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
        ],
        data,
    }
}

fn set_tranche_config_ix(c: &Ctx, admin: &Pubkey, junior_fee_mult_bps: u16) -> Instruction {
    let mut data = vec![15u8];
    data.extend_from_slice(&junior_fee_mult_bps.to_le_bytes());
    Instruction {
        program_id: c.stake_id,
        accounts: vec![
            AccountMeta::new(*admin, true),
            AccountMeta::new(c.pool_pda, false),
        ],
        data,
    }
}

fn bind_ix(c: &Ctx, admin: &Pubkey) -> Instruction {
    Instruction {
        program_id: c.stake_id,
        accounts: vec![
            AccountMeta::new(*admin, true),
            AccountMeta::new_readonly(c.pool_pda, false),
            AccountMeta::new_readonly(c.vault_auth, false),
            AccountMeta::new(c.market, false),
            AccountMeta::new_readonly(c.wrapper_id, false),
        ],
        data: vec![19u8],
    }
}

fn flush_ix(c: &Ctx, admin: &Pubkey, amount: u64) -> Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: c.stake_id,
        accounts: vec![
            AccountMeta::new(*admin, true),
            AccountMeta::new(c.pool_pda, false),
            AccountMeta::new(c.vault, false),
            AccountMeta::new_readonly(c.vault_auth, false),
            AccountMeta::new(c.market, false),
            AccountMeta::new(c.wrapper_vault, false),
            AccountMeta::new_readonly(c.wrapper_id, false),
            AccountMeta::new_readonly(c.token_program, false),
        ],
        data,
    }
}

fn recover_ix(c: &Ctx, caller: &Pubkey, amount: u64) -> Instruction {
    let mut data = vec![23u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: c.stake_id,
        accounts: vec![
            AccountMeta::new_readonly(*caller, false), // permissionless: not a signer
            AccountMeta::new(c.pool_pda, false),
            AccountMeta::new(c.vault, false),
            AccountMeta::new_readonly(c.vault_auth, false),
            AccountMeta::new(c.market, false),
            AccountMeta::new(c.wrapper_vault, false),
            AccountMeta::new_readonly(c.wrapper_vault_auth, false),
            AccountMeta::new_readonly(c.token_program, false),
            AccountMeta::new_readonly(c.wrapper_id, false),
        ],
        data,
    }
}

fn return_insurance_ix(c: &Ctx, admin: &Pubkey, admin_ata: Pubkey, amount: u64) -> Instruction {
    let mut data = vec![10u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: c.stake_id,
        accounts: vec![
            AccountMeta::new(*admin, true),
            AccountMeta::new(c.pool_pda, false),
            AccountMeta::new(admin_ata, false),
            AccountMeta::new(c.vault, false),
            AccountMeta::new_readonly(c.token_program, false),
        ],
        data,
    }
}

fn read_pool(svm: &LiteSVM, pool_pda: &Pubkey) -> StakePool {
    let data = svm.get_account(pool_pda).unwrap().data;
    *bytemuck::from_bytes::<StakePool>(&data[..STAKE_POOL_SIZE])
}

/// GROUND TRUTH, computed from real on-chain state: what `senior_balance()` becomes
/// after a legal recovery of `amount`. A recovery bumps `total_returned` and
/// `total_recovered_from_wrapper` by the same amount and touches nothing else.
fn senior_balance_after_recovery(p: &StakePool, amount: u64) -> u64 {
    let mut q = *p;
    q.total_returned += amount;
    q.total_recovered_from_wrapper += amount;
    q.senior_balance().expect("senior_balance after recovery")
}

// ── world ────────────────────────────────────────────────────────────────────

struct World {
    svm: LiteSVM,
    c: Ctx,
    admin: Keypair,
    payer: Keypair,
}

/// Real InitMarket -> real InitPool (mode 0) -> real bind -> real
/// `AdminSetTrancheConfig` (tag 15). Nothing about the pool is forged.
fn world_inner(cooldown_slots: u64, tranched: bool) -> World {
    assert!(
        stake_so().exists(),
        "missing {} — run `cargo build-sbf --no-default-features` first. \
         Without this the suite would report ok in 0.00s having tested nothing.",
        stake_so().display()
    );
    assert!(
        wrapper_so().exists(),
        "missing {} — build ../percolator-prog first.",
        wrapper_so().display()
    );

    let mut svm = LiteSVM::new().with_spl_programs();
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
    let wrapper_id = Pubkey::from_str(WRAPPER_MAINNET).unwrap();
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    svm.add_program_from_file(stake_id, stake_so()).unwrap();
    svm.add_program_from_file(wrapper_id, wrapper_so()).unwrap();

    let admin = Keypair::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&admin.pubkey(), 10_000_000_000).unwrap();

    let (market, mint, wrapper_vault, wrapper_vault_auth) =
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
        wrapper_vault,
        wrapper_vault_auth,
    };

    send(
        &mut svm,
        &payer,
        &[&admin],
        init_pool_ix(&c, &admin.pubkey(), cooldown_slots, 0),
    )
    .expect("InitPool");
    svm.expire_blockhash();
    send(&mut svm, &payer, &[&admin], bind_ix(&c, &admin.pubkey()))
        .expect("BindInsuranceAuthority");
    svm.expire_blockhash();
    if tranched {
        send(
            &mut svm,
            &payer,
            &[&admin],
            set_tranche_config_ix(&c, &admin.pubkey(), 20_000),
        )
        .expect("AdminSetTrancheConfig");
        svm.expire_blockhash();
    }

    assert_eq!(
        read_pool(&svm, &pool_pda).tranche_enabled(),
        tranched,
        "the pool must start in the requested tranche mode"
    );

    World {
        svm,
        c,
        admin,
        payer,
    }
}

/// Tranches ON — the arm this file exercises.
fn world(cooldown_slots: u64) -> World {
    world_inner(cooldown_slots, true)
}

/// Tranches OFF — a pool living under the shipped A-H2 gate, used to show that
/// switching tranches on must not be an escape hatch out of it.
fn world_untranched(cooldown_slots: u64) -> World {
    world_inner(cooldown_slots, false)
}

fn new_user(w: &mut World, amount: u64) -> (Keypair, Pubkey, Pubkey) {
    let user = Keypair::new();
    w.svm.airdrop(&user.pubkey(), 10_000_000_000).unwrap();
    let ata = Pubkey::new_unique();
    let lp_ata = Pubkey::new_unique();
    set_token_account(&mut w.svm, ata, &w.c.mint, &user.pubkey(), amount);
    set_token_account(&mut w.svm, lp_ata, &w.c.lp_mint, &user.pubkey(), 0);
    (user, ata, lp_ata)
}

/// Junior cohort in first (the junior gate demands `physical_net_loss == 0`), then
/// the senior cohort, then the admin flushes `flush` into wrapper insurance.
/// Returns (junior kp/lp_ata, senior kp/lp_ata).
fn tranched_pool_with_flush(w: &mut World, flush: u64) -> ((Keypair, Pubkey), (Keypair, Pubkey)) {
    let (jun, jun_ata, jun_lp) = new_user(w, JUNIOR);
    let payer = w.payer.insecure_clone();
    send(
        &mut w.svm,
        &payer,
        &[&jun],
        deposit_junior_ix(&w.c, &jun.pubkey(), jun_ata, jun_lp, JUNIOR),
    )
    .expect("DepositJunior");
    w.svm.expire_blockhash();

    let (sen, sen_ata, sen_lp) = new_user(w, SENIOR);
    send(
        &mut w.svm,
        &payer,
        &[&sen],
        deposit_senior_ix(&w.c, &sen.pubkey(), sen_ata, sen_lp, SENIOR),
    )
    .expect("DepositSenior");
    w.svm.expire_blockhash();

    let p = read_pool(&w.svm, &w.c.pool_pda);
    assert_eq!(p.junior_balance(), JUNIOR, "junior sub-pool funded");
    assert_eq!(
        p.senior_balance().unwrap(),
        SENIOR,
        "senior sub-pool funded"
    );

    let admin = w.admin.insecure_clone();
    send(
        &mut w.svm,
        &payer,
        &[&admin],
        flush_ix(&w.c, &admin.pubkey(), flush),
    )
    .expect("FlushToInsurance");
    w.svm.expire_blockhash();

    let p = read_pool(&w.svm, &w.c.pool_pda);
    assert_eq!(p.total_flushed, flush);
    assert_eq!(p.wrapper_recoverable(), flush);
    ((jun, jun_lp), (sen, sen_lp))
}

fn admin_returns(w: &mut World, amount: u64) {
    let admin = w.admin.insecure_clone();
    let payer = w.payer.insecure_clone();
    let admin_ata = Pubkey::new_unique();
    set_token_account(&mut w.svm, admin_ata, &w.c.mint, &admin.pubkey(), amount);
    send(
        &mut w.svm,
        &payer,
        &[&admin],
        return_insurance_ix(&w.c, &admin.pubkey(), admin_ata, amount),
    )
    .expect("ReturnInsurance");
    w.svm.expire_blockhash();
}

// ── tests ────────────────────────────────────────────────────────────────────

/// **The PoC.** Junior-absorbed flush, then a FULL admin `ReturnInsurance`. `net_loss`
/// now reads 0 so the bare #159 gate opens — but the whole flush is still
/// permissionlessly recoverable and a recovery now lands entirely on senior.
///
/// Asserts the exposure out of real state FIRST (so the test documents the size of
/// the hole even on a build where the gate is missing), then asserts the deposit is
/// refused.
#[test]
fn ah3_poc_senior_snipe_is_blocked() {
    let mut w = world(1);
    tranched_pool_with_flush(&mut w, FLUSH_ABSORBED);
    admin_returns(&mut w, FLUSH_ABSORBED);

    let p = read_pool(&w.svm, &w.c.pool_pda);

    // The #159 quantity has gone to zero — the OLD gate opens right here.
    assert_eq!(
        p.total_flushed.saturating_sub(p.total_returned),
        0,
        "net_loss reads 0 after a full ReturnInsurance: the #159 gate would open"
    );
    assert!(
        p.total_flushed.saturating_sub(p.total_returned) <= p.junior_balance(),
        "#159's condition `net_loss > junior_balance` is FALSE here"
    );
    // ...while the entire flush is still injectable by anyone.
    assert_eq!(p.wrapper_recoverable(), FLUSH_ABSORBED);

    // And a recovery would move senior_balance() by the FULL amount, because
    // effective_junior_balance() has saturated at the raw junior_balance().
    let sb_now = p.senior_balance().unwrap();
    let sb_after = senior_balance_after_recovery(&p, FLUSH_ABSORBED);
    assert_eq!(
        sb_after - sb_now,
        FLUSH_ABSORBED,
        "the whole recovery lands on senior: {sb_now} -> {sb_after}"
    );
    assert_eq!(
        p.senior_recovery_exposure(),
        FLUSH_ABSORBED,
        "senior_recovery_exposure() must measure exactly that step-up"
    );

    // Therefore the deposit must be refused — atomic or not.
    let (att, att_ata, att_lp) = new_user(&mut w, ATTACK);
    let payer = w.payer.insecure_clone();
    let err = send_batch(
        &mut w.svm,
        &payer,
        &[&att],
        vec![
            deposit_senior_ix(&w.c, &att.pubkey(), att_ata, att_lp, ATTACK),
            recover_ix(&w.c, &att.pubkey(), FLUSH_ABSORBED),
        ],
    )
    .expect_err("A-H3: atomic DepositSenior+Recover must be refused");
    assert_eq!(
        custom_code(&err),
        Some(ERR_INSURANCE_LOSS_OUTSTANDING),
        "expected InsuranceLossOutstanding, got {:?}",
        err.err
    );

    w.svm.expire_blockhash();
    let err = send(
        &mut w.svm,
        &payer,
        &[&att],
        deposit_senior_ix(&w.c, &att.pubkey(), att_ata, att_lp, ATTACK),
    )
    .expect_err("bare DepositSenior in the exposed window must be refused too");
    assert_eq!(custom_code(&err), Some(ERR_INSURANCE_LOSS_OUTSTANDING));

    // Nothing moved.
    assert_eq!(token_amount(&w.svm, &att_lp), 0, "no LP minted");
    assert_eq!(
        token_amount(&w.svm, &att_ata),
        ATTACK,
        "collateral untouched"
    );
    let after = read_pool(&w.svm, &w.c.pool_pda);
    assert_eq!(after.total_deposited, p.total_deposited);
    assert_eq!(after.total_returned, p.total_returned);
}

/// **The over-block pin. The single most important test in this file.**
///
/// Junior-ABSORBED loss, no admin return. `wrapper_recoverable()` is the entire
/// flush, so the blunt A-H2 condition fires — but `senior_balance()` is INVARIANT
/// under every legal recovery, so there is nothing to snipe and senior deposits MUST
/// stay open.
///
/// This test FAILS if the gate is ever simplified to `wrapper_recoverable() > 0`.
#[test]
fn ah3_junior_absorbed_loss_does_not_gate_senior() {
    let mut w = world(1);
    tranched_pool_with_flush(&mut w, FLUSH_ABSORBED);

    let p = read_pool(&w.svm, &w.c.pool_pda);
    assert!(
        p.wrapper_recoverable() > 0,
        "the blunt `wrapper_recoverable() > 0` condition IS satisfied here"
    );
    assert!(
        p.total_flushed.saturating_sub(p.total_returned) <= p.junior_balance(),
        "but the loss is junior-absorbed"
    );

    // Ground truth: NO legal recovery moves senior_balance() by even one unit.
    let sb_now = p.senior_balance().unwrap();
    for amount in 1..=p.wrapper_recoverable() {
        // step through the interesting boundary, not all 200k values
        if amount > 3 && amount < p.wrapper_recoverable() - 3 && amount % 25_000 != 0 {
            continue;
        }
        assert_eq!(
            senior_balance_after_recovery(&p, amount),
            sb_now,
            "senior_balance() must be invariant under a recovery of {amount}"
        );
    }
    assert_eq!(
        p.senior_recovery_exposure(),
        0,
        "so the exposure is zero and the gate must NOT fire"
    );

    // Liveness: an honest senior depositor is NOT frozen out.
    let (dep, dep_ata, dep_lp) = new_user(&mut w, ATTACK);
    let payer = w.payer.insecure_clone();
    send(
        &mut w.svm,
        &payer,
        &[&dep],
        deposit_senior_ix(&w.c, &dep.pubkey(), dep_ata, dep_lp, ATTACK),
    )
    .expect(
        "senior deposits MUST stay open on a junior-absorbed loss — blocking here is \
         the exact over-block this gate is designed to avoid",
    );
    assert!(token_amount(&w.svm, &dep_lp) > 0, "LP minted");
    w.svm.expire_blockhash();

    // ...and letting the recovery happen afterwards does NOT enrich them: the
    // liveness we preserved is not a hole.
    let before = read_pool(&w.svm, &w.c.pool_pda);
    let lp = token_amount(&w.svm, &dep_lp);
    let anyone = Pubkey::new_unique();
    send(
        &mut w.svm,
        &payer,
        &[],
        recover_ix(&w.c, &anyone, FLUSH_ABSORBED),
    )
    .expect("permissionless recover");
    let after = read_pool(&w.svm, &w.c.pool_pda);

    assert_eq!(
        after.senior_balance().unwrap(),
        before.senior_balance().unwrap(),
        "senior sub-pool is unchanged by the recovery — nothing was sniped"
    );
    let claim = percolator_stake::math::calc_senior_collateral_for_withdraw(
        after.senior_total_lp(),
        after.senior_balance().unwrap(),
        lp,
    )
    .unwrap();
    assert!(
        claim <= ATTACK,
        "depositor must not profit from the recovery: paid {ATTACK}, claim {claim}"
    );
}

/// The middle case a "gate only when `net_loss == 0`" patch would miss: a PARTIAL
/// `ReturnInsurance`. `net_loss` is still positive and still junior-absorbed, so both
/// the old gate and a `net_loss == 0` special case stay open — yet `total_returned`
/// can now be pushed PAST `total_flushed`, and the overshoot lands on senior.
#[test]
fn ah3_partial_return_insurance_still_exposes_senior() {
    const PARTIAL: u64 = 50_000;
    let mut w = world(1);
    tranched_pool_with_flush(&mut w, FLUSH_ABSORBED);
    admin_returns(&mut w, PARTIAL);

    let p = read_pool(&w.svm, &w.c.pool_pda);
    let net = p.total_flushed.saturating_sub(p.total_returned);
    assert_eq!(net, FLUSH_ABSORBED - PARTIAL, "net_loss is still POSITIVE");
    assert!(
        net <= p.junior_balance(),
        "and still junior-absorbed: #159 opens"
    );
    assert_ne!(net, 0, "so a `net_loss == 0` special case would miss this");

    let sb_now = p.senior_balance().unwrap();
    let sb_after = senior_balance_after_recovery(&p, p.wrapper_recoverable());
    assert_eq!(
        sb_after - sb_now,
        PARTIAL,
        "the overshoot past total_flushed — exactly the admin-returned amount — \
         lands on senior"
    );
    assert_eq!(p.senior_recovery_exposure(), PARTIAL);

    let (att, att_ata, att_lp) = new_user(&mut w, ATTACK);
    let payer = w.payer.insecure_clone();
    let err = send(
        &mut w.svm,
        &payer,
        &[&att],
        deposit_senior_ix(&w.c, &att.pubkey(), att_ata, att_lp, ATTACK),
    )
    .expect_err("partial-return exposure must be gated");
    assert_eq!(custom_code(&err), Some(ERR_INSURANCE_LOSS_OUTSTANDING));
}

/// #159 is not regressed: a loss that spills PAST junior still blocks senior
/// deposits, for the original reason (senior is marked down and a recovery un-marks
/// it).
#[test]
fn ah3_spilled_loss_still_blocks_senior_deposits() {
    let mut w = world(1);
    tranched_pool_with_flush(&mut w, FLUSH_SPILL);

    let p = read_pool(&w.svm, &w.c.pool_pda);
    let net = p.total_flushed.saturating_sub(p.total_returned);
    assert!(net > p.junior_balance(), "#159's own condition holds");
    assert_eq!(
        p.senior_recovery_exposure(),
        FLUSH_SPILL - JUNIOR,
        "exposure is the senior-absorbed slice of the loss"
    );

    let (att, att_ata, att_lp) = new_user(&mut w, ATTACK);
    let payer = w.payer.insecure_clone();
    let err = send(
        &mut w.svm,
        &payer,
        &[&att],
        deposit_senior_ix(&w.c, &att.pubkey(), att_ata, att_lp, ATTACK),
    )
    .expect_err("#159 must still block");
    assert_eq!(custom_code(&err), Some(ERR_INSURANCE_LOSS_OUTSTANDING));
}

/// **Liveness / self-lift.** The gate is not a freeze and needs no privileged key:
/// the blocked party prepends the permissionless recover and the deposit then prices
/// against the restored, honest basis.
#[test]
fn ah3_recover_then_deposit_senior_succeeds_and_prices_fairly() {
    let mut w = world(1);
    let (_jun, (_sen, sen_lp)) = tranched_pool_with_flush(&mut w, FLUSH_ABSORBED);
    admin_returns(&mut w, FLUSH_ABSORBED);
    let senior_lp_incumbent = token_amount(&w.svm, &sen_lp);

    let (dep, dep_ata, dep_lp) = new_user(&mut w, ATTACK);
    let payer = w.payer.insecure_clone();
    send_batch(
        &mut w.svm,
        &payer,
        &[&dep],
        vec![
            recover_ix(&w.c, &dep.pubkey(), FLUSH_ABSORBED),
            deposit_senior_ix(&w.c, &dep.pubkey(), dep_ata, dep_lp, ATTACK),
        ],
    )
    .expect("Recover-then-DepositSenior must succeed — the gate self-lifts");

    let p = read_pool(&w.svm, &w.c.pool_pda);
    assert_eq!(p.wrapper_recoverable(), 0, "recovery completed");
    assert_eq!(p.senior_recovery_exposure(), 0, "gate is open again");

    let senior_bal = p.senior_balance().unwrap();
    let dep_claim = percolator_stake::math::calc_senior_collateral_for_withdraw(
        p.senior_total_lp(),
        senior_bal,
        token_amount(&w.svm, &dep_lp),
    )
    .unwrap();
    assert!(
        dep_claim <= ATTACK,
        "late depositor must not profit: paid {ATTACK}, claim {dep_claim}"
    );

    // The incumbent senior keeps the whole step-up: 700_000 principal plus the
    // admin's 200_000 top-up that the recovery pushed past total_flushed.
    let inc_claim = percolator_stake::math::calc_senior_collateral_for_withdraw(
        p.senior_total_lp(),
        senior_bal,
        senior_lp_incumbent,
    )
    .unwrap();
    assert!(
        inc_claim >= SENIOR + FLUSH_ABSORBED - 2_000,
        "incumbent senior keeps the recovery: {inc_claim}"
    );
}

/// **Withdrawals must never be frozen.** While the gate is shut, every exit path
/// stays open — senior and junior alike.
#[test]
fn ah3_gate_never_freezes_withdrawals() {
    let mut w = world(1);
    let ((jun, jun_lp), (sen, sen_lp)) = tranched_pool_with_flush(&mut w, FLUSH_ABSORBED);
    admin_returns(&mut w, FLUSH_ABSORBED);
    // Clear the deposit cooldown so the exits below are legal on their own terms —
    // this test is about the GATE, not the cooldown.
    let slot = w.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    w.svm.warp_to_slot(slot + 100);

    assert!(
        read_pool(&w.svm, &w.c.pool_pda).senior_recovery_exposure() > 0,
        "precondition: deposits ARE gated in this state"
    );

    let payer = w.payer.insecure_clone();

    // Senior exit.
    let sen_ata = Pubkey::new_unique();
    set_token_account(&mut w.svm, sen_ata, &w.c.mint, &sen.pubkey(), 0);
    let sen_lp_amt = token_amount(&w.svm, &sen_lp);
    send(
        &mut w.svm,
        &payer,
        &[&sen],
        withdraw_ix(&w.c, &sen.pubkey(), sen_ata, sen_lp, sen_lp_amt),
    )
    .expect("SENIOR WITHDRAWAL MUST STAY OPEN while the deposit gate is shut");
    assert!(token_amount(&w.svm, &sen_ata) > 0, "senior got paid");
    w.svm.expire_blockhash();

    // Junior exit.
    let jun_ata = Pubkey::new_unique();
    set_token_account(&mut w.svm, jun_ata, &w.c.mint, &jun.pubkey(), 0);
    let jun_lp_amt = token_amount(&w.svm, &jun_lp);
    send(
        &mut w.svm,
        &payer,
        &[&jun],
        withdraw_ix(&w.c, &jun.pubkey(), jun_ata, jun_lp, jun_lp_amt),
    )
    .expect("JUNIOR WITHDRAWAL MUST STAY OPEN while the deposit gate is shut");
    assert!(token_amount(&w.svm, &jun_ata) > 0, "junior got paid");
}

/// Inertness: a tranche pool that has never flushed is completely unaffected.
#[test]
fn ah3_unflushed_tranche_pool_is_unaffected() {
    let mut w = world(1);
    let (jun, jun_ata, jun_lp) = new_user(&mut w, JUNIOR);
    let payer = w.payer.insecure_clone();
    send(
        &mut w.svm,
        &payer,
        &[&jun],
        deposit_junior_ix(&w.c, &jun.pubkey(), jun_ata, jun_lp, JUNIOR),
    )
    .expect("DepositJunior");
    w.svm.expire_blockhash();

    assert_eq!(
        read_pool(&w.svm, &w.c.pool_pda).senior_recovery_exposure(),
        0
    );

    let (sen, sen_ata, sen_lp) = new_user(&mut w, SENIOR);
    send(
        &mut w.svm,
        &payer,
        &[&sen],
        deposit_senior_ix(&w.c, &sen.pubkey(), sen_ata, sen_lp, SENIOR),
    )
    .expect("senior deposits are untouched on a healthy pool");
    assert!(token_amount(&w.svm, &sen_lp) > 0);
}

/// The senior gate and the A-H2 non-tranche gate are ONE formula evaluated at
/// different junior balances: with `junior_balance() == 0`,
/// `senior_recovery_exposure()` collapses to `wrapper_recoverable()`, so the two arms
/// of the `if tranche_enabled()` block agree and neither shadows the other.
///
/// Pure state math — no `.so` needed.
#[test]
fn senior_gate_reduces_to_nontranche_gate_when_junior_is_empty() {
    for (f, admin_returned, recovered, realized) in [
        (0u64, 0u64, 0u64, 0u64),
        (1000, 0, 0, 0),
        (1000, 1000, 0, 0),
        (1000, 400, 300, 0),
        (1000, 0, 1000, 0),
        (1000, 250, 250, 250),
        (1000, 1000, 0, 500),
    ] {
        let mut p = StakePool::zeroed();
        p.set_discriminator();
        p.set_tranche_enabled(true);
        p.total_deposited = 10_000;
        p.total_flushed = f;
        p.total_returned = admin_returned + recovered + realized;
        p.total_recovered_from_wrapper = recovered;
        p.set_realized_junior_loss(realized);
        p.set_junior_balance(0); // junior tranche empty

        assert_eq!(
            p.senior_recovery_exposure(),
            p.wrapper_recoverable(),
            "with an empty junior the senior gate must equal the A-H2 gate \
             (f={f} returned={admin_returned} recovered={recovered} realized={realized})"
        );
        assert_eq!(
            p.senior_recovery_exposure() > 0,
            p.wrapper_recoverable() > 0,
            "...including the boolean the two call sites actually branch on"
        );
    }
}

/// **The bypass. This is the strongest single argument for shipping the senior gate,
/// and it is independent of how one scores A-H3's severity.**
///
/// A-H2's shipped gate lives in the `else` arm of `if pool.tranche_enabled()`. It
/// therefore STOPS RUNNING the moment tranches are switched on — and
/// `AdminSetTrancheConfig` (tag 15) is a one-line admin call with no precondition
/// relating to insurance state, available at any point in a pool's life.
///
/// So on the shipped code a non-tranche pool sitting in the A-H2-gated state
/// (`wrapper_recoverable() > 0`) is moved out of that gate by enabling tranches: the
/// tranche arm then evaluates `net_loss > junior_balance()`, which with an empty
/// junior tranche and a completed `ReturnInsurance` is `0 > 0` — FALSE. Deposits
/// reopen and the A-H2 snipe is live again on a pool the fix was supposed to cover.
///
/// `senior_recovery_exposure()` closes it because it collapses to
/// `wrapper_recoverable()` exactly when `junior_balance() == 0` — the two arms agree
/// on the empty-junior boundary instead of disagreeing across it.
#[test]
fn ah3_enabling_tranches_must_not_reopen_the_ah2_gate() {
    // A pool that starts life WITHOUT tranches, in the A-H2-gated state.
    let mut w = world_untranched(1);
    let (lp, lp_ata, lp_lp) = new_user(&mut w, SENIOR);
    let payer = w.payer.insecure_clone();
    send(
        &mut w.svm,
        &payer,
        &[&lp],
        deposit_senior_ix(&w.c, &lp.pubkey(), lp_ata, lp_lp, SENIOR),
    )
    .expect("Deposit (non-tranche)");
    w.svm.expire_blockhash();

    let admin = w.admin.insecure_clone();
    send(
        &mut w.svm,
        &payer,
        &[&admin],
        flush_ix(&w.c, &admin.pubkey(), FLUSH_ABSORBED),
    )
    .expect("Flush");
    w.svm.expire_blockhash();
    admin_returns(&mut w, FLUSH_ABSORBED);

    // A-H2's gate is shut.
    let (att, att_ata, att_lp) = new_user(&mut w, ATTACK);
    let err = send(
        &mut w.svm,
        &payer,
        &[&att],
        deposit_senior_ix(&w.c, &att.pubkey(), att_ata, att_lp, ATTACK),
    )
    .expect_err("precondition: A-H2's non-tranche gate blocks here");
    assert_eq!(custom_code(&err), Some(ERR_INSURANCE_LOSS_OUTSTANDING));
    w.svm.expire_blockhash();

    // The admin enables tranches. A-H2's `else` arm stops running.
    send(
        &mut w.svm,
        &payer,
        &[&admin],
        set_tranche_config_ix(&w.c, &admin.pubkey(), 20_000),
    )
    .expect("AdminSetTrancheConfig");
    w.svm.expire_blockhash();

    let p = read_pool(&w.svm, &w.c.pool_pda);
    assert!(p.tranche_enabled());
    assert_eq!(p.junior_balance(), 0, "no junior has ever deposited");
    // The OLD tranche-arm predicate is now FALSE — this is the bypass.
    assert!(
        !(p.total_flushed.saturating_sub(p.total_returned) > p.junior_balance()),
        "`net_loss > junior_balance` is 0 > 0 = FALSE: the shipped tranche arm would \
         let the deposit through and re-open the A-H2 snipe"
    );
    assert_eq!(
        p.wrapper_recoverable(),
        FLUSH_ABSORBED,
        "while the whole flush is still permissionlessly injectable"
    );

    // The new predicate does not have the seam.
    assert_eq!(
        p.senior_recovery_exposure(),
        p.wrapper_recoverable(),
        "with an empty junior the senior gate equals the A-H2 gate — no seam to slip through"
    );
    let err = send(
        &mut w.svm,
        &payer,
        &[&att],
        deposit_senior_ix(&w.c, &att.pubkey(), att_ata, att_lp, ATTACK),
    )
    .expect_err("enabling tranches MUST NOT be an escape hatch out of the A-H2 gate");
    assert_eq!(custom_code(&err), Some(ERR_INSURANCE_LOSS_OUTSTANDING));
    assert_eq!(token_amount(&w.svm, &att_lp), 0, "no LP minted");
}
