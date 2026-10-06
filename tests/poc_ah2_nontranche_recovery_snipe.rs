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
const MARKET_LEN_V17_CAP1: usize = 3827; // v2.2 cap-1 market (592 + 798 + 2437); was 3147 (v17), 3675 (v2.1)
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;

/// `StakeError::InsuranceLossOutstanding` (src/error.rs).
const ERR_INSURANCE_LOSS_OUTSTANDING: u32 = 24;

const GENESIS: u64 = 1_000_000;
const FLUSH: u64 = 900_000;
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

fn custom_code(err: &litesvm::types::FailedTransactionMetadata) -> Option<u32> {
    match err.err {
        TransactionError::InstructionError(_, InstructionError::Custom(c)) => Some(c),
        _ => None,
    }
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

// ── world ────────────────────────────────────────────────────────────────────

struct World {
    svm: LiteSVM,
    c: Ctx,
    admin: Keypair,
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
        init_pool_ix(&c, &admin.pubkey(), cooldown_slots, deposit_cap),
    )
    .expect("InitPool");
    send(&mut svm, &payer, &[&admin], bind_ix(&c, &admin.pubkey()))
        .expect("BindInsuranceAuthority");

    World {
        svm,
        c,
        admin,
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

/// Genesis LP deposits, admin flushes `FLUSH` to wrapper insurance.
/// Returns the genesis LP's keypair and LP ATA.
fn genesis_and_flush(w: &mut World) -> (Keypair, Pubkey) {
    let (lp, ata, lp_ata) = new_user(w, GENESIS);
    deposit(w, &lp, ata, lp_ata, GENESIS);
    w.svm.expire_blockhash();

    let admin = w.admin.insecure_clone();
    let payer = w.payer.insecure_clone();
    send(
        &mut w.svm,
        &payer,
        &[&admin],
        flush_ix(&w.c, &admin.pubkey(), FLUSH),
    )
    .expect("FlushToInsurance");
    w.svm.expire_blockhash();

    let p = read_pool(&w.svm, &w.c.pool_pda);
    assert_eq!(p.total_flushed, FLUSH);
    assert_eq!(
        p.total_pool_value().unwrap(),
        GENESIS - FLUSH,
        "pool value is marked down by the flush"
    );
    assert_eq!(
        p.wrapper_recoverable(),
        FLUSH,
        "the whole flush is permissionlessly recoverable"
    );
    (lp, lp_ata)
}

// ── tests ────────────────────────────────────────────────────────────────────

/// **The PoC.** Deposit + Recover in ONE transaction must be refused.
///
/// Pre-fix this transaction SUCCEEDS and the attacker walks away with ~5.5x.
/// Post-fix the `Deposit` half is refused with `InsuranceLossOutstanding`, which
/// reverts the whole transaction, so no LP is minted and no tokens move.
#[test]
fn ah2_poc_snipe_is_blocked() {
    let mut w = world(1, 0);
    let (_lp, _lp_ata) = genesis_and_flush(&mut w);

    let before = read_pool(&w.svm, &w.c.pool_pda);
    let (att, att_ata, att_lp_ata) = new_user(&mut w, ATTACK);

    let payer = w.payer.insecure_clone();
    let err = send_batch(
        &mut w.svm,
        &payer,
        &[&att],
        vec![
            deposit_ix(&w.c, &att.pubkey(), att_ata, att_lp_ata, ATTACK),
            recover_ix(&w.c, &att.pubkey(), FLUSH),
        ],
    )
    .expect_err("A-H2: atomic Deposit+Recover must be refused");

    assert_eq!(
        custom_code(&err),
        Some(ERR_INSURANCE_LOSS_OUTSTANDING),
        "expected InsuranceLossOutstanding, got {:?}",
        err.err
    );

    // Whole transaction reverted: no LP minted, no collateral moved, no accounting drift.
    assert_eq!(token_amount(&w.svm, &att_lp_ata), 0, "no LP minted");
    assert_eq!(
        token_amount(&w.svm, &att_ata),
        ATTACK,
        "collateral untouched"
    );
    let after = read_pool(&w.svm, &w.c.pool_pda);
    assert_eq!(after.total_lp_supply, before.total_lp_supply);
    assert_eq!(after.total_deposited, before.total_deposited);
    assert_eq!(after.total_returned, before.total_returned);
}

/// Non-atomic is equally refused — the attacker does not need to own the recover.
/// This is why permissioning tag 23 would not have been a fix.
#[test]
fn ah2_snipe_is_blocked_without_atomicity() {
    let mut w = world(1, 0);
    genesis_and_flush(&mut w);

    let (att, att_ata, att_lp_ata) = new_user(&mut w, ATTACK);
    let payer = w.payer.insecure_clone();
    let err = send(
        &mut w.svm,
        &payer,
        &[&att],
        deposit_ix(&w.c, &att.pubkey(), att_ata, att_lp_ata, ATTACK),
    )
    .expect_err("bare Deposit during the recoverable window must be refused");

    assert_eq!(custom_code(&err), Some(ERR_INSURANCE_LOSS_OUTSTANDING));
    assert_eq!(token_amount(&w.svm, &att_lp_ata), 0);
}

/// **Liveness.** The gate is not a freeze: the blocked party lifts it themselves.
/// Recover-then-Deposit in the SAME transaction succeeds, and the deposit is then
/// priced against the restored basis — so the depositor breaks even instead of
/// capturing 5.5x, and the incumbent is made whole.
#[test]
fn ah2_recover_then_deposit_prices_fairly() {
    let mut w = world(1, 0);
    let (_lp, lp_ata) = genesis_and_flush(&mut w);
    let lp_tokens_genesis = token_amount(&w.svm, &lp_ata);

    let (dep, dep_ata, dep_lp_ata) = new_user(&mut w, ATTACK);
    let payer = w.payer.insecure_clone();
    send_batch(
        &mut w.svm,
        &payer,
        &[&dep],
        vec![
            recover_ix(&w.c, &dep.pubkey(), FLUSH),
            deposit_ix(&w.c, &dep.pubkey(), dep_ata, dep_lp_ata, ATTACK),
        ],
    )
    .expect("Recover-then-Deposit must succeed — the gate self-lifts");

    let p = read_pool(&w.svm, &w.c.pool_pda);
    assert_eq!(p.wrapper_recoverable(), 0, "recovery completed");
    assert_eq!(
        p.total_pool_value().unwrap(),
        GENESIS + ATTACK,
        "pool value restored and credited with the new deposit"
    );

    // The depositor's claim must not exceed what they paid in: no snipe.
    let dep_lp = token_amount(&w.svm, &dep_lp_ata);
    let dep_claim = p.calc_collateral_for_withdraw(dep_lp).unwrap();
    assert!(
        dep_claim <= ATTACK,
        "depositor must not profit: paid {ATTACK}, claim {dep_claim}"
    );

    // And the incumbent must be ~whole: the recovery accrued to them, not the newcomer.
    let genesis_claim = p.calc_collateral_for_withdraw(lp_tokens_genesis).unwrap();
    assert!(
        genesis_claim >= GENESIS - 2_000,
        "incumbent must retain their value: {genesis_claim} vs {GENESIS}"
    );
}

/// **The quantity pin — highest-value regression test in this file.**
///
/// `ReturnInsurance` (tag 10) credits `total_returned` from the admin's OWN wallet
/// without moving wrapper tokens. So `total_flushed - total_returned` reads 0 while
/// `wrapper_recoverable()` is still the entire flush and a permissionless tag-23
/// injection is still armed. A gate written against `flushed - returned` would open
/// here and the snipe would be live again.
#[test]
fn ah2_gate_tracks_wrapper_recoverable_not_flushed_minus_returned() {
    let mut w = world(1, 0);
    genesis_and_flush(&mut w);

    // Admin returns the full amount out of their own wallet.
    let admin = w.admin.insecure_clone();
    let payer = w.payer.insecure_clone();
    let admin_ata = Pubkey::new_unique();
    set_token_account(&mut w.svm, admin_ata, &w.c.mint, &admin.pubkey(), FLUSH);
    send(
        &mut w.svm,
        &payer,
        &[&admin],
        return_insurance_ix(&w.c, &admin.pubkey(), admin_ata, FLUSH),
    )
    .expect("ReturnInsurance");
    w.svm.expire_blockhash();

    let p = read_pool(&w.svm, &w.c.pool_pda);
    assert_eq!(
        p.total_flushed.saturating_sub(p.total_returned),
        0,
        "the OLD quantity reads zero — a `flushed - returned` gate would open here"
    );
    assert_eq!(
        p.wrapper_recoverable(),
        FLUSH,
        "but the whole flush is still permissionlessly injectable"
    );

    // The gate must still be shut.
    let (att, att_ata, att_lp_ata) = new_user(&mut w, ATTACK);
    let err = send(
        &mut w.svm,
        &payer,
        &[&att],
        deposit_ix(&w.c, &att.pubkey(), att_ata, att_lp_ata, ATTACK),
    )
    .expect_err("deposit must still be refused while wrapper_recoverable() > 0");
    assert_eq!(custom_code(&err), Some(ERR_INSURANCE_LOSS_OUTSTANDING));
}

/// Not a permanent freeze: once the recovery is complete, deposits reopen.
#[test]
fn ah2_deposits_reopen_after_full_recovery() {
    let mut w = world(1, 0);
    genesis_and_flush(&mut w);

    let payer = w.payer.insecure_clone();
    // Deliberately an account that signs NOTHING and has no role in the pool: the
    // recover handler takes its caller slot as a non-signer, which is the
    // permissionlessness this fix leaves intact.
    let anyone = Pubkey::new_unique();
    send(&mut w.svm, &payer, &[], recover_ix(&w.c, &anyone, FLUSH))
        .expect("permissionless recover by an unrelated, non-signing party");
    w.svm.expire_blockhash();

    assert_eq!(read_pool(&w.svm, &w.c.pool_pda).wrapper_recoverable(), 0);

    let (dep, dep_ata, dep_lp_ata) = new_user(&mut w, ATTACK);
    send(
        &mut w.svm,
        &payer,
        &[&dep],
        deposit_ix(&w.c, &dep.pubkey(), dep_ata, dep_lp_ata, ATTACK),
    )
    .expect("deposits reopen once nothing is recoverable");
    assert!(token_amount(&w.svm, &dep_lp_ata) > 0, "LP minted");
}

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
