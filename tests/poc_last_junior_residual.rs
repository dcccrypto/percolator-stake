//! Last-junior N7 residual (v2.2 Kani proof review, finding "N7 residual", M11/N1/B1).
//!
//! `calc_junior_collateral_for_withdraw` prices a junior burn with the N7 virtual
//! offsets: `lp * (ejb + 1) / (jlp + 1)`. When the burn is the WHOLE junior supply
//! (`lp == jlp`) and the effective junior balance `ejb` exceeds `jlp` (any fee the
//! junior tranche has earned does this), that pays `ejb - (ejb - jlp)/(jlp + 1)`, not
//! `ejb`. `process_withdraw` then sets `junior_balance := 0`, so the unpaid remainder
//! stays in the vault and `senior_balance() = total_pool_value() - ejb` absorbs it: the
//! last junior is short-changed and senior gets a windfall. At the Kani counterexample's
//! numbers (`ejb = 1000`, `jlp = 1`) the last junior gets 500 and senior gains 500.
//!
//! Fix (`math::calc_junior_collateral_for_withdraw`): a burn of the whole junior supply
//! pays the whole effective junior balance. It never pays more than `ejb`, and `ejb` is
//! the junior tranche's own value, so senior's value is unchanged by the exit.
//!
//! NEW-1 (security review of 9942a2c): with a SENIOR genesis the junior sub-pool had no
//! dead-share floor, so a 1-LP first junior could inflate the junior share price and take
//! a later junior's round-down. The first deposit into an empty junior sub-pool now locks
//! `MINIMUM_LIQUIDITY` dead junior shares (and, mirrored, the first deposit into an empty
//! senior sub-pool after a junior genesis locks senior ones). The junior supply then never
//! reaches 0, so the full-burn branch above is defence in depth; the original
//! `ejb = 1000, jlp = 1` state is unreachable and the tests below show the last REAL
//! junior exit still never windfalls senior.
//!
//! Drives the real `percolator_stake.so` (+ the real wrapper `.so` for `InitMarket`)
//! through LiteSVM. Pool is a mode-1 (`InitTradingPool`) tranche pool, the mode in which
//! a vault surplus books as fees (mode 0 books only wrapper tag-87 payouts, #290); the
//! surplus is a real SPL `transfer` into the vault followed by the real permissionless
//! `AccrueFees`. Nothing in the stake pool is forged; every asserted number is read back
//! out of accounts the programs wrote.

#![allow(clippy::result_large_err)] // LiteSVM's FailedTransactionMetadata, as in the sibling e2e files

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
const MARKET_LEN_V17_CAP1: usize = 4059; // same v2.2 -rem cap-1 market as poc_ah3_senior_recovery_snipe.rs
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;

/// Junior fee multiplier (2x). Junior weight = jb * 20_000, senior = sb * 10_000.
const JUNIOR_MULT_BPS: u16 = 20_000;
/// Senior genesis deposit (1000 of it is the N7 MINIMUM_LIQUIDITY dead-share floor).
const SENIOR_GENESIS: u64 = 2_000;
const COOLDOWN_SLOTS: u64 = 1;

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
    (market, mint)
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

fn read_pool(svm: &LiteSVM, pool_pda: &Pubkey) -> StakePool {
    let data = svm.get_account(pool_pda).unwrap().data;
    *bytemuck::from_bytes::<StakePool>(&data[..STAKE_POOL_SIZE])
}

/// Tag 13 `InitTradingPool`: same 11-account list as `InitPool`, 16-byte payload.
fn init_trading_pool_ix(c: &Ctx, admin: &Pubkey) -> Instruction {
    let mut data = vec![13u8];
    data.extend_from_slice(&COOLDOWN_SLOTS.to_le_bytes()); // cooldown_slots (must be > 0)
    data.extend_from_slice(&0u64.to_le_bytes()); // deposit_cap (0 = uncapped)
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

/// Tag 12 `AccrueFees` (permissionless). Mode 1 needs no wrapper market account.
fn accrue_fees_ix(c: &Ctx, caller: &Pubkey) -> Instruction {
    Instruction {
        program_id: c.stake_id,
        accounts: vec![
            AccountMeta::new_readonly(*caller, true),
            AccountMeta::new(c.pool_pda, false),
            AccountMeta::new_readonly(c.vault, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
        ],
        data: vec![12u8],
    }
}

/// A plain SPL-Token `Transfer` (tag 3) of `amount` from `src` (owned by `owner`).
fn spl_transfer_ix(c: &Ctx, src: Pubkey, dst: Pubkey, owner: &Pubkey, amount: u64) -> Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: c.token_program,
        accounts: vec![
            AccountMeta::new(src, false),
            AccountMeta::new(dst, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data,
    }
}

// ── world ────────────────────────────────────────────────────────────────────

struct World {
    svm: LiteSVM,
    c: Ctx,
    admin: Keypair,
    payer: Keypair,
}

/// Real InitMarket -> real InitTradingPool (mode 1) -> real AdminSetTrancheConfig.
fn world() -> World {
    world_mult(JUNIOR_MULT_BPS)
}

fn world_mult(junior_mult_bps: u16) -> World {
    let mut w = world_untranched();
    enable_tranches_mult(&mut w, junior_mult_bps);
    w
}

fn enable_tranches(w: &mut World) {
    enable_tranches_mult(w, JUNIOR_MULT_BPS);
}

fn enable_tranches_mult(w: &mut World, junior_mult_bps: u16) {
    let payer = w.payer.insecure_clone();
    let admin = w.admin.insecure_clone();
    send(
        &mut w.svm,
        &payer,
        &[&admin],
        set_tranche_config_ix(&w.c, &admin.pubkey(), junior_mult_bps),
    )
    .expect("AdminSetTrancheConfig");
    w.svm.expire_blockhash();
    assert!(pool(w).tranche_enabled(), "tranches on");
}

/// Real InitMarket -> real InitTradingPool (mode 1), tranches OFF.
fn world_untranched() -> World {
    assert!(
        stake_so().exists(),
        "missing {} — run `cargo build-sbf` first. Without this the suite would report \
         ok having tested nothing.",
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

    let (market, mint) = build_live_market_v17(&mut svm, wrapper_id, token_program, &admin, &payer);
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
        init_trading_pool_ix(&c, &admin.pubkey()),
    )
    .expect("InitTradingPool");
    svm.expire_blockhash();

    let p = read_pool(&svm, &pool_pda);
    assert_eq!(p.pool_mode, 1, "trading pool");
    assert!(!p.tranche_enabled(), "tranches off until enabled");
    World {
        svm,
        c,
        admin,
        payer,
    }
}

struct User {
    kp: Keypair,
    ata: Pubkey,
    lp_ata: Pubkey,
}

fn new_user(w: &mut World, amount: u64) -> User {
    let kp = Keypair::new();
    w.svm.airdrop(&kp.pubkey(), 10_000_000_000).unwrap();
    let ata = Pubkey::new_unique();
    let lp_ata = Pubkey::new_unique();
    set_token_account(&mut w.svm, ata, &w.c.mint, &kp.pubkey(), amount);
    set_token_account(&mut w.svm, lp_ata, &w.c.lp_mint, &kp.pubkey(), 0);
    User { kp, ata, lp_ata }
}

fn deposit_senior(w: &mut World, u: &User, amount: u64) {
    let payer = w.payer.insecure_clone();
    let ix = deposit_senior_ix(&w.c, &u.kp.pubkey(), u.ata, u.lp_ata, amount);
    send(&mut w.svm, &payer, &[&u.kp], ix).expect("Deposit (senior)");
    w.svm.expire_blockhash();
}

fn deposit_junior(w: &mut World, u: &User, amount: u64) {
    let payer = w.payer.insecure_clone();
    let ix = deposit_junior_ix(&w.c, &u.kp.pubkey(), u.ata, u.lp_ata, amount);
    send(&mut w.svm, &payer, &[&u.kp], ix).expect("DepositJunior");
    w.svm.expire_blockhash();
}

/// Burns the user's WHOLE LP balance; returns the collateral the vault paid out.
fn withdraw_all(w: &mut World, u: &User) -> u64 {
    let payer = w.payer.insecure_clone();
    let lp = token_amount(&w.svm, &u.lp_ata);
    assert!(lp > 0, "user holds LP");
    let before = token_amount(&w.svm, &u.ata);
    let slot = w.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    w.svm.warp_to_slot(slot + COOLDOWN_SLOTS + 1); // past the deposit cooldown
    let ix = withdraw_ix(&w.c, &u.kp.pubkey(), u.ata, u.lp_ata, lp);
    send(&mut w.svm, &payer, &[&u.kp], ix).expect("Withdraw");
    w.svm.expire_blockhash();
    assert_eq!(token_amount(&w.svm, &u.lp_ata), 0, "all LP burned");
    token_amount(&w.svm, &u.ata) - before
}

/// A real SPL transfer of `amount` into the pool vault, then the real AccrueFees, which
/// books the surplus as fees and splits it junior/senior (PERC-303 `distribute_fees`).
fn donate_and_accrue(w: &mut World, donor: &User, amount: u64) {
    let payer = w.payer.insecure_clone();
    let t = spl_transfer_ix(&w.c, donor.ata, w.c.vault, &donor.kp.pubkey(), amount);
    let a = accrue_fees_ix(&w.c, &donor.kp.pubkey());
    send_batch(&mut w.svm, &payer, &[&donor.kp], vec![t, a]).expect("donate + AccrueFees");
    w.svm.expire_blockhash();
}

fn pool(w: &World) -> StakePool {
    read_pool(&w.svm, &w.c.pool_pda)
}

/// The vault's real token balance always equals the pool's booked value (mode 1, no
/// flush): nothing is created or destroyed by any step below.
fn assert_vault_matches_books(w: &World) {
    let p = pool(w);
    assert_eq!(
        token_amount(&w.svm, &w.c.vault),
        p.total_pool_value().unwrap(),
        "vault balance == total_pool_value()"
    );
}

/// Builds: senior genesis 2,000 -> first junior deposits `MINIMUM_LIQUIDITY + 1` (1 real
/// junior LP; since NEW-1 the other 1,000 are dead junior shares) -> a real donation +
/// AccrueFees books fee income to both tranches. Returns (world, junior user).
fn one_real_lp_junior_with_fees(fee: u64) -> (World, User) {
    let mut w = world();
    let sen = new_user(&mut w, SENIOR_GENESIS);
    deposit_senior(&mut w, &sen, SENIOR_GENESIS);
    let first = percolator_stake::state::MINIMUM_LIQUIDITY + 1;
    let jun = new_user(&mut w, first);
    deposit_junior(&mut w, &jun, first);
    let p = pool(&w);
    assert_eq!(
        p.junior_total_lp(),
        first,
        "junior supply counts the dead shares"
    );
    assert_eq!(token_amount(&w.svm, &jun.lp_ata), 1, "one real junior LP");

    let donor = new_user(&mut w, fee);
    donate_and_accrue(&mut w, &donor, fee);
    assert_vault_matches_books(&w);
    (w, jun)
}

// ── tests ────────────────────────────────────────────────────────────────────

/// The original repro (9942a2c) reached `ejb = 1000, jlp = 1` with a 1-atom first junior
/// and showed the last junior paid 500 with senior +500. Since the NEW-1 junior dead-share
/// floor that state is unreachable: junior supply never drops below MINIMUM_LIQUIDITY, so
/// the last REAL junior's burn is a partial burn priced by the N7 formula, and its rounding
/// remainder stays in the junior tranche (held by the dead shares). Senior never gains.
#[test]
fn last_real_junior_exit_never_windfalls_senior() {
    let (mut w, jun) = one_real_lp_junior_with_fees(9_991_000);
    let p = pool(&w);
    let (ejb, jlp) = (p.effective_junior_balance(), p.junior_total_lp());
    assert!(ejb > jlp, "junior earned fees (ejb {ejb} > jlp {jlp})");
    let senior_before = p.senior_balance().unwrap();
    let expect = percolator_stake::math::calc_collateral_for_withdraw(jlp, ejb, 1).unwrap();

    let paid = withdraw_all(&mut w, &jun);
    let p = pool(&w);
    println!(
        "last real junior: ejb={ejb} jlp={jlp} paid={paid}; junior left {} on {} dead shares; \
         senior {senior_before} -> {}",
        p.junior_balance(),
        p.junior_total_lp(),
        p.senior_balance().unwrap()
    );
    assert_eq!(paid, expect, "a partial burn: N7 formula");
    assert_eq!(
        p.junior_total_lp(),
        percolator_stake::state::MINIMUM_LIQUIDITY
    );
    assert_eq!(p.junior_balance(), ejb - paid, "remainder stays junior");
    assert_eq!(
        p.senior_balance().unwrap(),
        senior_before,
        "senior gains nothing"
    );
    assert_vault_matches_books(&w);
}

/// Two real juniors exit; every payout is the N7 formula, the junior tranche keeps the
/// remainder on its dead shares, and senior is flat across both exits.
#[test]
fn junior_exits_conserve_junior_value_and_leave_senior_flat() {
    let (mut w, a) = one_real_lp_junior_with_fees(9_991_000);
    let b = new_user(&mut w, 25_000);
    deposit_junior(&mut w, &b, 25_000); // ~5,000/LP -> 5 LP
    let p = pool(&w);
    let (jlp, ejb) = (p.junior_total_lp(), p.effective_junior_balance());
    let b_lp = token_amount(&w.svm, &b.lp_ata);
    let senior_before = p.senior_balance().unwrap();

    let expect_b = percolator_stake::math::calc_collateral_for_withdraw(jlp, ejb, b_lp).unwrap();
    let paid_b = withdraw_all(&mut w, &b);
    assert_eq!(paid_b, expect_b);
    let paid_a = withdraw_all(&mut w, &a);
    let p = pool(&w);
    assert_eq!(
        paid_a + paid_b + p.junior_balance(),
        ejb,
        "junior value conserved"
    );
    assert_eq!(p.senior_balance().unwrap(), senior_before, "senior flat");
    assert_vault_matches_books(&w);
}

// ── NEW-1: junior sub-pool share inflation (security review of 9942a2c) ─────────
//
// When a tranche pool's genesis deposit is SENIOR, the N7 MINIMUM_LIQUIDITY lock went to
// the senior side and the junior sub-pool started with no dead shares. A first junior
// with 1 LP pumps the junior share price (donation + AccrueFees, mode 1), a victim's
// junior deposit rounds down by up to one share price, and the attacker collects it.
// Fix: the first deposit into an EMPTY junior sub-pool locks MINIMUM_LIQUIDITY dead
// junior shares, exactly as the pool-genesis deposit does.

/// `StakeError::DepositBelowMinimumLiquidity`.
const ERR_DEPOSIT_BELOW_MIN_LIQUIDITY: u32 = 28;

fn custom_code(err: &litesvm::types::FailedTransactionMetadata) -> Option<u32> {
    match err.err {
        TransactionError::InstructionError(_, InstructionError::Custom(c)) => Some(c),
        _ => None,
    }
}

struct AttackOutcome {
    attacker_net: i128,
    victim_in: u64,
    victim_out: u64,
    /// One junior share price, rounded up, when the victim deposited.
    price_at_victim: u64,
    attacker_entry: u64,
    rounds: u32,
}

/// The reviewer's attack, on real instructions. `own_senior`: the attacker also funds the
/// senior genesis `g` (and withdraws it at the end); otherwise `g` is an honest senior.
/// The attacker enters the junior sub-pool as cheaply as the program allows (1 atom; if
/// that is refused as below the dead-share floor, `MINIMUM_LIQUIDITY + 1`), donates the
/// whole pool value each round and cranks AccrueFees until the junior tranche holds
/// `target`, then a victim deposits `ejb` into the junior tranche, the victim exits, and
/// the attacker exits.
fn run_attack(mult: u16, own_senior: bool, g: u64, target: u64) -> AttackOutcome {
    let mut w = world_mult(mult);
    let payer = w.payer.insecure_clone();
    let sen = new_user(&mut w, g);
    deposit_senior(&mut w, &sen, g);

    let floor = percolator_stake::state::MINIMUM_LIQUIDITY + 1;
    let att = new_user(&mut w, floor);
    let ix = deposit_junior_ix(&w.c, &att.kp.pubkey(), att.ata, att.lp_ata, 1);
    let attacker_entry = match send(&mut w.svm, &payer, &[&att.kp], ix) {
        Ok(()) => 1,
        Err(e) => {
            assert_eq!(
                custom_code(&e),
                Some(ERR_DEPOSIT_BELOW_MIN_LIQUIDITY),
                "a 1-atom first junior deposit is refused only by the dead-share floor"
            );
            w.svm.expire_blockhash();
            deposit_junior(&mut w, &att, floor);
            floor
        }
    };
    w.svm.expire_blockhash();

    let donor = new_user(&mut w, 1u64 << 62);
    let mut donated: u128 = 0;
    let mut rounds = 0;
    while pool(&w).effective_junior_balance() < target {
        let p = pool(&w);
        let d = p.senior_balance().unwrap() + p.effective_junior_balance();
        donate_and_accrue(&mut w, &donor, d);
        donated += d as u128;
        rounds += 1;
        assert!(rounds < 80, "pump did not converge");
    }
    assert_vault_matches_books(&w);

    let p = pool(&w);
    let ejb = p.effective_junior_balance();
    let price_at_victim = (ejb + 1).div_ceil(p.junior_total_lp() + 1);
    let victim_in = ejb;
    let victim = new_user(&mut w, victim_in);
    deposit_junior(&mut w, &victim, victim_in);
    let victim_out = withdraw_all(&mut w, &victim);
    let a_out = withdraw_all(&mut w, &att);

    let mut a_in = attacker_entry as i128 + donated as i128;
    let mut a_got = a_out as i128;
    if own_senior {
        a_in += g as i128;
        a_got += withdraw_all(&mut w, &sen) as i128;
    }
    assert_vault_matches_books(&w);
    AttackOutcome {
        attacker_net: a_got - a_in,
        victim_in,
        victim_out,
        price_at_victim,
        attacker_entry,
        rounds,
    }
}

fn assert_attack_fails(o: &AttackOutcome, label: &str) {
    let victim_loss = o.victim_in.saturating_sub(o.victim_out);
    println!(
        "NEW-1 {label}: entry {} rounds {} | attacker net {} | victim in {} out {} (loss {}, \
         share price {})",
        o.attacker_entry,
        o.rounds,
        o.attacker_net,
        o.victim_in,
        o.victim_out,
        victim_loss,
        o.price_at_victim
    );
    assert!(
        o.attacker_net < 0,
        "{label}: the inflation attack must lose money"
    );
    // Rounding bound: under one share price on the deposit, under one on the withdraw.
    assert!(
        victim_loss <= 2 * o.price_at_victim,
        "{label}: victim loss {victim_loss} > 2 share prices ({})",
        o.price_at_victim
    );
}

/// Reviewer's main setup: 5x junior multiplier, attacker funds the senior side (1e6).
#[test]
fn new1_inflation_attacker_funded_senior_loses() {
    let o = run_attack(50_000, true, 1_000_000, 1_000_000_000);
    assert_attack_fails(&o, "5x, attacker senior 1e6, target 1e9");
}

/// Honest small senior (2,000): the case where 9942a2c alone turned a loss into a profit.
#[test]
fn new1_inflation_honest_small_senior_loses() {
    let o = run_attack(50_000, false, 2_000, 1_000_000_000);
    assert_attack_fails(&o, "5x, honest senior 2000, target 1e9");
}

/// The junior dead-share floor: a pool with a senior genesis still locks MINIMUM_LIQUIDITY
/// junior shares on the first junior deposit, they stay in `junior_total_lp` for good,
/// and so a real burn can never take the junior supply to 0.
#[test]
fn new1_first_junior_deposit_locks_dead_junior_shares() {
    let mut w = world();
    let sen = new_user(&mut w, SENIOR_GENESIS);
    deposit_senior(&mut w, &sen, SENIOR_GENESIS);
    let total_before = pool(&w).total_lp_supply;
    let senior_lp_before = pool(&w).senior_total_lp();

    let floor = percolator_stake::state::MINIMUM_LIQUIDITY;
    let small = new_user(&mut w, floor);
    let payer = w.payer.insecure_clone();
    let ix = deposit_junior_ix(&w.c, &small.kp.pubkey(), small.ata, small.lp_ata, floor);
    let err = send(&mut w.svm, &payer, &[&small.kp], ix).expect_err("at the floor");
    assert_eq!(custom_code(&err), Some(ERR_DEPOSIT_BELOW_MIN_LIQUIDITY));
    w.svm.expire_blockhash();

    let j = new_user(&mut w, 5_000);
    deposit_junior(&mut w, &j, 5_000);
    let p = pool(&w);
    assert_eq!(
        p.junior_total_lp(),
        5_000,
        "full amount counted in junior supply"
    );
    assert_eq!(
        token_amount(&w.svm, &j.lp_ata),
        5_000 - floor,
        "dead shares not minted"
    );
    assert_eq!(p.total_lp_supply, total_before + 5_000);
    assert_eq!(
        p.senior_total_lp(),
        senior_lp_before,
        "senior supply untouched"
    );

    // A second junior is priced normally (no second lock).
    let j2 = new_user(&mut w, 3_000);
    deposit_junior(&mut w, &j2, 3_000);
    assert_eq!(
        token_amount(&w.svm, &j2.lp_ata),
        3_000,
        "N7 pro-rata at 1:1 (3000 * 5001 / 5001), no extra lock"
    );

    withdraw_all(&mut w, &j2);
    withdraw_all(&mut w, &j);
    let p = pool(&w);
    assert_eq!(
        p.junior_total_lp(),
        floor,
        "dead junior shares survive every real exit"
    );
    assert!(p.junior_balance() > 0, "and keep their (tiny) junior value");
    assert_vault_matches_books(&w);
}

/// NEW-1 mirror: junior genesis, then the first SENIOR deposit locks the senior
/// sub-pool's own dead shares (it used to start 1:1 with none).
#[test]
fn new1_first_senior_after_junior_genesis_locks_dead_senior_shares() {
    let mut w = world();
    let floor = percolator_stake::state::MINIMUM_LIQUIDITY;
    let j = new_user(&mut w, 5_000);
    deposit_junior(&mut w, &j, 5_000);
    let p = pool(&w);
    assert_eq!((p.junior_total_lp(), p.senior_total_lp()), (5_000, 0));
    assert_eq!(
        token_amount(&w.svm, &j.lp_ata),
        5_000 - floor,
        "junior genesis lock"
    );

    let s = new_user(&mut w, 3_000);
    deposit_senior(&mut w, &s, 3_000);
    let p = pool(&w);
    assert_eq!(
        p.senior_total_lp(),
        3_000,
        "full amount counted in senior supply"
    );
    assert_eq!(
        token_amount(&w.svm, &s.lp_ata),
        3_000 - floor,
        "dead senior shares not minted"
    );
    assert_eq!(p.junior_total_lp(), 5_000, "junior supply untouched");
    withdraw_all(&mut w, &s);
    assert_eq!(
        pool(&w).senior_total_lp(),
        floor,
        "dead senior shares survive the exit"
    );
    assert_vault_matches_books(&w);
}

// ── R-1: real-holder detection must count one floor PER SUB-POOL (review of b83ddf9) ──
//
// Since NEW-1 a tranche pool can hold two dead-share floors (senior + junior), so
// `total_lp_supply > MINIMUM_LIQUIDITY` no longer means "a real LP exists". Every fee
// gate (AccrueFees F3 refusal, the deposit/withdraw pre-accrue, F-9 terminal recovery)
// and the junior/senior fee split must use the per-sub-pool real supply.

/// `StakeError::NoRealLpHolders`.
const ERR_NO_REAL_LP_HOLDERS: u32 = 29;

fn try_donate_and_accrue(
    w: &mut World,
    donor: &User,
    amount: u64,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let payer = w.payer.insecure_clone();
    let t = spl_transfer_ix(&w.c, donor.ata, w.c.vault, &donor.kp.pubkey(), amount);
    let a = accrue_fees_ix(&w.c, &donor.kp.pubkey());
    let r = send_batch(&mut w.svm, &payer, &[&donor.kp], vec![t, a]);
    w.svm.expire_blockhash();
    r
}

/// Reviewer's repro: senior 2,000 + junior 5,000, everyone exits -> 2,000 dead LP
/// (1,000 per sub-pool). A donation + AccrueFees must be refused (29), exactly as the
/// single-floor pool is on 9185fdd, and nothing booked.
#[test]
fn r1_dead_only_tranche_pool_refuses_accrue() {
    let mut w = world();
    let s = new_user(&mut w, SENIOR_GENESIS);
    deposit_senior(&mut w, &s, SENIOR_GENESIS);
    let j = new_user(&mut w, 5_000);
    deposit_junior(&mut w, &j, 5_000);
    withdraw_all(&mut w, &j);
    withdraw_all(&mut w, &s);
    let p = pool(&w);
    let floor = percolator_stake::state::MINIMUM_LIQUIDITY;
    assert_eq!(
        (p.total_lp_supply, p.junior_total_lp(), p.senior_total_lp()),
        (2 * floor, floor, floor)
    );
    let fees_before = p.total_fees_earned;

    let donor = new_user(&mut w, 1_000_000);
    let err = try_donate_and_accrue(&mut w, &donor, 1_000_000).expect_err("dead-only pool");
    assert_eq!(custom_code(&err), Some(ERR_NO_REAL_LP_HOLDERS));
    assert_eq!(pool(&w).total_fees_earned, fees_before, "nothing booked");
}

/// A junior sub-pool holding only its dead shares takes no share of fees: everything
/// goes to the senior sub-pool, whose real holders exist.
#[test]
fn r1_dead_only_junior_gets_no_fee_share() {
    let mut w = world();
    let s = new_user(&mut w, 100_000);
    deposit_senior(&mut w, &s, 100_000);
    let j = new_user(&mut w, 5_000);
    deposit_junior(&mut w, &j, 5_000);
    withdraw_all(&mut w, &j);
    let p = pool(&w);
    assert_eq!(
        p.junior_total_lp(),
        percolator_stake::state::MINIMUM_LIQUIDITY
    );
    let (jb_before, sb_before) = (p.junior_balance(), p.senior_balance().unwrap());

    let donor = new_user(&mut w, 1_000_000);
    donate_and_accrue(&mut w, &donor, 1_000_000);
    let p = pool(&w);
    assert_eq!(
        p.junior_balance(),
        jb_before,
        "dead-only junior booked no fee"
    );
    assert_eq!(
        p.senior_balance().unwrap(),
        sb_before + 1_000_000,
        "all fee to senior"
    );
    assert_vault_matches_books(&w);
}

/// Mirror: junior genesis, a senior enters and leaves -> senior holds only its dead
/// floor; every fee goes to the junior sub-pool.
#[test]
fn r1_dead_only_senior_gets_no_fee_share() {
    let mut w = world();
    let j = new_user(&mut w, 100_000);
    deposit_junior(&mut w, &j, 100_000);
    let s = new_user(&mut w, 5_000);
    deposit_senior(&mut w, &s, 5_000);
    withdraw_all(&mut w, &s);
    let p = pool(&w);
    assert_eq!(
        p.senior_total_lp(),
        percolator_stake::state::MINIMUM_LIQUIDITY
    );
    let (jb_before, sb_before) = (p.junior_balance(), p.senior_balance().unwrap());

    let donor = new_user(&mut w, 1_000_000);
    donate_and_accrue(&mut w, &donor, 1_000_000);
    let p = pool(&w);
    assert_eq!(
        p.senior_balance().unwrap(),
        sb_before,
        "dead-only senior booked no fee"
    );
    assert_eq!(
        p.junior_balance(),
        jb_before + 1_000_000,
        "all fee to junior"
    );
    assert_vault_matches_books(&w);
}

/// Non-tranche pool that turns tranches on after deposits: its genesis floor sits in
/// the senior supply, the first junior adds one junior floor; once every real staker is
/// out the pool is dead-only and refuses AccrueFees.
#[test]
fn r1_tranches_enabled_later_counts_both_floors() {
    let mut w = world_untranched();
    let s = new_user(&mut w, SENIOR_GENESIS);
    deposit_senior(&mut w, &s, SENIOR_GENESIS);
    enable_tranches(&mut w);
    let j = new_user(&mut w, 5_000);
    deposit_junior(&mut w, &j, 5_000);
    withdraw_all(&mut w, &j);
    withdraw_all(&mut w, &s);
    let floor = percolator_stake::state::MINIMUM_LIQUIDITY;
    let p = pool(&w);
    assert_eq!((p.senior_total_lp(), p.junior_total_lp()), (floor, floor));
    let donor = new_user(&mut w, 1_000);
    let err = try_donate_and_accrue(&mut w, &donor, 1_000).expect_err("dead-only pool");
    assert_eq!(custom_code(&err), Some(ERR_NO_REAL_LP_HOLDERS));
}

/// The #127 multiplier lock follows REAL junior LP: once every real junior is out
/// (only the dead floor left, which takes no fee share), the admin may change it.
#[test]
fn r1_multiplier_unlocks_when_only_dead_junior_shares_remain() {
    let mut w = world();
    let s = new_user(&mut w, SENIOR_GENESIS);
    deposit_senior(&mut w, &s, SENIOR_GENESIS);
    let j = new_user(&mut w, 5_000);
    deposit_junior(&mut w, &j, 5_000);
    let payer = w.payer.insecure_clone();
    let admin = w.admin.insecure_clone();
    let ix = set_tranche_config_ix(&w.c, &admin.pubkey(), 30_000);
    send(&mut w.svm, &payer, &[&admin], ix).expect_err("locked while a real junior exists");
    w.svm.expire_blockhash();
    withdraw_all(&mut w, &j);
    let ix = set_tranche_config_ix(&w.c, &admin.pubkey(), 30_000);
    send(&mut w.svm, &payer, &[&admin], ix).expect("free again with only dead junior LP");
    assert_eq!(pool(&w).junior_fee_mult_bps(), 30_000);
}
