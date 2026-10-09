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
    payer: Keypair,
}

/// Real InitMarket -> real InitTradingPool (mode 1) -> real AdminSetTrancheConfig.
fn world() -> World {
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
    send(
        &mut svm,
        &payer,
        &[&admin],
        set_tranche_config_ix(&c, &admin.pubkey(), JUNIOR_MULT_BPS),
    )
    .expect("AdminSetTrancheConfig");
    svm.expire_blockhash();

    let p = read_pool(&svm, &pool_pda);
    assert_eq!(p.pool_mode, 1, "trading pool");
    assert!(p.tranche_enabled(), "tranches on");
    World { svm, c, payer }
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

/// Builds: senior genesis 2,000 -> junior deposits 1 atom (junior LP = 1) -> fees booked
/// until the junior tranche holds ~1,000 (the Kani counterexample's `jb0 = 1000, jlp = 1`).
/// Returns (world, junior user).
fn one_lp_junior_worth_1000(fee: u64) -> (World, User) {
    let mut w = world();
    let sen = new_user(&mut w, SENIOR_GENESIS);
    deposit_senior(&mut w, &sen, SENIOR_GENESIS);
    let jun = new_user(&mut w, 1);
    deposit_junior(&mut w, &jun, 1);
    let p = pool(&w);
    assert_eq!(p.junior_total_lp(), 1, "junior LP supply is one share");
    assert_eq!(p.junior_balance(), 1);

    let donor = new_user(&mut w, fee);
    donate_and_accrue(&mut w, &donor, fee);
    assert_vault_matches_books(&w);
    (w, jun)
}

// ── tests ────────────────────────────────────────────────────────────────────

/// The repro. Junior weight 1 * 20_000 vs senior 2_000 * 10_000 = 1/1001 of each fee, so a
/// 999,999 fee books 999 to junior: `ejb = 1000`, `jlp = 1`. Burning the single junior LP
/// must pay all 1,000 and leave senior exactly where it was. Pre-fix: pays
/// `1 * (1000 + 1) / (1 + 1) = 500`, and senior_balance jumps by 500.
#[test]
fn last_junior_exit_pays_the_whole_junior_balance() {
    let (mut w, jun) = one_lp_junior_worth_1000(999_999);
    let p = pool(&w);
    let ejb = p.effective_junior_balance();
    let jlp = p.junior_total_lp();
    assert_eq!(
        (ejb, jlp),
        (1_000, 1),
        "the Kani counterexample state, reached for real"
    );
    let senior_before = p.senior_balance().unwrap();
    let pre_fix_payout =
        percolator_stake::math::calc_collateral_for_withdraw(jlp, ejb, jlp).unwrap();
    assert_eq!(pre_fix_payout, 500, "the plain N7 formula on a full burn");

    let paid = withdraw_all(&mut w, &jun);
    let p = pool(&w);
    let senior_after = p.senior_balance().unwrap();
    println!(
        "last junior: ejb={ejb} jlp={jlp} paid={paid} (N7 formula {pre_fix_payout}); \
         senior {senior_before} -> {senior_after}"
    );
    assert_eq!(
        paid, ejb,
        "last junior must receive the whole effective junior balance"
    );
    assert_eq!(
        senior_after, senior_before,
        "senior must not gain the junior's residual"
    );
    assert_eq!(p.junior_total_lp(), 0);
    assert_eq!(p.junior_balance(), 0);
    assert_vault_matches_books(&w);
}

/// Non-last junior exits are untouched: with two juniors, the first to leave is still
/// priced by the N7 formula (it does NOT burn the whole junior supply), and only the
/// last one picks up the rounding remainder — which is junior money either way.
/// Across both exits the junior tranche pays out exactly its value and senior is flat.
#[test]
fn only_the_full_supply_burn_changes() {
    let (mut w, a) = one_lp_junior_worth_1000(999_999);
    // B buys in at the junior price (~1000/LP): 2_500 * 2 / 1_001 = 4 LP (rounds down).
    let b = new_user(&mut w, 2_500);
    deposit_junior(&mut w, &b, 2_500);
    let p = pool(&w);
    let (jlp, ejb) = (p.junior_total_lp(), p.effective_junior_balance());
    let b_lp = token_amount(&w.svm, &b.lp_ata);
    assert_eq!(jlp, 1 + b_lp);
    let senior_before = p.senior_balance().unwrap();

    let expect_b = percolator_stake::math::calc_collateral_for_withdraw(jlp, ejb, b_lp).unwrap();
    let paid_b = withdraw_all(&mut w, &b);
    assert_eq!(
        paid_b, expect_b,
        "a partial junior burn keeps the N7 formula"
    );
    let left = pool(&w).effective_junior_balance();
    let paid_a = withdraw_all(&mut w, &a);
    assert_eq!(
        paid_a, left,
        "the last junior takes what is left of the junior tranche"
    );
    assert_eq!(
        paid_a + paid_b,
        ejb,
        "junior tranche paid out exactly its value"
    );
    assert_eq!(
        pool(&w).senior_balance().unwrap(),
        senior_before,
        "senior flat"
    );
    assert_vault_matches_books(&w);
}

/// Inflation / donation check. The N7 offsets exist so a donation that pumps a tiny
/// share's price cannot be recovered for free. Here the attacker A is a 1-LP junior who
/// pumps the junior price with a donation (booked as fees), victim V buys in, V leaves,
/// then A leaves LAST and (with the fix) collects the whole junior remainder.
///
/// What the fix must NOT allow, asserted below:
/// - paying any junior more than the junior tranche holds (sum of junior payouts ==
///   junior value; vault == books);
/// - touching senior (senior_balance unchanged across both junior exits);
/// - a profitable attack: A's gain on the junior side is bounded by V's rounding loss,
///   which is under one junior share price per V operation, while the donation that
///   created that price is split by `distribute_fees` and ~1000/1001 of it is booked to
///   senior, unrecoverable by A. A's net is deeply negative.
#[test]
fn donation_pumped_one_lp_junior_cannot_profit() {
    let fee = 999_999;
    let (mut w, attacker) = one_lp_junior_worth_1000(fee);
    let price_before_v = {
        let p = pool(&w);
        (p.effective_junior_balance() + 1).div_ceil(p.junior_total_lp() + 1)
    };
    let senior_start = pool(&w).senior_balance().unwrap();

    let v_in = 1_500;
    let victim = new_user(&mut w, v_in);
    deposit_junior(&mut w, &victim, v_in);
    let junior_value = pool(&w).effective_junior_balance();
    let v_out = withdraw_all(&mut w, &victim);
    let a_out = withdraw_all(&mut w, &attacker);
    let p = pool(&w);

    let v_loss = v_in - v_out;
    let a_cost = 1 + fee; // A's junior deposit + its donation
    println!(
        "inflation: price~{price_before_v}/LP; victim in {v_in} out {v_out} (loss {v_loss}); \
         attacker cost {a_cost} out {a_out}; senior {senior_start} -> {}",
        p.senior_balance().unwrap()
    );
    assert_eq!(
        a_out + v_out,
        junior_value,
        "junior payouts == junior tranche value"
    );
    assert_eq!(
        p.senior_balance().unwrap(),
        senior_start,
        "senior untouched"
    );
    assert_eq!((p.junior_total_lp(), p.junior_balance()), (0, 0));
    assert_vault_matches_books(&w);
    // A's junior-side gain over the value booked to its share is exactly V's loss.
    assert_eq!(a_out, 1_000 + v_loss);
    assert!(
        v_loss < 2 * price_before_v,
        "V loses under one share price per operation"
    );
    assert!(
        a_out < a_cost / 100,
        "the donation is not recoverable: attacker nets a loss"
    );
}
