//! AUD-S2-3 (full audit 2026-10-17; security review 2026-10-14 M-3 / M-4 / L-4), reproduced on
//! the REAL stake .so + the REAL wrapper .so under LiteSVM. Nothing is forged except SPL token
//! balances used as funding and, for M-3 only, the recorded seed (same helper shape as
//! `f9_terminal_insurance_recovery_e2e.rs::forge_seed`, to create "growth above the seed"
//! without a fee-generating trade history).
//!
//! * M-4: a third party appends asset 1 (wrapper tag 40, permissionless only while the market's
//!   `permissionless_market_init_fee != 0`) and the v5 bind refuses 48 forever. The fee can only be
//!   set by `marketauth` (wrapper tag 59), and InitPool hands `marketauth` to the pool PDA, which
//!   proxies neither tag 59 nor tag 40. So the window is "fee set before InitPool".
//! * L-4: once a position exists, any accrual that moves K/F marks the whole side stale and the
//!   v5 bind refuses 44 until every positioned account has been touched.
//! * M-3: a just-in-time deposit before the resolve shares the close-out growth pro rata.
//!
//! The wrapper .so defaults to `../percolator-prog/target/deploy/percolator_prog.so`
//! (`F9_WRAPPER_SO` overrides); the stake .so to `target/deploy/percolator_stake.so`
//! (`E2E_STAKE_SO`), loaded at `E2E_STAKE_ID`.

#![allow(clippy::result_large_err, clippy::too_many_arguments)]

use litesvm::LiteSVM;
use percolator_stake::state::{
    derive_deposit_pda, derive_pool_pda, derive_vault_authority, StakePool, STAKE_POOL_SIZE,
};
use percolator_stake::wrapper_layout as wl;
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
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const MARKET_LEN_V18_CAP1: usize = 4059;
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;
const BUDGET: u64 = 5_000_000;
const STAKE: u64 = 10_000_000;
const PRICE: u64 = 100;

// Wrapper portfolio layout (v2.2, `PORTFOLIO_ACCOUNT_LEN == 10603` const-asserted in the wrapper):
// ... matcher config (104 B, control word at +96) | portfolio_id u64 | matcher_sequence u64 | expiry u64.
const PORTFOLIO_LEN: usize = 10_603;
const PORTFOLIO_ID_OFF: usize = PORTFOLIO_LEN - 24;
const PORTFOLIO_SEQ_OFF: usize = PORTFOLIO_LEN - 16;
const PORTFOLIO_CONTROL_OFF: usize = PORTFOLIO_LEN - 24 - 104 + 96;
/// Wrapper `AssetControlSequencesV16` of asset 0 (profile +512): oracle_observation is lane 0.
const ASSET0_ORACLE_OBS_SEQ_OFF: usize = wl::ASSET0_WRAPPER_START + wl::ASSET_CONTROL_SEQUENCES_OFF;
/// ... and market_init_fee is lane 7.
const ASSET0_MARKET_INIT_FEE_SEQ_OFF: usize = ASSET0_ORACLE_OBS_SEQ_OFF + 7 * 8;
/// Wrapper config `permissionless_market_init_fee` (u128): header 16 + 3 x 32 + maintenance u128.
const MARKET_PERMISSIONLESS_INIT_FEE_OFF: usize = 16 + 96 + 16;

const E_MULTI_ASSET_NOT_SUPPORTED: u32 = 48;
const E_INSURANCE_READINGS_DIVERGED: u32 = 44;
/// Wrapper `Unauthorized`.
const W_UNAUTHORIZED: u32 = 8;

fn stake_id_str() -> String {
    std::env::var("E2E_STAKE_ID")
        .unwrap_or_else(|_| "A6DVNubvzMMETQinK6bipekkaTTrkUu2RMw2kBoJrdkE".to_string())
}

fn stake_so() -> PathBuf {
    if let Ok(p) = std::env::var("E2E_STAKE_SO") {
        return PathBuf::from(p);
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_stake.so");
    p
}

fn wrapper_so() -> PathBuf {
    if let Ok(p) = std::env::var("F9_WRAPPER_SO") {
        return PathBuf::from(p);
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("percolator-prog/target/deploy/percolator_prog.so");
    p
}

fn mint_data() -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[45] = 1; // is_initialized, decimals 0, no authorities (same as the f9 suite)
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
    svm.set_account(
        key,
        Account {
            lamports: 1_000_000_000,
            data: token_data(mint, owner, amount),
            owner: Pubkey::from_str(TOKEN_PROGRAM).unwrap(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn token_amount(svm: &LiteSVM, key: &Pubkey) -> u64 {
    let d = svm.get_account(key).unwrap().data;
    u64::from_le_bytes(d[64..72].try_into().unwrap())
}

fn canonical_vault_ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    let ata_program = Pubkey::from_str(ATA_PROGRAM).unwrap();
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ata_program,
    )
    .0
}

/// The same 219-byte legacy InitMarket the f9 suite sends (max_portfolio_assets = 1,
/// initial_price 100, max_accrual_dt_slots 1, no funding).
fn encode_init_market_v17() -> Vec<u8> {
    let mut out = Vec::with_capacity(219);
    out.push(0u8);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&10u64.to_le_bytes());
    out.extend_from_slice(&PRICE.to_le_bytes());
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
    assert_eq!(out.len(), 219);
    out
}

type TxResult = Result<(), litesvm::types::FailedTransactionMetadata>;

fn send_ixs(svm: &mut LiteSVM, payer: &Keypair, signers: &[&Keypair], ixs: Vec<Instruction>) -> TxResult {
    let mut all: Vec<&Keypair> = vec![payer];
    all.extend_from_slice(signers);
    svm.expire_blockhash();
    let mut v = vec![
        solana_sdk::compute_budget::ComputeBudgetInstruction::request_heap_frame(128 * 1024),
        solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
    ];
    v.extend(ixs);
    let tx = Transaction::new_signed_with_payer(&v, Some(&payer.pubkey()), &all, svm.latest_blockhash());
    svm.send_transaction(tx).map(|_| ())
}

fn custom(r: &TxResult) -> Option<u32> {
    match r {
        Err(e) => match &e.err {
            TransactionError::InstructionError(_, InstructionError::Custom(c)) => Some(*c),
            _ => None,
        },
        Ok(()) => None,
    }
}

fn logs(r: &TxResult) -> String {
    match r {
        Err(e) => format!("{:?}\n{}", e.err, e.meta.logs.join("\n")),
        Ok(()) => "Ok".into(),
    }
}

fn rd_u64(svm: &LiteSVM, key: &Pubkey, off: usize) -> u64 {
    let d = svm.get_account(key).unwrap().data;
    u64::from_le_bytes(d[off..off + 8].try_into().unwrap())
}

fn rd_u128(svm: &LiteSVM, key: &Pubkey, off: usize) -> u128 {
    let d = svm.get_account(key).unwrap().data;
    u128::from_le_bytes(d[off..off + 16].try_into().unwrap())
}

fn rd_u32(svm: &LiteSVM, key: &Pubkey, off: usize) -> u32 {
    let d = svm.get_account(key).unwrap().data;
    u32::from_le_bytes(d[off..off + 4].try_into().unwrap())
}

fn read_pool(svm: &LiteSVM, pool: &Pubkey) -> StakePool {
    let d = svm.get_account(pool).unwrap().data;
    *bytemuck::from_bytes::<StakePool>(&d[..STAKE_POOL_SIZE])
}

struct World {
    svm: LiteSVM,
    stake_id: Pubkey,
    wrapper_id: Pubkey,
    admin: Keypair,
    payer: Keypair,
    market: Pubkey,
    mint: Pubkey,
    wrapper_vault: Pubkey,
    wrapper_vault_auth: Pubkey,
    pool: Pubkey,
    vault_auth: Pubkey,
    vault: Pubkey,
    lp_mint: Pubkey,
    creator_ata: Pubkey,
    obs_seq: u64,
}

struct Staker {
    kp: Keypair,
    ata: Pubkey,
    lp_ata: Pubkey,
}

/// InitMarket (admin = marketauth = every asset-0 authority) + admin TopUpInsurance `BUDGET`.
/// No pool yet.
fn market_only() -> World {
    let (so, wso) = (stake_so(), wrapper_so());
    assert!(
        so.exists() && wso.exists(),
        "MISSING ARTIFACT (hard failure, never a skip): stake={} wrapper={}",
        so.display(),
        wso.display()
    );
    let mut svm = LiteSVM::new().with_spl_programs();
    svm.warp_to_slot(1_000);
    let stake_id = Pubkey::from_str(&stake_id_str()).unwrap();
    let wrapper_id = Pubkey::from_str(WRAPPER_MAINNET).unwrap();
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    svm.add_program_from_file(stake_id, &so).unwrap();
    svm.add_program_from_file(wrapper_id, &wso).unwrap();
    let admin = Keypair::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.airdrop(&admin.pubkey(), 20_000_000_000).unwrap();
    let market = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    svm.set_account(
        mint,
        Account { lamports: 1_000_000_000, data: mint_data(), owner: token_program, executable: false, rent_epoch: 0 },
    )
    .unwrap();
    let wrapper_vault_auth = Pubkey::find_program_address(&[b"vault", market.as_ref()], &wrapper_id).0;
    let wrapper_vault = canonical_vault_ata(&wrapper_vault_auth, &mint);
    set_token_account(&mut svm, wrapper_vault, &mint, &wrapper_vault_auth, 0);
    svm.set_account(
        market,
        Account {
            lamports: 1_000_000_000,
            data: vec![0u8; MARKET_LEN_V18_CAP1],
            owner: wrapper_id,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    let ix = Instruction {
        program_id: wrapper_id,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
            AccountMeta::new_readonly(mint, false),
        ],
        data: encode_init_market_v17(),
    };
    let r = send_ixs(&mut svm, &payer, &[&admin], vec![ix]);
    assert!(r.is_ok(), "InitMarket: {}", logs(&r));

    let src = Pubkey::new_unique();
    set_token_account(&mut svm, src, &mint, &admin.pubkey(), BUDGET);
    let mut d = vec![9u8];
    d.extend_from_slice(&rd_u64(&svm, &market, wl::ASSET0_MARKET_ID_OFF).to_le_bytes());
    d.extend_from_slice(&(rd_u64(&svm, &market, wl::ASSET0_INSURANCE_TOP_UP_OFF) + 1).to_le_bytes());
    d.extend_from_slice(&rd_u64(&svm, &market, wl::ASSET0_AUTHORITY_EPOCH_OFF).to_le_bytes());
    d.extend_from_slice(&(BUDGET as u128).to_le_bytes());
    let ix = Instruction {
        program_id: wrapper_id,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
            AccountMeta::new(src, false),
            AccountMeta::new(wrapper_vault, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data: d,
    };
    let r = send_ixs(&mut svm, &payer, &[&admin], vec![ix]);
    assert!(r.is_ok(), "TopUpInsurance: {}", logs(&r));

    let (pool, _) = derive_pool_pda(&stake_id, &market);
    let (vault_auth, _) = derive_vault_authority(&stake_id, &pool);
    let creator_ata = Pubkey::new_unique();
    set_token_account(&mut svm, creator_ata, &mint, &admin.pubkey(), 0);
    World {
        svm,
        stake_id,
        wrapper_id,
        admin,
        payer,
        market,
        mint,
        wrapper_vault,
        wrapper_vault_auth,
        pool,
        vault_auth,
        vault: Pubkey::new_unique(),
        lp_mint: Pubkey::new_unique(),
        creator_ata,
        obs_seq: 0,
    }
}

/// Real stake InitPool, FEE_ONLY (risk mode 2), cooldown 5.
fn init_pool(w: &mut World) -> TxResult {
    let mut ipd = vec![0u8];
    ipd.extend_from_slice(&5u64.to_le_bytes());
    ipd.extend_from_slice(&0u64.to_le_bytes());
    ipd.push(2u8);
    ipd.extend_from_slice(&0u16.to_le_bytes());
    ipd.extend_from_slice(&3_000u16.to_le_bytes());
    ipd.extend_from_slice(&500u16.to_le_bytes());
    init_pool_with(w, ipd)
}

/// Stake InitPool-family instruction with raw `data` (tag 0 or tag 13 InitTradingPool), same accounts.
fn init_pool_with(w: &mut World, ipd: Vec<u8>) -> TxResult {
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    for (k, n) in [(w.lp_mint, 82usize), (w.vault, 165usize)] {
        w.svm
            .set_account(k, Account { lamports: 1_000_000_000, data: vec![0u8; n], owner: token_program, executable: false, rent_epoch: 0 })
            .unwrap();
    }
    let ix = Instruction {
        program_id: w.stake_id,
        accounts: vec![
            AccountMeta::new(w.admin.pubkey(), true),
            AccountMeta::new(w.market, false),
            AccountMeta::new(w.pool, false),
            AccountMeta::new(w.lp_mint, false),
            AccountMeta::new(w.vault, false),
            AccountMeta::new_readonly(w.vault_auth, false),
            AccountMeta::new_readonly(w.mint, false),
            AccountMeta::new_readonly(w.wrapper_id, false),
            AccountMeta::new_readonly(token_program, false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
        ],
        data: ipd,
    };
    let (admin, payer) = (w.admin.insecure_clone(), w.payer.insecure_clone());
    send_ixs(&mut w.svm, &payer, &[&admin], vec![ix])
}

fn bind_ix(w: &World) -> Instruction {
    Instruction {
        program_id: w.stake_id,
        accounts: vec![
            AccountMeta::new(w.admin.pubkey(), true),
            AccountMeta::new(w.pool, false),
            AccountMeta::new_readonly(w.vault_auth, false),
            AccountMeta::new(w.market, false),
            AccountMeta::new_readonly(w.wrapper_id, false),
        ],
        data: vec![19u8],
    }
}

fn bind(w: &mut World) -> TxResult {
    let ix = bind_ix(w);
    let (admin, payer) = (w.admin.insecure_clone(), w.payer.insecure_clone());
    send_ixs(&mut w.svm, &payer, &[&admin], vec![ix])
}

/// Wrapper tag 59 UpdateMarketInitFeePolicy, signed by `signer` (must be marketauth).
fn set_init_fee(w: &mut World, signer: &Keypair, fee: u128) -> TxResult {
    let seq = rd_u64(&w.svm, &w.market, ASSET0_MARKET_INIT_FEE_SEQ_OFF) + 1;
    let mut d = vec![59u8];
    d.extend_from_slice(&fee.to_le_bytes());
    d.extend_from_slice(&seq.to_le_bytes());
    let ix = Instruction {
        program_id: w.wrapper_id,
        accounts: vec![AccountMeta::new(signer.pubkey(), true), AccountMeta::new(w.market, false)],
        data: d,
    };
    let payer = w.payer.insecure_clone();
    send_ixs(&mut w.svm, &payer, &[signer], vec![ix])
}

/// Wrapper tag 40 UpdateAssetLifecycle ACTIVATE append of asset 1, signed by `who`, offering to pay
/// up to `max_fee` from a token account it owns. Every new-asset authority = `who`.
fn append_asset1(w: &mut World, who: &Keypair, max_fee: u128) -> TxResult {
    w.svm.airdrop(&who.pubkey(), 10_000_000_000).unwrap();
    let src = Pubkey::new_unique();
    let (mint, wk) = (w.mint, who.pubkey());
    set_token_account(&mut w.svm, src, &mint, &wk, 1_000_000_000);
    let slot = w.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    let next_id = rd_u64(&w.svm, &w.market, wl::MARKET_ASSET_GENERATION_FRONTIER_OFF);
    let mut d = vec![40u8, 0u8];
    d.extend_from_slice(&1u16.to_le_bytes());
    d.extend_from_slice(&next_id.to_le_bytes());
    d.extend_from_slice(&0u64.to_le_bytes()); // authority_epoch (permissionless lane: 0)
    d.extend_from_slice(&slot.to_le_bytes());
    d.extend_from_slice(&PRICE.to_le_bytes());
    d.extend_from_slice(&max_fee.to_le_bytes());
    for _ in 0..4 {
        d.extend_from_slice(wk.as_ref());
    }
    let ix = Instruction {
        program_id: w.wrapper_id,
        accounts: vec![
            AccountMeta::new(wk, true),
            AccountMeta::new(w.market, false),
            AccountMeta::new(src, false),
            AccountMeta::new(w.wrapper_vault, false),
            AccountMeta::new_readonly(Pubkey::from_str(TOKEN_PROGRAM).unwrap(), false),
        ],
        data: d,
    };
    let payer = w.payer.insecure_clone();
    send_ixs(&mut w.svm, &payer, &[who], vec![ix])
}

fn max_market_slots(w: &World) -> u32 {
    rd_u32(&w.svm, &w.market, wl::MARKET_MAX_MARKET_SLOTS_OFF)
}

fn custody(w: &World) -> ([u8; 32], [u8; 32]) {
    let d = w.svm.get_account(&w.market).unwrap().data;
    let a = wl::ASSET0_INSURANCE_AUTHORITY_OFF;
    let o = wl::ASSET0_INSURANCE_OPERATOR_OFF;
    (d[a..a + 32].try_into().unwrap(), d[o..o + 32].try_into().unwrap())
}

// ── oracle / portfolio / trade (L-4) ─────────────────────────────────────────────────────

fn now(w: &World) -> u64 {
    w.svm.get_sysvar::<solana_sdk::clock::Clock>().slot
}

fn oracle_ix(w: &mut World, tag: u8, mark: u64) -> Instruction {
    w.obs_seq = rd_u64(&w.svm, &w.market, ASSET0_ORACLE_OBS_SEQ_OFF) + 1;
    let mut d = vec![tag];
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&rd_u64(&w.svm, &w.market, wl::ASSET0_MARKET_ID_OFF).to_le_bytes());
    d.extend_from_slice(&now(w).to_le_bytes());
    d.extend_from_slice(&mark.to_le_bytes());
    d.extend_from_slice(&w.obs_seq.to_le_bytes());
    Instruction {
        program_id: w.wrapper_id,
        accounts: vec![AccountMeta::new(w.admin.pubkey(), true), AccountMeta::new(w.market, false)],
        data: d,
    }
}

/// Wrapper tag 62 (ConfigureAuthMark) / 63 (PushAuthMark), signed by admin (asset-0 oracle authority).
fn oracle(w: &mut World, tag: u8, mark: u64) {
    let ix = oracle_ix(w, tag, mark);
    let (admin, payer) = (w.admin.insecure_clone(), w.payer.insecure_clone());
    let r = send_ixs(&mut w.svm, &payer, &[&admin], vec![ix]);
    assert!(r.is_ok(), "oracle tag {tag}: {}", logs(&r));
}

struct Trader {
    kp: Keypair,
    pf: Pubkey,
}

fn trader(w: &mut World, amount: u64) -> Trader {
    let kp = Keypair::new();
    w.svm.airdrop(&kp.pubkey(), 10_000_000_000).unwrap();
    let pf = Pubkey::new_unique();
    let wid = w.wrapper_id;
    w.svm
        .set_account(pf, Account { lamports: 1_000_000_000, data: vec![0u8; PORTFOLIO_LEN], owner: wid, executable: false, rent_epoch: 0 })
        .unwrap();
    let payer = w.payer.insecure_clone();
    let ix = Instruction {
        program_id: wid,
        accounts: vec![AccountMeta::new(kp.pubkey(), true), AccountMeta::new(w.market, false), AccountMeta::new(pf, false)],
        data: vec![1u8],
    };
    let r = send_ixs(&mut w.svm, &payer, &[&kp], vec![ix]);
    assert!(r.is_ok(), "InitPortfolio: {}", logs(&r));
    let src = Pubkey::new_unique();
    let (mint, k) = (w.mint, kp.pubkey());
    set_token_account(&mut w.svm, src, &mint, &k, amount);
    let mut d = vec![3u8];
    d.extend_from_slice(&rd_u64(&w.svm, &pf, PORTFOLIO_ID_OFF).to_le_bytes());
    d.extend_from_slice(&rd_u64(&w.svm, &pf, PORTFOLIO_SEQ_OFF).to_le_bytes());
    d.extend_from_slice(&(amount as u128).to_le_bytes());
    let ix = Instruction {
        program_id: wid,
        accounts: vec![
            AccountMeta::new(k, true),
            AccountMeta::new(w.market, false),
            AccountMeta::new(pf, false),
            AccountMeta::new(src, false),
            AccountMeta::new(w.wrapper_vault, false),
            AccountMeta::new_readonly(Pubkey::from_str(TOKEN_PROGRAM).unwrap(), false),
        ],
        data: d,
    };
    let r = send_ixs(&mut w.svm, &payer, &[&kp], vec![ix]);
    assert!(r.is_ok(), "Deposit: {}", logs(&r));
    Trader { kp, pf }
}

fn position_epoch(w: &World, pf: &Pubkey) -> u64 {
    // bits 1..49 of the matcher control word.
    (rd_u64(&w.svm, pf, PORTFOLIO_CONTROL_OFF) >> 1) & ((1u64 << 49) - 1)
}

/// Wrapper tag 6 TradeNoCpi: `a` takes `size_q` against `b` at `price`, fee 0.
fn trade(w: &mut World, a: &Trader, b: &Trader, size_q: i128, price: u64) {
    let mut d = vec![6u8];
    d.extend_from_slice(&rd_u64(&w.svm, &a.pf, PORTFOLIO_ID_OFF).to_le_bytes());
    d.extend_from_slice(&position_epoch(w, &a.pf).to_le_bytes());
    d.extend_from_slice(&rd_u64(&w.svm, &b.pf, PORTFOLIO_ID_OFF).to_le_bytes());
    d.extend_from_slice(&position_epoch(w, &b.pf).to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&rd_u64(&w.svm, &w.market, wl::ASSET0_MARKET_ID_OFF).to_le_bytes());
    d.extend_from_slice(&size_q.to_le_bytes());
    d.extend_from_slice(&price.to_le_bytes());
    d.extend_from_slice(&0u64.to_le_bytes());
    d.extend_from_slice(&10_000u16.to_le_bytes());
    let ix = Instruction {
        program_id: w.wrapper_id,
        accounts: vec![
            AccountMeta::new(a.kp.pubkey(), true),
            AccountMeta::new(b.kp.pubkey(), true),
            AccountMeta::new(w.market, false),
            AccountMeta::new(a.pf, false),
            AccountMeta::new(b.pf, false),
        ],
        data: d,
    };
    let (ak, bk, payer) = (a.kp.insecure_clone(), b.kp.insecure_clone(), w.payer.insecure_clone());
    let r = send_ixs(&mut w.svm, &payer, &[&ak, &bk], vec![ix]);
    assert!(r.is_ok(), "TradeNoCpi: {}", logs(&r));
}

/// Wrapper tag 5 PermissionlessCrank at the current slot, touching `pfs`.
fn crank_ix(w: &World, pfs: &[Pubkey]) -> Instruction {
    let mut d = vec![5u8];
    d.extend_from_slice(&now(w).to_le_bytes());
    d.push(1u8);
    d.extend_from_slice(&0u16.to_le_bytes());
    d.push(0u8);
    let mut accounts = vec![AccountMeta::new(w.payer.pubkey(), true), AccountMeta::new(w.market, false)];
    for p in pfs {
        accounts.push(AccountMeta::new(*p, false));
    }
    Instruction { program_id: w.wrapper_id, accounts, data: d }
}

fn crank(w: &mut World, pfs: &[Pubkey]) -> TxResult {
    let ix = crank_ix(w, pfs);
    let payer = w.payer.insecure_clone();
    send_ixs(&mut w.svm, &payer, &[], vec![ix])
}

fn stale(w: &World) -> (u64, u64) {
    (
        rd_u64(&w.svm, &w.market, wl::ASSET0_STALE_COUNT_LONG_OFF),
        rd_u64(&w.svm, &w.market, wl::ASSET0_STALE_COUNT_SHORT_OFF),
    )
}

// ── staking (M-3) ────────────────────────────────────────────────────────────────────────

fn new_staker(w: &mut World, amount: u64) -> Staker {
    let kp = Keypair::new();
    w.svm.airdrop(&kp.pubkey(), 10_000_000_000).unwrap();
    let ata = Pubkey::new_unique();
    let lp_ata = Pubkey::new_unique();
    let (mint, lp_mint, k) = (w.mint, w.lp_mint, kp.pubkey());
    set_token_account(&mut w.svm, ata, &mint, &k, amount);
    set_token_account(&mut w.svm, lp_ata, &lp_mint, &k, 0);
    Staker { kp, ata, lp_ata }
}

fn deposit(w: &mut World, amount: u64) -> Staker {
    let s = new_staker(w, amount);
    let (dpda, _) = derive_deposit_pda(&w.stake_id, &w.pool, &s.kp.pubkey());
    let mut data = vec![1u8];
    data.extend_from_slice(&amount.to_le_bytes());
    let ix = Instruction {
        program_id: w.stake_id,
        accounts: vec![
            AccountMeta::new(s.kp.pubkey(), true),
            AccountMeta::new(w.pool, false),
            AccountMeta::new(s.ata, false),
            AccountMeta::new(w.vault, false),
            AccountMeta::new(w.lp_mint, false),
            AccountMeta::new(s.lp_ata, false),
            AccountMeta::new_readonly(w.vault_auth, false),
            AccountMeta::new(dpda, false),
            AccountMeta::new_readonly(Pubkey::from_str(TOKEN_PROGRAM).unwrap(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(w.market, false),
        ],
        data,
    };
    let (k, payer) = (s.kp.insecure_clone(), w.payer.insecure_clone());
    let r = send_ixs(&mut w.svm, &payer, &[&k], vec![ix]);
    assert!(r.is_ok(), "Deposit: {}", logs(&r));
    s
}

fn withdraw_all(w: &mut World, s: &Staker) -> u64 {
    let lp = token_amount(&w.svm, &s.lp_ata);
    let before = token_amount(&w.svm, &s.ata);
    let (dpda, _) = derive_deposit_pda(&w.stake_id, &w.pool, &s.kp.pubkey());
    let mut data = vec![2u8];
    data.extend_from_slice(&lp.to_le_bytes());
    let ix = Instruction {
        program_id: w.stake_id,
        accounts: vec![
            AccountMeta::new(s.kp.pubkey(), true),
            AccountMeta::new(w.pool, false),
            AccountMeta::new(s.lp_ata, false),
            AccountMeta::new(w.lp_mint, false),
            AccountMeta::new(w.vault, false),
            AccountMeta::new(s.ata, false),
            AccountMeta::new_readonly(w.vault_auth, false),
            AccountMeta::new(dpda, false),
            AccountMeta::new_readonly(Pubkey::from_str(TOKEN_PROGRAM).unwrap(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
            AccountMeta::new_readonly(w.market, false),
        ],
        data,
    };
    let (k, payer) = (s.kp.insecure_clone(), w.payer.insecure_clone());
    let r = send_ixs(&mut w.svm, &payer, &[&k], vec![ix]);
    assert!(r.is_ok(), "Withdraw: {}", logs(&r));
    token_amount(&w.svm, &s.ata) - before
}

fn admin_resolve(w: &mut World) {
    let ix = Instruction {
        program_id: w.stake_id,
        accounts: vec![
            AccountMeta::new_readonly(w.admin.pubkey(), true),
            AccountMeta::new_readonly(w.pool, false),
            AccountMeta::new(w.market, false),
            AccountMeta::new_readonly(w.wrapper_id, false),
        ],
        data: vec![24u8],
    };
    let (admin, payer) = (w.admin.insecure_clone(), w.payer.insecure_clone());
    let r = send_ixs(&mut w.svm, &payer, &[&admin], vec![ix]);
    assert!(r.is_ok(), "AdminResolveMarket: {}", logs(&r));
}

/// Stake tag 29 (permissionless), pulling `amount` via wrapper tag 41, creator ATA in the tail.
fn recover_terminal(w: &mut World, amount: u64) -> TxResult {
    let mut data = vec![29u8];
    data.extend_from_slice(&amount.to_le_bytes());
    let ix = Instruction {
        program_id: w.stake_id,
        accounts: vec![
            AccountMeta::new_readonly(Pubkey::new_unique(), false),
            AccountMeta::new(w.pool, false),
            AccountMeta::new(w.vault, false),
            AccountMeta::new_readonly(w.vault_auth, false),
            AccountMeta::new(w.market, false),
            AccountMeta::new(w.wrapper_vault, false),
            AccountMeta::new_readonly(w.wrapper_vault_auth, false),
            AccountMeta::new_readonly(Pubkey::from_str(TOKEN_PROGRAM).unwrap(), false),
            AccountMeta::new_readonly(w.wrapper_id, false),
            AccountMeta::new(w.creator_ata, false),
        ],
        data,
    };
    let payer = w.payer.insecure_clone();
    send_ixs(&mut w.svm, &payer, &[], vec![ix])
}

/// Same shape as `f9::forge_seed(Some(seed))`: lower the recorded seed so the fund holds
/// `BUDGET - seed` of growth above it (pool bytes 333 bit 0 + 457..464).
fn forge_seed(w: &mut World, seed: u64) {
    let mut a = w.svm.get_account(&w.pool).unwrap();
    a.data[333] |= 1;
    a.data[457..464].copy_from_slice(&seed.to_le_bytes()[..7]);
    w.svm.set_account(w.pool, a).unwrap();
    assert_eq!(read_pool(&w.svm, &w.pool).creator_seed_atoms(), seed, "forge_seed layout");
}

// ═════════════════════════════════════════════════════════════════════════════════════════
// M-4
// ═════════════════════════════════════════════════════════════════════════════════════════

/// Pins the raw config offset this file (and the M-4 fix) reads the init fee from: tag 59 writes
/// exactly the u128 at 128..144.
#[test]
fn m4_pin_permissionless_init_fee_offset_on_real_wrapper() {
    let mut w = market_only();
    assert_eq!(rd_u128(&w.svm, &w.market, MARKET_PERMISSIONLESS_INIT_FEE_OFF), 0, "InitMarket writes 0");
    let admin = w.admin.insecure_clone();
    let r = set_init_fee(&mut w, &admin, 123_456_789);
    assert!(r.is_ok(), "{}", logs(&r));
    assert_eq!(rd_u128(&w.svm, &w.market, MARKET_PERMISSIONLESS_INIT_FEE_OFF), 123_456_789);
    assert_eq!(MARKET_PERMISSIONLESS_INIT_FEE_OFF, wl::MARKET_PERMISSIONLESS_INIT_FEE_OFF, "program pin");
    let d = w.svm.get_account(&w.market).unwrap().data;
    assert_eq!(
        percolator_stake::state::read_wrapper_asset_append_guard(&d),
        Some((1, 123_456_789)),
        "the program's own reader sees the fee and the single slot"
    );
}

/// THE GRIEF (reproduction of M-4 on the base program). The creator set a non-zero permissionless
/// init fee before InitPool; a third party appends asset 1 paying it; the v5 bind then refuses 48,
/// and nothing can undo the append (only marketauth = the pool PDA could retire it, and stake has
/// no proxy for it).
/// FIXED BEHAVIOUR: InitPool refuses such a market (48) before the pool exists, so a pool can never
/// be created in the griefable state. On the base build InitPool succeeds and this test fails at
/// the first assert.
#[test]
fn m4_init_pool_refuses_nonzero_permissionless_init_fee() {
    let mut w = market_only();
    let admin = w.admin.insecure_clone();
    assert!(set_init_fee(&mut w, &admin, 1_000_000).is_ok());
    let r = init_pool(&mut w);
    assert_eq!(custom(&r), Some(E_MULTI_ASSET_NOT_SUPPORTED), "InitPool must refuse: {}", logs(&r));
    assert!(w.svm.get_account(&w.pool).map(|a| a.data.is_empty()).unwrap_or(true), "no pool created");
    let d = w.svm.get_account(&w.market).unwrap().data;
    assert_eq!(&d[16..48], w.admin.pubkey().as_ref(), "marketauth NOT handed to the pool PDA");
    // The creator can still repair the market (fee back to 0) and then launch normally.
    assert!(set_init_fee(&mut w, &admin, 0).is_ok());
    let r = init_pool(&mut w);
    assert!(r.is_ok(), "fee 0: {}", logs(&r));
    let r = bind(&mut w);
    assert!(r.is_ok(), "bind: {}", logs(&r));
}

/// FIXED BEHAVIOUR: InitPool refuses a market that is already multi-asset (48). Here the creator
/// (marketauth, fee 0) appended asset 1 itself; the v5 bind could never succeed on it.
/// On the base build InitPool succeeds (and the bind later refuses 48 forever).
#[test]
fn m4_init_pool_refuses_multi_asset_market() {
    let mut w = market_only();
    let admin = w.admin.insecure_clone();
    let r = append_asset1(&mut w, &admin, 0);
    assert!(r.is_ok(), "marketauth append: {}", logs(&r));
    assert_eq!(max_market_slots(&w), 2);
    let r = init_pool(&mut w);
    assert_eq!(custom(&r), Some(E_MULTI_ASSET_NOT_SUPPORTED), "InitPool must refuse: {}", logs(&r));
}

/// Characterises the base program end to end (passes on both builds by construction of its
/// branches): with the fee set before InitPool, a third party's append makes every later bind 48.
/// On the fixed build the InitPool itself is refused, so the grief cannot be set up.
#[test]
fn m4_third_party_append_then_bind_is_refused_forever_on_base() {
    let mut w = market_only();
    let admin = w.admin.insecure_clone();
    assert!(set_init_fee(&mut w, &admin, 1_000_000).is_ok());
    let r = init_pool(&mut w);
    if r.is_err() {
        assert_eq!(custom(&r), Some(E_MULTI_ASSET_NOT_SUPPORTED), "{}", logs(&r));
        return; // fixed build: the griefable state is unreachable
    }
    let attacker = Keypair::new();
    let ins0 = token_amount(&w.svm, &w.wrapper_vault);
    let r = append_asset1(&mut w, &attacker, 1_000_000);
    assert!(r.is_ok(), "third-party append: {}", logs(&r));
    assert_eq!(max_market_slots(&w), 2, "asset 1 appended by a stranger");
    assert_eq!(token_amount(&w.svm, &w.wrapper_vault), ins0 + 1_000_000, "attacker paid the fee once");
    let me = w.admin.pubkey().to_bytes();
    for _ in 0..3 {
        let r = bind(&mut w);
        assert_eq!(custom(&r), Some(E_MULTI_ASSET_NOT_SUPPORTED), "{}", logs(&r));
        assert_eq!(custody(&w), (me, me), "custody never moves");
        w.svm.warp_to_slot(now(&w) + 10);
    }
    // And the creator cannot reset the fee or retire the slot any more: marketauth is the pool PDA.
    let r = set_init_fee(&mut w, &admin, 0);
    assert!(r.is_err(), "creator is no longer marketauth");
}

/// Review L1: InitTradingPool (tag 13) shares `process_init_pool`, so it hits the same guard.
#[test]
fn m4_init_trading_pool_also_refuses_nonzero_permissionless_init_fee() {
    let mut w = market_only();
    let admin = w.admin.insecure_clone();
    assert!(set_init_fee(&mut w, &admin, 1_000_000).is_ok());
    let mut d = vec![13u8];
    d.extend_from_slice(&5u64.to_le_bytes());
    d.extend_from_slice(&0u64.to_le_bytes());
    let r = init_pool_with(&mut w, d.clone());
    assert_eq!(custom(&r), Some(E_MULTI_ASSET_NOT_SUPPORTED), "{}", logs(&r));
    assert!(set_init_fee(&mut w, &admin, 0).is_ok());
    let r = init_pool_with(&mut w, d);
    assert!(r.is_ok(), "fee 0: {}", logs(&r));
}

/// Review L1: an unpinned wrapper header (FORGED version byte on the real market) fails closed
/// with UnsupportedWrapperLayout (32) before anything is created.
#[test]
fn m4_init_pool_refuses_unpinned_wrapper_layout() {
    let mut w = market_only();
    let mut m = w.svm.get_account(&w.market).unwrap();
    let v = u16::from_le_bytes(m.data[8..10].try_into().unwrap());
    m.data[8..10].copy_from_slice(&(v + 1).to_le_bytes());
    w.svm.set_account(w.market, m).unwrap();
    let r = init_pool(&mut w);
    assert_eq!(custom(&r), Some(32), "{}", logs(&r));
    assert!(w.svm.get_account(&w.pool).map(|a| a.data.is_empty()).unwrap_or(true));
}

/// Review L2: the M-4 invariant needs stake to never CPI wrapper tag 59 (fee setter) or tag 40
/// (asset lifecycle). Every wrapper tag stake sends is a `const TAG_*: u8 = N;` in src/cpi.rs.
#[test]
fn m4_stake_cpi_never_targets_wrapper_tag_59_or_40() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cpi.rs")).unwrap();
    let mut tags = vec![];
    for line in src.lines() {
        let l = line.trim();
        if l.starts_with("const TAG_") || l.starts_with("pub const TAG_") {
            let n: u8 = l.rsplit('=').next().unwrap().trim().trim_end_matches(';').trim().parse().unwrap();
            tags.push(n);
        }
    }
    assert!(tags.len() >= 10, "found the TAG table: {tags:?}");
    assert!(!tags.contains(&59) && !tags.contains(&40), "M-4 invariant broken: {tags:?}");
}

/// The invariant the fix relies on (both builds): once InitPool lands with fee 0, nobody can append
/// and nobody (not even the creator) can raise the fee, so `max_market_slots` stays 1 for the
/// pool's whole life (the bind and any FEE_ONLY re-bind can never hit 48).
#[test]
fn m4_fee_zero_market_cannot_be_appended_or_refeed_after_init_pool() {
    let mut w = market_only();
    assert!(init_pool(&mut w).is_ok());
    let attacker = Keypair::new();
    let r = append_asset1(&mut w, &attacker, u128::MAX);
    assert_eq!(custom(&r), Some(W_UNAUTHORIZED), "fee 0: stranger cannot append: {}", logs(&r));
    let admin = w.admin.insecure_clone();
    let r = set_init_fee(&mut w, &admin, 1);
    assert_eq!(custom(&r), Some(W_UNAUTHORIZED), "creator cannot set the fee after InitPool: {}", logs(&r));
    let r = append_asset1(&mut w, &admin, 0);
    assert_eq!(custom(&r), Some(W_UNAUTHORIZED), "creator cannot append after InitPool: {}", logs(&r));
    assert_eq!(max_market_slots(&w), 1);
    assert!(bind(&mut w).is_ok());
}

// ═════════════════════════════════════════════════════════════════════════════════════════
// L-4 (characterisation; no code change on this branch)
// ═════════════════════════════════════════════════════════════════════════════════════════

/// Two traders hold opposite positions. One slot later the oracle moves and a crank touches only
/// one of them: the other side's cohort stays stale and the v5 bind refuses 44. One crank per
/// positioned account, sent in the SAME transaction as the bind, clears it (the documented client
/// mitigation). With N positioned accounts the mitigation needs N crank instructions in one
/// transaction (or N transactions landing in one slot); past the tx size / CU limit it is not
/// available (the grief: open many small positions).
#[test]
fn l4_stale_cohort_after_a_real_price_move_blocks_bind_until_every_position_is_touched() {
    let mut w = market_only();
    oracle(&mut w, 62, PRICE);
    assert!(init_pool(&mut w).is_ok());
    let a = trader(&mut w, 1_000_000_000);
    let b = trader(&mut w, 1_000_000_000);
    trade(&mut w, &a, &b, 1_000_000 * 100_000, PRICE);
    assert_eq!(stale(&w), (0, 0), "a trade settles both legs it touches");
    // Price unchanged and a new slot: no K/F move, nothing goes stale, the bind would work.
    w.svm.warp_to_slot(now(&w) + 1);
    assert!(crank(&mut w, &[a.pf]).is_ok());
    assert_eq!(stale(&w), (0, 0), "no K/F move, no stale cohort");
    // A real move.
    w.svm.warp_to_slot(now(&w) + 1);
    oracle(&mut w, 63, PRICE + 10);
    let r = crank(&mut w, &[a.pf]);
    assert!(r.is_ok(), "{}", logs(&r));
    let (sl, ss) = stale(&w);
    assert!(sl + ss >= 1, "the untouched side stays stale: {:?}", (sl, ss));
    let r = bind(&mut w);
    assert_eq!(custom(&r), Some(E_INSURANCE_READINGS_DIVERGED), "{}", logs(&r));
    // Later slots: every crank that accrues re-marks the side; touching one account is never enough.
    w.svm.warp_to_slot(now(&w) + 1);
    oracle(&mut w, 63, PRICE + 5);
    assert!(crank(&mut w, &[b.pf]).is_ok());
    let r = bind(&mut w);
    assert_eq!(custom(&r), Some(E_INSURANCE_READINGS_DIVERGED), "{}", logs(&r));
    // Mitigation: one crank (refresh) per positioned account + the bind, in ONE transaction
    // (PermissionlessCrank refreshes exactly one portfolio; same slot, so dt = 0 and no re-mark).
    let ixs = vec![crank_ix(&w, &[a.pf]), crank_ix(&w, &[b.pf]), bind_ix(&w)];
    let (admin, payer) = (w.admin.insecure_clone(), w.payer.insecure_clone());
    let r = send_ixs(&mut w.svm, &payer, &[&admin], ixs);
    assert!(r.is_ok(), "crank-all + bind in one tx: {}", logs(&r));
    assert_eq!(custody(&w).0, w.vault_auth.to_bytes());
}

// ═════════════════════════════════════════════════════════════════════════════════════════
// M-3 / D8 (#318): mark-to-close pricing + maturity gate (was a characterisation of the flaw)
// ═════════════════════════════════════════════════════════════════════════════════════════

/// Alice stakes for the life of the market. Bob deposits the same amount one slot before the
/// (predictable) admin resolve, and leaves right after the close-out. Growth above the seed
/// (`BUDGET - SEED`) is booked at the close-out. BEFORE D8 Bob took about half of it for a
/// position held only a few slots (this test pinned that flaw); NOW the deposit is priced with
/// the pending growth (mark-to-close) and, as a backstop, LP minted within `MATURITY_GATE_SLOTS`
/// of the terminal does not share in the surplus: Bob earns (to rounding) nothing and Alice
/// keeps the growth. The full red/green matrix is `tests/d8_jit_closeout_e2e.rs`.
#[test]
fn m3_jit_deposit_before_resolve_no_longer_shares_closeout_growth() {
    const SEED: u64 = 3_000_000;
    let mut w = market_only();
    assert!(init_pool(&mut w).is_ok());
    let alice = deposit(&mut w, STAKE);
    assert!(bind(&mut w).is_ok());
    forge_seed(&mut w, SEED);
    w.svm.warp_to_slot(now(&w) + 100_000);
    let bob = deposit(&mut w, STAKE); // just in time
    w.svm.warp_to_slot(now(&w) + 1);
    admin_resolve(&mut w);
    let r = recover_terminal(&mut w, BUDGET);
    assert!(r.is_ok(), "{}", logs(&r));
    assert_eq!(token_amount(&w.svm, &w.creator_ata), SEED, "creator capped at the seed");
    w.svm.warp_to_slot(now(&w) + 10);
    let bob_out = withdraw_all(&mut w, &bob);
    let alice_out = withdraw_all(&mut w, &alice);
    let growth = BUDGET - SEED;
    let bob_profit = bob_out.saturating_sub(STAKE);
    let alice_profit = alice_out.saturating_sub(STAKE);
    eprintln!("M-3/D8: growth {growth}, alice +{alice_profit} (100k+ slots), bob +{bob_profit} (~2 slots)");
    assert!(
        bob_profit * 1_000 <= growth,
        "JIT staker must not take the growth: bob +{bob_profit} of {growth}"
    );
    assert!(
        alice_profit * 100 >= growth * 99,
        "the long-term staker keeps the growth: alice +{alice_profit} of {growth}"
    );
    assert!(alice_profit + bob_profit <= growth);
}
