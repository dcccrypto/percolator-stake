//! GH#322: the wrapper's CloseSlab re-book of orphaned fee legs (W-S1) advances
//! `insurance_reserve_withdrawn` (the #290 counter stake reads as "tag-87 atoms transferred into
//! pool.vault") with no token transfer. Before the fix, the next stake reader (tag 29, AccrueFees,
//! a Withdraw that passes the slab) booked the FEE_ONLY creator's recovered seed as staker fees,
//! so the creator got less than the seed.
//!
//! Correct behaviour (the `*_creator_gets_full_seed` tests; they fail on 3a7c4dd9): a FEE_ONLY
//! creator whose seed is intact gets the whole seed back from tag 29, whether AdminCloseSlab ran
//! first or not.
//!
//! Everything goes through REAL instructions on the REAL stake .so (7JrgAUHi) + REAL wrapper .so:
//! wrapper InitMarket (0), TopUpInsurance (9), stake InitPool (0, FEE_ONLY), Deposit (1), Bind (19),
//! wrapper InitPortfolio (1), portfolio Deposit (3), fee-bearing TradeNoCpi (6), portfolio
//! Withdraw (4), ClosePortfolio (8), stake AdminResolveMarket (24), stake AdminCloseSlab (30),
//! stake RecoverTerminalInsurance (29).
//!
//! Forged bytes (the setup a client's system createAccount / SPL InitializeAccount would produce):
//!   * collateral mint (82 bytes, `is_initialized = 1`, supply 0, no authority);
//!   * SPL token accounts with a starting balance (funding: creator seed source, staker, trader
//!     sources, empty destinations, the wrapper vault ATA with balance 0);
//!   * zero-filled, wrapper-owned market (4059 bytes) and portfolio (10,603 bytes) accounts;
//!   * zero-filled, token-owned lp_mint / pool vault accounts (stake InitPool initializes them).
//! NO pool, market-config, fee-counter, unit-ledger or seed byte is written by the test.
//!
//! D26 (wrapper rc23 #622): the market and every portfolio are keypairs and SIGN their init, which
//! the deployed wrapper (aca02ba6) simply does not check, so the same file drives both wrappers.
//!
//! Artifacts: `GH311_STAKE_SO` (default target/deploy/percolator_stake.so), `GH311_WRAPPER_SO`
//! (default ../percolator-prog/target/deploy/percolator_prog.so). Both must pin stake 7JrgAUHi.

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use percolator_stake::state::{
    derive_deposit_pda, derive_pool_pda, derive_vault_authority, read_wrapper_terminal, StakePool,
    WrapperTerminal, STAKE_POOL_SIZE,
};
use percolator_stake::wrapper_layout::{
    ASSET0_AUTHORITY_EPOCH_OFF, ASSET0_INSURANCE_TOP_UP_OFF, ASSET0_MARKET_ID_OFF,
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

const WRAPPER_ID: &str = "ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv";
const STAKE_ID: &str = "7JrgAUHi4PxaRv5JKHoGAxodDFbozYexpERei66Xgq4V";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const MARKET_LEN_V22_CAP1: usize = 4059;
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;
const RISK_FEE_ONLY: u8 = 2;

const SEED: u64 = 5_000_000;
const ALICE: u64 = 10_000_000;
const PF_LEN: usize = 10_603;
const PF_ID_OFF: usize = PF_LEN - 24;
const PF_SEQ_OFF: usize = PF_LEN - 16;
const PF_CONTROL_OFF: usize = PF_LEN - 24 - 104 + 96;
/// WrapperConfigV16 fee counters (account bytes): lp_acc, lp_wd, ins_acc, ins_wd (READ only).
const OFF_LP_ACC: usize = 16 + 496;
const OFF_LP_WD: usize = 16 + 512;
const OFF_INS_ACC: usize = 16 + 528;
const OFF_INS_WD: usize = 16 + 544;
const PRICE: u64 = 100;
const FEE_BPS: u64 = 500;
const TRADER_CAP: u64 = 30_000_000_000;
/// Big history: re-booked legs (6.4M) exceed the seed. Small: re-booked legs (1.6M) are below it.
const SIZE_BIG: i128 = 1_000_000 * 1_000_000;
const SIZE_SMALL: i128 = SIZE_BIG / 4;

fn token_program() -> Pubkey {
    Pubkey::from_str(TOKEN_PROGRAM).unwrap()
}

fn so(var: &str, default: PathBuf) -> PathBuf {
    let p = std::env::var(var).map(PathBuf::from).unwrap_or(default);
    assert!(p.exists(), "{var}: missing .so at {}", p.display());
    p
}

fn token_data(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    d
}

fn raw(svm: &mut LiteSVM, key: Pubkey, owner: Pubkey, data: Vec<u8>) {
    let acct = Account {
        lamports: 1_000_000_000,
        data,
        owner,
        executable: false,
        rent_epoch: 0,
    };
    svm.set_account(key, acct).unwrap();
}

fn set_token(svm: &mut LiteSVM, key: Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) {
    raw(svm, key, token_program(), token_data(mint, owner, amount));
}

fn bal(svm: &LiteSVM, key: &Pubkey) -> u64 {
    match svm.get_account(key) {
        Some(a) if a.data.len() >= 72 => u64::from_le_bytes(a.data[64..72].try_into().unwrap()),
        _ => 0,
    }
}

fn read_u64(svm: &LiteSVM, key: &Pubkey, off: usize) -> u64 {
    let d = svm.get_account(key).unwrap().data;
    u64::from_le_bytes(d[off..off + 8].try_into().unwrap())
}

fn rd_u128(svm: &LiteSVM, key: &Pubkey, off: usize) -> u128 {
    let d = svm.get_account(key).unwrap().data;
    u128::from_le_bytes(d[off..off + 16].try_into().unwrap())
}

/// Wrapper InitMarket, the same 219-byte form the F-9 / v5 / gh311 suites use.
fn encode_init_market() -> Vec<u8> {
    let mut out = vec![0u8];
    out.extend_from_slice(&1u16.to_le_bytes());
    for v in [0u64, 10, 100] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&1u128.to_le_bytes());
    out.extend_from_slice(&2u128.to_le_bytes());
    for v in [10_000u64, 10_000, 10_000, 0, 0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&0u128.to_le_bytes());
    out.extend_from_slice(&0u128.to_le_bytes());
    for v in [10_000u64, 1, 0, 1, 1, 1, 100] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&MAX_VAULT_TVL.to_le_bytes());
    out.extend_from_slice(&0u128.to_le_bytes());
    assert_eq!(out.len(), 219);
    out
}

type TxResult = Result<(), litesvm::types::FailedTransactionMetadata>;

fn send(svm: &mut LiteSVM, payer: &Keypair, signers: &[&Keypair], ix: Instruction) -> TxResult {
    let mut all: Vec<&Keypair> = vec![payer];
    all.extend_from_slice(signers);
    svm.expire_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[
            solana_sdk::compute_budget::ComputeBudgetInstruction::request_heap_frame(128 * 1024),
            solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            ix,
        ],
        Some(&payer.pubkey()),
        &all,
        svm.latest_blockhash(),
    );
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

fn ok(r: TxResult, what: &str) {
    assert!(r.is_ok(), "{what}: {}", logs(&r));
}

#[derive(Debug, Clone, Copy)]
struct Legs {
    lp_acc: u128,
    lp_wd: u128,
    ins_acc: u128,
    ins_wd: u128,
}

struct W {
    svm: LiteSVM,
    stake: Pubkey,
    wrapper: Pubkey,
    admin: Keypair,
    payer: Keypair,
    market: Pubkey,
    mint: Pubkey,
    wvault: Pubkey,
    wvault_auth: Pubkey,
    pool: Pubkey,
    vault_auth: Pubkey,
    vault: Pubkey,
    lp_mint: Pubkey,
    creator_ata: Pubkey,
    alice: Keypair,
    alice_ata: Pubkey,
    alice_lp: Pubkey,
}

impl W {
    fn pool(&self) -> StakePool {
        let d = self.svm.get_account(&self.pool).unwrap().data;
        *bytemuck::from_bytes::<StakePool>(&d[..STAKE_POOL_SIZE])
    }
    fn legs(&self) -> Legs {
        Legs {
            lp_acc: rd_u128(&self.svm, &self.market, OFF_LP_ACC),
            lp_wd: rd_u128(&self.svm, &self.market, OFF_LP_WD),
            ins_acc: rd_u128(&self.svm, &self.market, OFF_INS_ACC),
            ins_wd: rd_u128(&self.svm, &self.market, OFF_INS_WD),
        }
    }
    fn terminal(&self) -> WrapperTerminal {
        read_wrapper_terminal(&self.svm.get_account(&self.market).unwrap().data)
    }
    fn warp(&mut self, n: u64) {
        let s = self.svm.get_sysvar::<solana_sdk::clock::Clock>().slot + n;
        self.svm.warp_to_slot(s);
    }
    fn tx(
        &mut self,
        program: Pubkey,
        signers: &[&Keypair],
        accounts: Vec<AccountMeta>,
        data: Vec<u8>,
    ) -> TxResult {
        let payer = self.payer.insecure_clone();
        send(
            &mut self.svm,
            &payer,
            signers,
            Instruction {
                program_id: program,
                accounts,
                data,
            },
        )
    }
    fn admin_stake(&mut self, accounts: Vec<AccountMeta>, data: Vec<u8>) -> TxResult {
        let (admin, stake) = (self.admin.insecure_clone(), self.stake);
        self.tx(stake, &[&admin], accounts, data)
    }
}

/// Live market, creator seed (tag 9), FEE_ONLY InitPool, alice deposits 10M, Bind (19) records
/// the seed. Same order as the gh311 `fo_scene` (FEE_ONLY bind needs a real staker first).
fn world() -> W {
    let stake_so = so(
        "GH311_STAKE_SO",
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/deploy/percolator_stake.so"),
    );
    let mut wp = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    wp.pop();
    let wrapper_so = so(
        "GH311_WRAPPER_SO",
        wp.join("percolator-prog/target/deploy/percolator_prog.so"),
    );
    let mut svm = LiteSVM::new().with_spl_programs();
    svm.warp_to_slot(1_000);
    let stake = Pubkey::from_str(STAKE_ID).unwrap();
    let wrapper = Pubkey::from_str(WRAPPER_ID).unwrap();
    svm.add_program_from_file(stake, &stake_so).unwrap();
    svm.add_program_from_file(wrapper, &wrapper_so).unwrap();
    let (admin, payer) = (Keypair::new(), Keypair::new());
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.airdrop(&admin.pubkey(), 20_000_000_000).unwrap();

    let market_kp = Keypair::new();
    let market = market_kp.pubkey();
    let mint = Pubkey::new_unique();
    let mut md = vec![0u8; 82];
    md[45] = 1;
    raw(&mut svm, mint, token_program(), md);
    let wvault_auth = Pubkey::find_program_address(&[b"vault", market.as_ref()], &wrapper).0;
    let wvault = Pubkey::find_program_address(
        &[
            wvault_auth.as_ref(),
            token_program().as_ref(),
            mint.as_ref(),
        ],
        &Pubkey::from_str(ATA_PROGRAM).unwrap(),
    )
    .0;
    set_token(&mut svm, wvault, &mint, &wvault_auth, 0);
    raw(&mut svm, market, wrapper, vec![0u8; MARKET_LEN_V22_CAP1]);
    let im = Instruction {
        program_id: wrapper,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, true), // D26: the market signs its init (rc23 #622)
            AccountMeta::new_readonly(mint, false),
        ],
        data: encode_init_market(),
    };
    ok(
        send(&mut svm, &payer, &[&admin, &market_kp], im),
        "InitMarket",
    );

    let src = Pubkey::new_unique();
    set_token(&mut svm, src, &mint, &admin.pubkey(), SEED);
    let mut d = vec![9u8];
    d.extend_from_slice(&read_u64(&svm, &market, ASSET0_MARKET_ID_OFF).to_le_bytes());
    d.extend_from_slice(&(read_u64(&svm, &market, ASSET0_INSURANCE_TOP_UP_OFF) + 1).to_le_bytes());
    d.extend_from_slice(&read_u64(&svm, &market, ASSET0_AUTHORITY_EPOCH_OFF).to_le_bytes());
    d.extend_from_slice(&(SEED as u128).to_le_bytes());
    let ix = Instruction {
        program_id: wrapper,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
            AccountMeta::new(src, false),
            AccountMeta::new(wvault, false),
            AccountMeta::new_readonly(token_program(), false),
        ],
        data: d,
    };
    ok(
        send(&mut svm, &payer, &[&admin], ix),
        "TopUpInsurance (creator seed)",
    );

    let (pool, _) = derive_pool_pda(&stake, &market);
    let (vault_auth, _) = derive_vault_authority(&stake, &pool);
    let (lp_mint, vault) = (Pubkey::new_unique(), Pubkey::new_unique());
    raw(&mut svm, lp_mint, token_program(), vec![0u8; 82]);
    raw(&mut svm, vault, token_program(), vec![0u8; 165]);
    // 23-byte InitPool: cooldown 5, cap 0, FEE_ONLY, target 0, buffer 3000, hysteresis 500.
    let mut ipd = vec![0u8];
    ipd.extend_from_slice(&5u64.to_le_bytes());
    ipd.extend_from_slice(&0u64.to_le_bytes());
    ipd.push(RISK_FEE_ONLY);
    for v in [0u16, 3_000, 500] {
        ipd.extend_from_slice(&v.to_le_bytes());
    }
    let ix = Instruction {
        program_id: stake,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
            AccountMeta::new(pool, false),
            AccountMeta::new(lp_mint, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(vault_auth, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(wrapper, false),
            AccountMeta::new_readonly(token_program(), false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
        ],
        data: ipd,
    };
    ok(send(&mut svm, &payer, &[&admin], ix), "InitPool FEE_ONLY");

    let creator_ata = Pubkey::new_unique();
    set_token(&mut svm, creator_ata, &mint, &admin.pubkey(), 0);
    let alice = Keypair::new();
    svm.airdrop(&alice.pubkey(), 10_000_000_000).unwrap();
    let (alice_ata, alice_lp) = (Pubkey::new_unique(), Pubkey::new_unique());
    set_token(&mut svm, alice_ata, &mint, &alice.pubkey(), ALICE);
    set_token(&mut svm, alice_lp, &lp_mint, &alice.pubkey(), 0);
    let mut w = W {
        svm,
        stake,
        wrapper,
        admin,
        payer,
        market,
        mint,
        wvault,
        wvault_auth,
        pool,
        vault_auth,
        vault,
        lp_mint,
        creator_ata,
        alice,
        alice_ata,
        alice_lp,
    };
    assert!(
        w.pool().is_v5_risk_mode() && w.pool().pool_mode == 0,
        "mode-0 v5 FEE_ONLY pool"
    );

    let (dpda, _) = derive_deposit_pda(&w.stake, &w.pool, &w.alice.pubkey());
    let mut data = vec![1u8];
    data.extend_from_slice(&ALICE.to_le_bytes());
    let accounts = vec![
        AccountMeta::new(w.alice.pubkey(), true),
        AccountMeta::new(w.pool, false),
        AccountMeta::new(w.alice_ata, false),
        AccountMeta::new(w.vault, false),
        AccountMeta::new(w.lp_mint, false),
        AccountMeta::new(w.alice_lp, false),
        AccountMeta::new_readonly(w.vault_auth, false),
        AccountMeta::new(dpda, false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
        AccountMeta::new_readonly(system_program::id(), false),
        AccountMeta::new_readonly(w.market, false),
    ];
    let (a, st) = (w.alice.insecure_clone(), w.stake);
    ok(w.tx(st, &[&a], accounts, data), "alice Deposit");

    let accounts = vec![
        AccountMeta::new(w.admin.pubkey(), true),
        AccountMeta::new(w.pool, false),
        AccountMeta::new_readonly(w.vault_auth, false),
        AccountMeta::new(w.market, false),
        AccountMeta::new_readonly(w.wrapper, false),
    ];
    ok(w.admin_stake(accounts, vec![19]), "Bind (19)");
    assert_eq!(
        w.pool().creator_seed_atoms(),
        SEED,
        "the real bind recorded the seed"
    );
    w
}

struct Trader {
    kp: Keypair,
    pf: Pubkey,
}

fn pf_epoch(w: &W, pf: &Pubkey) -> u64 {
    (read_u64(&w.svm, pf, PF_CONTROL_OFF) >> 1) & ((1u64 << 49) - 1)
}

fn trader(w: &mut W) -> Trader {
    let kp = Keypair::new();
    w.svm.airdrop(&kp.pubkey(), 10_000_000_000).unwrap();
    let pf_kp = Keypair::new();
    let pf = pf_kp.pubkey();
    let wid = w.wrapper;
    raw(&mut w.svm, pf, wid, vec![0u8; PF_LEN]);
    let accounts = vec![
        AccountMeta::new(kp.pubkey(), true),
        AccountMeta::new(w.market, false),
        AccountMeta::new(pf, true), // D26: the portfolio signs its init (rc23 #622)
    ];
    ok(
        w.tx(wid, &[&kp, &pf_kp], accounts, vec![1u8]),
        "InitPortfolio",
    );
    let src = Pubkey::new_unique();
    let (mint, k) = (w.mint, kp.pubkey());
    set_token(&mut w.svm, src, &mint, &k, TRADER_CAP);
    let mut d = vec![3u8];
    d.extend_from_slice(&read_u64(&w.svm, &pf, PF_ID_OFF).to_le_bytes());
    d.extend_from_slice(&read_u64(&w.svm, &pf, PF_SEQ_OFF).to_le_bytes());
    d.extend_from_slice(&(TRADER_CAP as u128).to_le_bytes());
    let accounts = vec![
        AccountMeta::new(k, true),
        AccountMeta::new(w.market, false),
        AccountMeta::new(pf, false),
        AccountMeta::new(src, false),
        AccountMeta::new(w.wvault, false),
        AccountMeta::new_readonly(token_program(), false),
    ];
    ok(w.tx(wid, &[&kp], accounts, d), "portfolio Deposit");
    Trader { kp, pf }
}

/// Wrapper tag 6 TradeNoCpi at PRICE with a REAL fee (FEE_BPS).
fn trade(w: &mut W, a: &Trader, b: &Trader, size_q: i128) {
    let mut d = vec![6u8];
    d.extend_from_slice(&read_u64(&w.svm, &a.pf, PF_ID_OFF).to_le_bytes());
    d.extend_from_slice(&pf_epoch(w, &a.pf).to_le_bytes());
    d.extend_from_slice(&read_u64(&w.svm, &b.pf, PF_ID_OFF).to_le_bytes());
    d.extend_from_slice(&pf_epoch(w, &b.pf).to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&read_u64(&w.svm, &w.market, ASSET0_MARKET_ID_OFF).to_le_bytes());
    d.extend_from_slice(&size_q.to_le_bytes());
    d.extend_from_slice(&PRICE.to_le_bytes());
    d.extend_from_slice(&FEE_BPS.to_le_bytes());
    d.extend_from_slice(&10_000u16.to_le_bytes());
    let accounts = vec![
        AccountMeta::new(a.kp.pubkey(), true),
        AccountMeta::new(b.kp.pubkey(), true),
        AccountMeta::new(w.market, false),
        AccountMeta::new(a.pf, false),
        AccountMeta::new(b.pf, false),
    ];
    let (ak, bk, wid) = (a.kp.insecure_clone(), b.kp.insecure_clone(), w.wrapper);
    ok(
        w.tx(wid, &[&ak, &bk], accounts, d),
        "fee-bearing TradeNoCpi",
    );
}

fn pf_withdraw_ix(w: &W, t: &Trader, dest: Pubkey, amount: u64) -> Instruction {
    let mut d = vec![4u8];
    d.extend_from_slice(&read_u64(&w.svm, &t.pf, PF_ID_OFF).to_le_bytes());
    d.extend_from_slice(&read_u64(&w.svm, &t.pf, PF_SEQ_OFF).to_le_bytes());
    d.extend_from_slice(&(amount as u128).to_le_bytes());
    Instruction {
        program_id: w.wrapper,
        accounts: vec![
            AccountMeta::new(t.kp.pubkey(), true),
            AccountMeta::new(w.market, false),
            AccountMeta::new(t.pf, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(w.wvault, false),
            AccountMeta::new_readonly(w.wvault_auth, false),
            AccountMeta::new_readonly(token_program(), false),
        ],
        data: d,
    }
}

/// Withdraw the largest amount the wrapper accepts (binary search by simulation), then
/// ClosePortfolio, so the market reaches terminal-empty (c_tot 0, no portfolio).
fn trader_exit(w: &mut W, t: &Trader) -> u64 {
    let dest = Pubkey::new_unique();
    let (mint, k) = (w.mint, t.kp.pubkey());
    set_token(&mut w.svm, dest, &mint, &k, 0);
    let (kp, payer) = (t.kp.insecure_clone(), w.payer.insecure_clone());
    let (mut lo, mut hi) = (0u64, TRADER_CAP + 1);
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        w.svm.expire_blockhash();
        let tx = Transaction::new_signed_with_payer(
            &[
                solana_sdk::compute_budget::ComputeBudgetInstruction::request_heap_frame(
                    128 * 1024,
                ),
                solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(
                    1_400_000,
                ),
                pf_withdraw_ix(w, t, dest, mid),
            ],
            Some(&payer.pubkey()),
            &[&payer, &kp],
            w.svm.latest_blockhash(),
        );
        if w.svm.simulate_transaction(tx).is_ok() {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let ix = pf_withdraw_ix(w, t, dest, lo);
    ok(send(&mut w.svm, &payer, &[&kp], ix), "portfolio Withdraw");
    let mut d = vec![8u8];
    d.extend_from_slice(&read_u64(&w.svm, &t.pf, PF_ID_OFF).to_le_bytes());
    d.extend_from_slice(&read_u64(&w.svm, &t.pf, PF_SEQ_OFF).to_le_bytes());
    d.extend_from_slice(&pf_epoch(w, &t.pf).to_le_bytes());
    let accounts = vec![
        AccountMeta::new(k, true),
        AccountMeta::new(w.market, false),
        AccountMeta::new(t.pf, false),
    ];
    let wid = w.wrapper;
    ok(w.tx(wid, &[&kp], accounts, d), "ClosePortfolio");
    lo
}

/// Real fee history (open + close `size` between two traders), traders exit, alice matures past
/// D8, stake AdminResolveMarket (24). Returns the legs before the resolve.
fn scene(size: i128) -> (W, Legs) {
    let mut w = world();
    let (a, b) = (trader(&mut w), trader(&mut w));
    trade(&mut w, &a, &b, size);
    trade(&mut w, &a, &b, -size);
    let l = w.legs();
    assert!(
        l.ins_acc > 0 && l.ins_wd == 0,
        "real trades accrued the staker leg: {l:?}"
    );
    let (ca, cb) = (trader_exit(&mut w, &a), trader_exit(&mut w, &b));
    println!(
        "GH#322 legs after trades {l:?}; traders withdrew {ca} + {cb}; wrapper vault {}",
        bal(&w.svm, &w.wvault)
    );
    w.warp(1_000);
    let accounts = vec![
        AccountMeta::new_readonly(w.admin.pubkey(), true),
        AccountMeta::new_readonly(w.pool, false),
        AccountMeta::new(w.market, false),
        AccountMeta::new_readonly(w.wrapper, false),
    ];
    ok(w.admin_stake(accounts, vec![24]), "AdminResolveMarket (24)");
    assert_eq!(w.terminal(), WrapperTerminal::Resolved);
    (w, l)
}

/// Stake tag 29 by an arbitrary caller, FEE_ONLY: [9] = the creator's token account.
fn tag29(w: &mut W, amount: u64) -> TxResult {
    let mut data = vec![29u8];
    data.extend_from_slice(&amount.to_le_bytes());
    let accounts = vec![
        AccountMeta::new_readonly(Pubkey::new_unique(), false),
        AccountMeta::new(w.pool, false),
        AccountMeta::new(w.vault, false),
        AccountMeta::new_readonly(w.vault_auth, false),
        AccountMeta::new(w.market, false),
        AccountMeta::new(w.wvault, false),
        AccountMeta::new_readonly(w.wvault_auth, false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(w.wrapper, false),
        AccountMeta::new(w.creator_ata, false),
    ];
    let st = w.stake;
    w.tx(st, &[], accounts, data)
}

/// ONE stake AdminCloseSlab (tag 30), deployed 10-account ABI, admin-signed.
fn close_slab(w: &mut W) -> TxResult {
    let pool_dest = Pubkey::new_unique();
    let (mint, pool) = (w.mint, w.pool);
    set_token(&mut w.svm, pool_dest, &mint, &pool, 0);
    let accounts = vec![
        AccountMeta::new(w.admin.pubkey(), true),
        AccountMeta::new(w.pool, false),
        AccountMeta::new(w.market, false),
        AccountMeta::new(w.wvault, false),
        AccountMeta::new_readonly(w.wvault_auth, false),
        AccountMeta::new(pool_dest, false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new(w.mint, false),
        AccountMeta::new(w.vault, false),
        AccountMeta::new_readonly(w.wrapper, false),
    ];
    w.admin_stake(accounts, vec![30])
}

fn alice_exit(w: &mut W) -> u64 {
    let lp = bal(&w.svm, &w.alice_lp);
    let before = bal(&w.svm, &w.alice_ata);
    let (dpda, _) = derive_deposit_pda(&w.stake, &w.pool, &w.alice.pubkey());
    let mut data = vec![2u8];
    data.extend_from_slice(&lp.to_le_bytes());
    let accounts = vec![
        AccountMeta::new(w.alice.pubkey(), true),
        AccountMeta::new(w.pool, false),
        AccountMeta::new(w.alice_lp, false),
        AccountMeta::new(w.lp_mint, false),
        AccountMeta::new(w.vault, false),
        AccountMeta::new(w.alice_ata, false),
        AccountMeta::new_readonly(w.vault_auth, false),
        AccountMeta::new(dpda, false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
        AccountMeta::new_readonly(w.market, false),
    ];
    let (a, st) = (w.alice.insecure_clone(), w.stake);
    ok(w.tx(st, &[&a], accounts, data), "alice Withdraw");
    bal(&w.svm, &w.alice_ata) - before
}

#[derive(Debug)]
struct Run {
    creator: u64,
    fees_booked_by_tag29: u64,
    ins_wd_jump: u128,
    alice_out: u64,
}

/// tag 29 BEFORE any AdminCloseSlab (the control ordering).
fn run_control(size: i128) -> Run {
    let (mut w, _) = scene(size);
    let f0 = w.pool().total_fees_earned;
    ok(tag29(&mut w, SEED), "control tag 29");
    let creator = bal(&w.svm, &w.creator_ata);
    let f1 = w.pool().total_fees_earned;
    let l0 = w.legs();
    let r = close_slab(&mut w);
    let l1 = w.legs();
    println!(
        "GH#322 control: tag29 creator {creator} fees {f0}->{f1}; then close -> {:?}; ins_wd {}->{}; terminal {:?}",
        custom(&r), l0.ins_wd, l1.ins_wd, w.terminal()
    );
    w.warp(10);
    let alice_out = alice_exit(&mut w);
    Run {
        creator,
        fees_booked_by_tag29: f1 - f0,
        ins_wd_jump: 0,
        alice_out,
    }
}

/// AdminCloseSlab FIRST (the documented close-out order), then tag 29.
fn run_close_first(size: i128) -> Run {
    let (mut w, _) = scene(size);
    let (l0, v0, wv0) = (w.legs(), bal(&w.svm, &w.vault), bal(&w.svm, &w.wvault));
    ok(close_slab(&mut w), "AdminCloseSlab #1");
    let (l1, v1, wv1) = (w.legs(), bal(&w.svm, &w.vault), bal(&w.svm, &w.wvault));
    println!(
        "GH#322 close #1 Ok; terminal {:?}; lp_acc {}; lp_wd {}->{}; ins_acc {}->{}; ins_wd {}->{}; pool vault {v0}->{v1}; wrapper vault {wv0}->{wv1}",
        w.terminal(), l0.lp_acc, l0.lp_wd, l1.lp_wd, l0.ins_acc, l1.ins_acc, l0.ins_wd, l1.ins_wd
    );
    assert_eq!(
        w.terminal(),
        WrapperTerminal::Resolved,
        "the re-book step returns Ok without closing"
    );
    assert_eq!((v0, wv0), (v1, wv1), "the re-book moved no token");
    let r2 = close_slab(&mut w);
    println!(
        "GH#322 close #2 -> {:?} ({})",
        custom(&r2),
        if r2.is_ok() { "Ok" } else { "Err" }
    );
    let f0 = w.pool().total_fees_earned;
    ok(tag29(&mut w, SEED), "tag 29 after the close");
    let creator = bal(&w.svm, &w.creator_ata);
    let f1 = w.pool().total_fees_earned;
    w.warp(10);
    let alice_out = alice_exit(&mut w);
    let run = Run {
        creator,
        fees_booked_by_tag29: f1 - f0,
        ins_wd_jump: l1.ins_wd - l0.ins_wd,
        alice_out,
    };
    println!(
        "GH#322 close-first size {size}: {run:?}; seed {SEED}; creator lost {}",
        SEED - creator
    );
    run
}

// ── Close first: the creator still gets the whole seed (failed on 3a7c4dd9) ─────────────

#[test]
fn close_first_creator_gets_full_seed() {
    let r = run_close_first(SIZE_BIG);
    assert_eq!(
        r.creator, SEED,
        "FEE_ONLY creator must get the whole intact seed back: {r:?}"
    );
    assert_eq!(
        r.fees_booked_by_tag29, 0,
        "no tag-87 atoms ever reached pool.vault: {r:?}"
    );
}

#[test]
fn close_first_small_history_creator_gets_full_seed() {
    let r = run_close_first(SIZE_SMALL);
    assert_eq!(
        r.creator, SEED,
        "FEE_ONLY creator must get the whole intact seed back: {r:?}"
    );
}

// ── Control: tag 29 before the close ──────────────────────────────────────────────────────

#[test]
fn control_tag29_first_creator_gets_full_seed() {
    let r = run_control(SIZE_BIG);
    assert_eq!(r.creator, SEED, "control: {r:?}");
    assert_eq!(r.fees_booked_by_tag29, 0, "control: {r:?}");
    assert_eq!(
        r.alice_out,
        ALICE - 1_000,
        "control: alice gets her stake back less the dead shares' 1000"
    );
}

// ── The re-book still moves the counter (wrapper unchanged); stake books none of it ────────

#[test]
fn close_first_counter_moves_but_nothing_is_booked() {
    for (size, jump) in [(SIZE_BIG, 6_400_000u128), (SIZE_SMALL, 1_600_000)] {
        let r = run_close_first(size);
        assert_eq!(
            r.ins_wd_jump, jump,
            "LP + staker leg re-booked with no transfer: {r:?}"
        );
        assert_eq!(r.creator, SEED, "{r:?}");
        assert_eq!(r.fees_booked_by_tag29, 0, "{r:?}");
        assert_eq!(
            r.alice_out,
            ALICE - 1_000,
            "alice gets exactly what the control pays: {r:?}"
        );
    }
}

/// Wrapper tag 41 sent DIRECTLY by a third party (FEE_ONLY: no units ledger), paying the
/// insurance budget into pool.vault without stake booking it.
fn direct_tag41(w: &mut W, amount: u64) -> TxResult {
    let mut data = vec![41u8];
    data.extend_from_slice(&(amount as u128).to_le_bytes());
    let accounts = vec![
        AccountMeta::new_readonly(w.vault_auth, false),
        AccountMeta::new(w.market, false),
        AccountMeta::new(w.vault, false),
        AccountMeta::new(w.wvault, false),
        AccountMeta::new_readonly(w.wvault_auth, false),
        AccountMeta::new_readonly(token_program(), false),
    ];
    let wid = w.wrapper;
    w.tx(wid, &[], accounts, data)
}

/// The Withdraw pre-accrue reader: third-party direct tag 41 (seed now in pool.vault), admin
/// close #1 (re-book), alice withdraws BEFORE any tag 29, then tag 29 (amount 0) forwards.
#[test]
fn direct41_close_withdraw_then_tag29_creator_gets_full_seed() {
    let (mut w, _) = scene(SIZE_BIG);
    ok(direct_tag41(&mut w, SEED), "direct tag 41");
    let wd0 = w.legs().ins_wd;
    ok(close_slab(&mut w), "AdminCloseSlab #1");
    assert!(w.legs().ins_wd > wd0, "the re-book moved the counter");
    w.warp(10);
    let alice_out = alice_exit(&mut w);
    let r = tag29(&mut w, 0);
    let creator = bal(&w.svm, &w.creator_ata);
    println!(
        "GH#322 direct41->close->withdraw->tag29(0): alice out {alice_out}; tag29 {:?}; creator {creator}; fees {}",
        custom(&r), w.pool().total_fees_earned
    );
    assert_eq!(
        alice_out,
        ALICE - 1_000,
        "alice is not paid the creator's seed"
    );
    assert_eq!(creator, SEED, "creator gets the whole seed");
    assert_eq!(w.pool().total_fees_earned, 0);
}

/// Wrapper tag 87 by a random signer (permissionless cranker).
fn tag87(w: &mut W) -> TxResult {
    let cranker = Keypair::new();
    w.svm.airdrop(&cranker.pubkey(), 1_000_000_000).unwrap();
    let accounts = vec![
        AccountMeta::new(cranker.pubkey(), true),
        AccountMeta::new(w.market, false),
        AccountMeta::new_readonly(w.pool, false),
        AccountMeta::new(w.vault, false),
        AccountMeta::new(w.wvault, false),
        AccountMeta::new_readonly(w.wvault_auth, false),
        AccountMeta::new_readonly(token_program(), false),
    ];
    let wid = w.wrapper;
    w.tx(wid, &[&cranker], accounts, vec![87u8])
}

/// The fix relies on the wrapper never paying tag 87 into a FEE_ONLY pool (`owed_staker_leg`:
/// mode-0 FIRST_LOSS only). Pin it: with a real staker leg owed, tag 87 refuses with 59
/// (StakePoolModeMismatch) and the counter does not move.
#[test]
fn wrapper_tag87_refuses_fee_only_pool() {
    let mut w = world();
    let (a, b) = (trader(&mut w), trader(&mut w));
    trade(&mut w, &a, &b, SIZE_BIG);
    trade(&mut w, &a, &b, -SIZE_BIG);
    let l0 = w.legs();
    assert!(
        l0.ins_acc > 0 && l0.ins_wd == 0,
        "a staker leg is owed: {l0:?}"
    );
    let r = tag87(&mut w);
    assert_eq!(
        custom(&r),
        Some(59),
        "tag 87 must refuse a FEE_ONLY pool: {}",
        logs(&r)
    );
    assert_eq!(w.legs().ins_wd, l0.ins_wd, "no payout recorded");
}
