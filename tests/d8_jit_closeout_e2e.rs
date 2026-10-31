//! D8 / stake #318 (M-3): JIT staking captures close-out growth. REAL stake .so + REAL wrapper
//! .so under LiteSVM (same artifacts and env as `gh311_closeout_direct_tag41_e2e.rs`:
//! `GH311_WRAPPER_SO` must pin stake 7JrgAUHi).
//!
//! The attack: a capital-rich staker deposits one slot before a predictable resolve. Deposits
//! were priced at BOOKED value, which excludes the close-out growth G (market insurance above
//! the creator's seed), and tag 29 books G pro rata to whoever holds LP at that moment, so the
//! late depositor took D/(D+LP) of G. The fix prices a deposit at booked value + pending G
//! (mark-to-close) and adds a maturity gate (LP minted within `MATURITY_GATE_SLOTS` of the
//! terminal does not share in the surplus; see `processor::young_lp_payout_cap`).
//!
//! Forged state, and only this: token balances used as funding, and the close-out seed record
//! (to model growth above the seed, as the gh311 `*_forged_seed` tests do).

#![allow(clippy::result_large_err, clippy::too_many_arguments, dead_code)]

use litesvm::LiteSVM;
use percolator_stake::state::{
    deposit_consent_bytes, derive_deposit_pda, derive_pool_pda, derive_vault_authority,
    derive_wrapper_ins_units, read_wrapper_ins_units, read_wrapper_terminal, StakePool,
    WrapperInsUnits, WrapperTerminal, STAKE_POOL_SIZE,
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
/// The stake id the deployed v2.2 wrapper pins (fresh-ID devnet build).
const STAKE_ID: &str = "7JrgAUHi4PxaRv5JKHoGAxodDFbozYexpERei66Xgq4V";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const MARKET_LEN_V22_CAP1: usize = 4059;
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;

/// The creator's insurance seed (wrapper tag 9 before the pool exists).
const SEED: u64 = 5_000_000;
const ALICE: u64 = 10_000_000;
const BOB: u64 = 2_000_000;
/// FIRST_LOSS: the sync deploys 50% of the 12M pool.
const DEPLOYED: u64 = 6_000_000;
/// FIRST_LOSS terminal fund: stake class 6M + creator class 5M.
const FUND: u64 = DEPLOYED + SEED;
/// The forged seed record of the growth tests: the creator seeded 3M, its units are worth 5M.
const SEED_LOW: u64 = 3_000_000;

const E_INSURANCE_UNITS_INVALID: u32 = 35;
const E_INVALID_ACCOUNT: u32 = 16;

const RISK_FIRST_LOSS: u8 = 1;
const RISK_FEE_ONLY: u8 = 2;

fn stake_so() -> PathBuf {
    if let Ok(p) = std::env::var("GH311_STAKE_SO") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/deploy/percolator_stake.so")
}

fn wrapper_so() -> PathBuf {
    if let Ok(p) = std::env::var("GH311_WRAPPER_SO") {
        return PathBuf::from(p);
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("percolator-prog/target/deploy/percolator_prog.so");
    p
}

fn token_program() -> Pubkey {
    Pubkey::from_str(TOKEN_PROGRAM).unwrap()
}

fn mint_data() -> Vec<u8> {
    let mut d = vec![0u8; 82];
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
    svm.set_account(
        key,
        Account {
            lamports: 2_039_280,
            data: token_data(mint, owner, amount),
            owner: token_program(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn token_amount(svm: &LiteSVM, key: &Pubkey) -> u64 {
    match svm.get_account(key) {
        Some(a) if a.data.len() >= 72 => u64::from_le_bytes(a.data[64..72].try_into().unwrap()),
        _ => 0,
    }
}

fn canonical_vault_ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    let ata_program = Pubkey::from_str(ATA_PROGRAM).unwrap();
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program().as_ref(), mint.as_ref()],
        &ata_program,
    )
    .0
}

/// Wrapper InitMarket, the same 219-byte form the F-9 / v5 suites use.
fn encode_init_market() -> Vec<u8> {
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

fn read_u64(svm: &LiteSVM, key: &Pubkey, off: usize) -> u64 {
    let d = svm.get_account(key).unwrap().data;
    u64::from_le_bytes(d[off..off + 8].try_into().unwrap())
}

struct Staker {
    kp: Keypair,
    ata: Pubkey,
    lp_ata: Pubkey,
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
    units: Pubkey,
    creator_ata: Pubkey,
    risk_mode: u8,
}

impl World {
    fn pool(&self) -> StakePool {
        let d = self.svm.get_account(&self.pool).unwrap().data;
        *bytemuck::from_bytes::<StakePool>(&d[..STAKE_POOL_SIZE])
    }

    fn units(&self) -> Option<WrapperInsUnits> {
        let a = self.svm.get_account(&self.units)?;
        read_wrapper_ins_units(&a.data, &self.market.to_bytes())
    }

    fn slot(&self) -> u64 {
        self.svm.get_sysvar::<solana_sdk::clock::Clock>().slot
    }

    fn warp(&mut self, slots: u64) {
        let s = self.slot() + slots;
        self.svm.warp_to_slot(s);
    }

    fn terminal(&self) -> WrapperTerminal {
        read_wrapper_terminal(&self.svm.get_account(&self.market).unwrap().data)
    }

    fn vault_balance(&self) -> u64 {
        token_amount(&self.svm, &self.vault)
    }

    fn tpv(&self) -> u64 {
        self.pool().total_pool_value().unwrap()
    }

    fn send_stake(
        &mut self,
        signers: &[&Keypair],
        accounts: Vec<AccountMeta>,
        data: Vec<u8>,
    ) -> TxResult {
        let payer = self.payer.insecure_clone();
        let ix = Instruction {
            program_id: self.stake_id,
            accounts,
            data,
        };
        send(&mut self.svm, &payer, signers, ix)
    }
}

/// Live market -> the creator seeds the insurance with SEED (wrapper tag 9) -> real InitPool
/// (`risk_mode`) -> FIRST_LOSS: real Bind (19, records the seed) + BurnAssetAdmin (21); FEE_ONLY:
/// the bind runs after the first deposit (see `scene`). No staker yet.
fn world(risk_mode: u8) -> World {
    world_with_bind(risk_mode, true)
}

/// `world`, optionally WITHOUT the FIRST_LOSS Bind + BurnAssetAdmin (the pool is then not the
/// market's insurance authority).
fn world_with_bind(risk_mode: u8, bind: bool) -> World {
    let (so, wso) = (stake_so(), wrapper_so());
    assert!(
        so.exists(),
        "GH#311 e2e: stake .so missing at {} (set GH311_STAKE_SO or `cargo build-sbf --features devnet`)",
        so.display()
    );
    assert!(
        wso.exists(),
        "GH#311 e2e: wrapper .so missing at {} (set GH311_WRAPPER_SO to the deployed v2.2 wrapper)",
        wso.display()
    );
    let mut svm = LiteSVM::new().with_spl_programs();
    svm.warp_to_slot(1_000);
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
    let wrapper_id = Pubkey::from_str(WRAPPER_ID).unwrap();
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
        Account {
            lamports: 1_000_000_000,
            data: mint_data(),
            owner: token_program(),
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    let wrapper_vault_auth =
        Pubkey::find_program_address(&[b"vault", market.as_ref()], &wrapper_id).0;
    let wrapper_vault = canonical_vault_ata(&wrapper_vault_auth, &mint);
    set_token_account(&mut svm, wrapper_vault, &mint, &wrapper_vault_auth, 0);
    svm.set_account(
        market,
        Account {
            lamports: 1_000_000_000,
            data: vec![0u8; MARKET_LEN_V22_CAP1],
            owner: wrapper_id,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    send(
        &mut svm,
        &payer,
        &[&admin],
        Instruction {
            program_id: wrapper_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new_readonly(mint, false),
            ],
            data: encode_init_market(),
        },
    )
    .unwrap_or_else(|e| panic!("InitMarket: {:?}\n{}", e.err, e.meta.logs.join("\n")));

    let src = Pubkey::new_unique();
    set_token_account(&mut svm, src, &mint, &admin.pubkey(), SEED);
    let mut d = vec![9u8];
    d.extend_from_slice(&read_u64(&svm, &market, ASSET0_MARKET_ID_OFF).to_le_bytes());
    d.extend_from_slice(&(read_u64(&svm, &market, ASSET0_INSURANCE_TOP_UP_OFF) + 1).to_le_bytes());
    d.extend_from_slice(&read_u64(&svm, &market, ASSET0_AUTHORITY_EPOCH_OFF).to_le_bytes());
    d.extend_from_slice(&(SEED as u128).to_le_bytes());
    send(
        &mut svm,
        &payer,
        &[&admin],
        Instruction {
            program_id: wrapper_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new(src, false),
                AccountMeta::new(wrapper_vault, false),
                AccountMeta::new_readonly(token_program(), false),
            ],
            data: d,
        },
    )
    .unwrap_or_else(|e| panic!("TopUpInsurance: {:?}\n{}", e.err, e.meta.logs.join("\n")));

    let (pool, _) = derive_pool_pda(&stake_id, &market);
    let (vault_auth, _) = derive_vault_authority(&stake_id, &pool);
    let lp_mint = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    for (k, n) in [(lp_mint, 82usize), (vault, 165usize)] {
        svm.set_account(
            k,
            Account {
                lamports: 1_000_000_000,
                data: vec![0u8; n],
                owner: token_program(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    }
    // 23-byte InitPool with an explicit risk mode. FIRST_LOSS: the protocol defaults (target
    // 5,000, buffer 3,000, hysteresis 500). FEE_ONLY: target 0. Cooldown 5 slots, uncapped.
    let mut ipd = vec![0u8];
    ipd.extend_from_slice(&5u64.to_le_bytes());
    ipd.extend_from_slice(&0u64.to_le_bytes());
    ipd.push(risk_mode);
    let target: u16 = if risk_mode == RISK_FIRST_LOSS {
        5_000
    } else {
        0
    };
    ipd.extend_from_slice(&target.to_le_bytes());
    ipd.extend_from_slice(&3_000u16.to_le_bytes());
    ipd.extend_from_slice(&500u16.to_le_bytes());
    send(
        &mut svm,
        &payer,
        &[&admin],
        Instruction {
            program_id: stake_id,
            accounts: vec![
                AccountMeta::new(admin.pubkey(), true),
                AccountMeta::new(market, false),
                AccountMeta::new(pool, false),
                AccountMeta::new(lp_mint, false),
                AccountMeta::new(vault, false),
                AccountMeta::new_readonly(vault_auth, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new_readonly(wrapper_id, false),
                AccountMeta::new_readonly(token_program(), false),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            ],
            data: ipd,
        },
    )
    .unwrap_or_else(|e| panic!("InitPool: {:?}\n{}", e.err, e.meta.logs.join("\n")));

    let creator_ata = Pubkey::new_unique();
    set_token_account(&mut svm, creator_ata, &mint, &admin.pubkey(), 0);
    let mut w = World {
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
        vault,
        lp_mint,
        units: derive_wrapper_ins_units(&wrapper_id, &market).0,
        creator_ata,
        risk_mode,
    };
    if risk_mode == RISK_FIRST_LOSS && bind {
        assert!(w.pool().is_first_loss());
        for tag in [19u8, 21u8] {
            bind_like(&mut w, tag);
        }
    }
    w
}

/// Stake tag 19 (Bind) or 21 (BurnAssetAdmin), admin-signed, pool writable.
fn bind_like(w: &mut World, tag: u8) {
    let admin = w.admin.insecure_clone();
    let accounts = vec![
        AccountMeta::new(w.admin.pubkey(), true),
        AccountMeta::new(w.pool, false),
        AccountMeta::new_readonly(w.vault_auth, false),
        AccountMeta::new(w.market, false),
        AccountMeta::new_readonly(w.wrapper_id, false),
    ];
    let r = w.send_stake(&[&admin], accounts, vec![tag]);
    assert!(r.is_ok(), "stake tag {tag}: {}", logs(&r));
}

fn new_staker(w: &mut World, amount: u64) -> Staker {
    let kp = Keypair::new();
    w.svm.airdrop(&kp.pubkey(), 10_000_000_000).unwrap();
    let ata = Pubkey::new_unique();
    let (mint, lp_mint) = (w.mint, w.lp_mint);
    set_token_account(&mut w.svm, ata, &mint, &kp.pubkey(), amount);
    let lp_ata = Pubkey::new_unique();
    set_token_account(&mut w.svm, lp_ata, &lp_mint, &kp.pubkey(), 0);
    Staker { kp, ata, lp_ata }
}

/// Stake tag 1. FIRST_LOSS: consent + the v5 tail (market writable, units ledger, wrapper).
/// FEE_ONLY: the #290 slab (read-only market).
fn deposit(w: &mut World, s: &Staker, amount: u64) -> TxResult {
    let (dpda, _) = derive_deposit_pda(&w.stake_id, &w.pool, &s.kp.pubkey());
    let mut data = vec![1u8];
    data.extend_from_slice(&amount.to_le_bytes());
    let mut accounts = vec![
        AccountMeta::new(s.kp.pubkey(), true),
        AccountMeta::new(w.pool, false),
        AccountMeta::new(s.ata, false),
        AccountMeta::new(w.vault, false),
        AccountMeta::new(w.lp_mint, false),
        AccountMeta::new(s.lp_ata, false),
        AccountMeta::new_readonly(w.vault_auth, false),
        AccountMeta::new(dpda, false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];
    if w.risk_mode == RISK_FIRST_LOSS {
        let p = w.pool();
        data.extend_from_slice(&deposit_consent_bytes(
            p.deploy_target_bps,
            p.liquid_buffer_bps,
            p.hysteresis_bps,
        ));
        accounts.push(AccountMeta::new(w.market, false));
        accounts.push(AccountMeta::new(w.units, false));
        accounts.push(AccountMeta::new_readonly(w.wrapper_id, false));
    } else {
        accounts.push(AccountMeta::new_readonly(w.market, false));
    }
    let kp = s.kp.insecure_clone();
    w.send_stake(&[&kp], accounts, data)
}

/// The tail a Withdraw passes after the 10 fixed accounts.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tail {
    /// No optional account (FEE_ONLY only; FIRST_LOSS requires the v5 tail).
    None,
    /// FEE_ONLY: the #290 slab only.
    Slab,
    /// FIRST_LOSS: market, units ledger, wrapper, system (the deployed ABI).
    V5,
    /// FIRST_LOSS with a WRONG units account at [11] (a random key).
    V5WrongUnits,
}

fn withdraw(w: &mut World, s: &Staker, lp: u64, tail: Tail) -> TxResult {
    let (dpda, _) = derive_deposit_pda(&w.stake_id, &w.pool, &s.kp.pubkey());
    let mut data = vec![2u8];
    data.extend_from_slice(&lp.to_le_bytes());
    let mut accounts = vec![
        AccountMeta::new(s.kp.pubkey(), true),
        AccountMeta::new(w.pool, false),
        AccountMeta::new(s.lp_ata, false),
        AccountMeta::new(w.lp_mint, false),
        AccountMeta::new(w.vault, false),
        AccountMeta::new(s.ata, false),
        AccountMeta::new_readonly(w.vault_auth, false),
        AccountMeta::new(dpda, false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
    ];
    match tail {
        Tail::None => {}
        Tail::Slab => accounts.push(AccountMeta::new_readonly(w.market, false)),
        Tail::V5 | Tail::V5WrongUnits => {
            let units = if tail == Tail::V5 {
                w.units
            } else {
                Pubkey::new_unique()
            };
            accounts.push(AccountMeta::new(w.market, false));
            accounts.push(AccountMeta::new(units, false));
            accounts.push(AccountMeta::new_readonly(w.wrapper_id, false));
            accounts.push(AccountMeta::new_readonly(system_program::id(), false));
        }
    }
    let kp = s.kp.insecure_clone();
    w.send_stake(&[&kp], accounts, data)
}

/// Withdraw all of `s`'s LP; returns the collateral paid.
fn exit_all(w: &mut World, s: &Staker, tail: Tail) -> u64 {
    let lp = token_amount(&w.svm, &s.lp_ata);
    let before = token_amount(&w.svm, &s.ata);
    let r = withdraw(w, s, lp, tail);
    assert!(r.is_ok(), "withdraw: {}", logs(&r));
    token_amount(&w.svm, &s.ata) - before
}

/// Stake tag 31, by a random permissionless caller.
fn sync(w: &mut World) -> TxResult {
    let caller = Keypair::new();
    w.svm.airdrop(&caller.pubkey(), 1_000_000_000).unwrap();
    let accounts = vec![
        AccountMeta::new(caller.pubkey(), true),
        AccountMeta::new(w.pool, false),
        AccountMeta::new(w.vault, false),
        AccountMeta::new_readonly(w.vault_auth, false),
        AccountMeta::new(w.market, false),
        AccountMeta::new(w.wrapper_vault, false),
        AccountMeta::new_readonly(w.wrapper_vault_auth, false),
        AccountMeta::new(w.units, false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(w.wrapper_id, false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];
    w.send_stake(&[&caller], accounts, vec![31])
}

fn admin_resolve(w: &mut World) {
    let admin = w.admin.insecure_clone();
    let accounts = vec![
        AccountMeta::new_readonly(w.admin.pubkey(), true),
        AccountMeta::new_readonly(w.pool, false),
        AccountMeta::new(w.market, false),
        AccountMeta::new_readonly(w.wrapper_id, false),
    ];
    let r = w.send_stake(&[&admin], accounts, vec![24]);
    assert!(r.is_ok(), "AdminResolveMarket: {}", logs(&r));
}

/// Stake tag 29 (permissionless). FIRST_LOSS: [9] units PDA, [10] creator account. FEE_ONLY: [9]
/// the creator account.
fn recover_terminal(w: &mut World, amount: u64) -> TxResult {
    let caller = Pubkey::new_unique();
    let mut data = vec![29u8];
    data.extend_from_slice(&amount.to_le_bytes());
    let mut accounts = vec![
        AccountMeta::new_readonly(caller, false),
        AccountMeta::new(w.pool, false),
        AccountMeta::new(w.vault, false),
        AccountMeta::new_readonly(w.vault_auth, false),
        AccountMeta::new(w.market, false),
        AccountMeta::new(w.wrapper_vault, false),
        AccountMeta::new_readonly(w.wrapper_vault_auth, false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(w.wrapper_id, false),
    ];
    if w.risk_mode == RISK_FIRST_LOSS {
        accounts.push(AccountMeta::new(w.units, false));
    }
    accounts.push(AccountMeta::new(w.creator_ata, false));
    w.send_stake(&[], accounts, data)
}

/// Wrapper tag 41 sent DIRECTLY by a third party (no stake instruction), naming the pool's
/// vault_auth (unsigned) as the authority and `pool.vault` as the destination. FIRST_LOSS: the
/// units ledger rides in the tail so the wrapper performs its class burn.
fn direct_tag41(w: &mut World, amount: u64) -> TxResult {
    let mut data = vec![41u8];
    data.extend_from_slice(&(amount as u128).to_le_bytes());
    let mut accounts = vec![
        AccountMeta::new_readonly(w.vault_auth, false),
        AccountMeta::new(w.market, false),
        AccountMeta::new(w.vault, false),
        AccountMeta::new(w.wrapper_vault, false),
        AccountMeta::new_readonly(w.wrapper_vault_auth, false),
        AccountMeta::new_readonly(token_program(), false),
    ];
    if w.risk_mode == RISK_FIRST_LOSS {
        accounts.push(AccountMeta::new(w.units, false));
    }
    let ix = Instruction {
        program_id: w.wrapper_id,
        accounts,
        data,
    };
    let payer = w.payer.insecure_clone();
    send(&mut w.svm, &payer, &[], ix)
}

/// Stake tag 30 (AdminCloseSlab), the deployed 10-account ABI, admin-signed. Retries: the wrapper
/// may need more than one CloseSlab call to reach the tombstone.
fn close_slab(w: &mut World) -> TxResult {
    let admin = w.admin.insecure_clone();
    let mut last = Ok(());
    for _ in 0..3 {
        let pool_dest = Pubkey::new_unique();
        let (mint, pool) = (w.mint, w.pool);
        set_token_account(&mut w.svm, pool_dest, &mint, &pool, 0);
        let accounts = vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(w.pool, false),
            AccountMeta::new(w.market, false),
            AccountMeta::new(w.wrapper_vault, false),
            AccountMeta::new_readonly(w.wrapper_vault_auth, false),
            AccountMeta::new(pool_dest, false),
            AccountMeta::new_readonly(token_program(), false),
            AccountMeta::new(w.mint, false),
            AccountMeta::new(w.vault, false),
            AccountMeta::new_readonly(w.wrapper_id, false),
        ];
        last = w.send_stake(&[&admin], accounts, vec![30]);
        if last.is_err() || w.terminal() == WrapperTerminal::Closed {
            break;
        }
    }
    last
}

/// FORGE the close-out seed record (bytes 457..464 + flag byte 333 bit 0).
fn forge_seed(w: &mut World, seed: u64) {
    let mut acct = w.svm.get_account(&w.pool).unwrap();
    acct.data[457..464].copy_from_slice(&seed.to_le_bytes()[..7]);
    acct.data[333] |= 1;
    w.svm.set_account(w.pool, acct).unwrap();
    assert_eq!(w.pool().creator_seed_atoms(), seed);
}

/// FORGE a creator-class loss: 2M stake units with no atoms (class invariant kept), so the
/// creator class is worth less than the seed at the terminal burn.
fn forge_creator_class_loss(w: &mut World) {
    let mut acct = w.svm.get_account(&w.units).unwrap();
    let u = w.units().unwrap();
    let off_total = percolator_stake::state::WRAPPER_INS_UNITS_OFF_UNITS_TOTAL;
    let off_stake = percolator_stake::state::WRAPPER_INS_UNITS_OFF_UNITS_STAKE;
    acct.data[off_total..off_total + 16]
        .copy_from_slice(&(u.units_total + 2_000_000).to_le_bytes());
    acct.data[off_stake..off_stake + 16]
        .copy_from_slice(&(u.units_stake + 2_000_000).to_le_bytes());
    w.svm.set_account(w.units, acct).unwrap();
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    /// Seed recorded at bind == creator class released (5M == 5M): the two models agree.
    Plain,
    /// Seed record forged to 3M; the creator class releases 5M: 2M of growth is the stakers'.
    Growth,
    /// Creator class worth less than the seed at terminal: the creator gets what is left.
    Loss,
}

/// FIRST_LOSS scene: creator seed 5M; alice 10M and bob 2M stake while Live; a permissionless
/// sync deploys 6M (50% of 12M) -> units {stake 6M, creator 5M}; `kind` forges; the admin
/// resolves; every cooldown has elapsed.
fn fl_scene(kind: Kind) -> (World, Staker, Staker) {
    let mut w = world(RISK_FIRST_LOSS);
    let alice = new_staker(&mut w, ALICE);
    let r = deposit(&mut w, &alice, ALICE);
    assert!(r.is_ok(), "alice deposit: {}", logs(&r));
    let bob = new_staker(&mut w, BOB);
    let r = deposit(&mut w, &bob, BOB);
    assert!(r.is_ok(), "bob deposit: {}", logs(&r));
    let r = sync(&mut w);
    assert!(r.is_ok(), "sync: {}", logs(&r));
    let u = w.units().expect("units ledger");
    assert_eq!(
        u.units_stake, DEPLOYED as u128,
        "PIN: the wrapper classes the pool's vault_auth as STAKE class. If this is 0, the wrapper \
         .so does not pin stake 7JrgAUHi: set GH311_WRAPPER_SO to the deployed v2.2 wrapper"
    );
    assert_eq!(
        u.units_creator, SEED as u128,
        "PIN: creator class = the seed"
    );
    assert_eq!(
        w.pool().creator_seed_atoms(),
        SEED,
        "PIN: the real bind recorded the seed"
    );
    match kind {
        Kind::Plain => {}
        Kind::Growth => forge_seed(&mut w, SEED_LOW),
        Kind::Loss => forge_creator_class_loss(&mut w),
    }
    admin_resolve(&mut w);
    assert_eq!(w.terminal(), WrapperTerminal::Resolved);
    assert_eq!(token_amount(&w.svm, &w.wrapper_vault), FUND);
    w.warp(100);
    (w, alice, bob)
}

/// FEE_ONLY scene: creator seed 5M (the whole fund, creator class), alice 10M and bob 2M; the
/// bind (after alice) records the seed; `growth` forges the record to 3M; resolved.
fn fo_scene(growth: bool) -> (World, Staker, Staker) {
    let mut w = world(RISK_FEE_ONLY);
    let alice = new_staker(&mut w, ALICE);
    let r = deposit(&mut w, &alice, ALICE);
    assert!(r.is_ok(), "alice deposit: {}", logs(&r));
    bind_like(&mut w, 19);
    assert_eq!(
        w.pool().creator_seed_atoms(),
        SEED,
        "PIN: the FEE_ONLY bind recorded the seed"
    );
    let bob = new_staker(&mut w, BOB);
    let r = deposit(&mut w, &bob, BOB);
    assert!(r.is_ok(), "bob deposit: {}", logs(&r));
    if growth {
        forge_seed(&mut w, SEED_LOW);
    }
    admin_resolve(&mut w);
    assert_eq!(w.terminal(), WrapperTerminal::Resolved);
    w.warp(100);
    (w, alice, bob)
}

// ─────────────────────────────────────────────────────────────────────────────
// D8 tests
// ─────────────────────────────────────────────────────────────────────────────

/// The JIT staker's capital: 10x the incumbent.
const JIT: u64 = 100_000_000;
/// Growth above the recorded seed in both scenes (fund 5M, seed record 3M).
const GROWTH: u64 = SEED - SEED_LOW;
/// Rounding / dead-share tolerance for "captures nothing": 1 bp of the JIT deposit.
const TOL: u64 = JIT / 10_000;

/// FEE_ONLY, Live: alice (10M) staked before the bind; the bind recorded the 5M seed; the seed
/// record is forged to 3M so 2M of the 5M fund is growth the stakers own at the close.
fn fo_live() -> (World, Staker) {
    let mut w = world(RISK_FEE_ONLY);
    let alice = new_staker(&mut w, ALICE);
    let r = deposit(&mut w, &alice, ALICE);
    assert!(r.is_ok(), "alice deposit: {}", logs(&r));
    bind_like(&mut w, 19);
    forge_seed(&mut w, SEED_LOW);
    // The incumbents are MATURE (staked long before any terminal): well past the gate.
    w.warp(1_000);
    (w, alice)
}

/// FIRST_LOSS, Live: alice 10M and bob 2M staked, a sync deployed 6M (units stake 6M /
/// creator 5M), the seed record forged to 3M (2M of creator-class growth).
fn fl_live() -> (World, Staker) {
    let mut w = world(RISK_FIRST_LOSS);
    let alice = new_staker(&mut w, ALICE);
    assert!(deposit(&mut w, &alice, ALICE).is_ok());
    let bob = new_staker(&mut w, BOB);
    assert!(deposit(&mut w, &bob, BOB).is_ok());
    let r = sync(&mut w);
    assert!(r.is_ok(), "sync: {}", logs(&r));
    assert_eq!(
        w.units().unwrap().units_stake,
        DEPLOYED as u128,
        "PIN: stake class"
    );
    forge_seed(&mut w, SEED_LOW);
    w.warp(1_000);
    (w, alice)
}

/// Resolve ONE slot after the JIT deposit, release the whole fund through tag 29, let every
/// cooldown elapse, then both stakers exit. Returns (jit_paid, alice_paid).
fn resolve_and_exit(
    w: &mut World,
    alice: &Staker,
    jit: &Staker,
    fund: u64,
    tail: Tail,
) -> (u64, u64) {
    w.warp(1);
    admin_resolve(w);
    assert_eq!(w.terminal(), WrapperTerminal::Resolved);
    w.warp(300);
    let r = recover_terminal(w, fund);
    assert!(r.is_ok(), "tag 29: {}", logs(&r));
    let jp = exit_all(w, jit, tail);
    let ap = exit_all(w, alice, tail);
    (jp, ap)
}

fn assert_jit_captures_nothing(jit_paid: u64, alice_paid: u64, alice_in: u64) {
    let profit = jit_paid as i128 - JIT as i128;
    assert!(
        profit <= TOL as i128,
        "JIT staker captured {profit} of the {GROWTH} growth (paid {jit_paid} for {JIT})"
    );
    // The incumbent keeps (all but dead-share dust of) the growth.
    assert!(
        alice_paid + 2 * TOL >= alice_in + GROWTH,
        "incumbent got {alice_paid}, expected about {}",
        alice_in + GROWTH
    );
}

/// RED on the pre-D8 build (the JIT staker takes ~1.8M of the 2M), GREEN after.
#[test]
fn d8_fee_only_jit_deposit_one_slot_before_resolve_captures_nothing() {
    let (mut w, alice) = fo_live();
    let jit = new_staker(&mut w, JIT);
    let r = deposit(&mut w, &jit, JIT);
    assert!(r.is_ok(), "jit deposit: {}", logs(&r));
    let (jp, ap) = resolve_and_exit(&mut w, &alice, &jit, SEED, Tail::Slab);
    assert_jit_captures_nothing(jp, ap, ALICE);
    assert_eq!(w.vault_balance(), w.tpv(), "conservation: vault == books");
}

#[test]
fn d8_first_loss_jit_deposit_one_slot_before_resolve_captures_nothing() {
    let (mut w, alice) = fl_live();
    // bob (2M) is also an incumbent: he is not exited here, so alice's expectation uses her
    // pro-rata share of the growth among the real LP (alice 10M of 12M).
    let jit = new_staker(&mut w, JIT);
    let r = deposit(&mut w, &jit, JIT);
    assert!(r.is_ok(), "jit deposit: {}", logs(&r));
    let fund = token_amount(&w.svm, &w.wrapper_vault);
    w.warp(1);
    admin_resolve(&mut w);
    w.warp(300);
    let r = recover_terminal(&mut w, fund);
    assert!(r.is_ok(), "tag 29: {}", logs(&r));
    let jp = exit_all(&mut w, &jit, Tail::V5);
    let profit = jp as i128 - JIT as i128;
    assert!(
        profit <= TOL as i128,
        "FIRST_LOSS JIT staker captured {profit} of the {GROWTH} growth"
    );
    let ap = exit_all(&mut w, &alice, Tail::V5);
    // alice holds 10/12 of the incumbents' LP: her share of the 2M growth.
    let want = ALICE + GROWTH * ALICE / (ALICE + BOB);
    assert!(
        ap + 2 * TOL >= want,
        "alice got {ap}, expected about {want}"
    );
}

/// The asymmetry is fail-safe: a depositor priced with pending growth who instead withdraws
/// from a LIVE market gets back no more than it put in (a round trip can only lose).
#[test]
fn d8_fee_only_live_round_trip_never_gains() {
    let (mut w, alice) = fo_live();
    let jit = new_staker(&mut w, JIT);
    assert!(deposit(&mut w, &jit, JIT).is_ok());
    w.warp(300);
    let paid = exit_all(&mut w, &jit, Tail::Slab);
    assert!(
        paid <= JIT,
        "round trip on a live market gained: {paid} > {JIT}"
    );
    let _ = alice;
}

/// A long-term staker (deposited long before, with a matching second staker joining after
/// the growth) is unaffected in the no-growth case: pricing without growth is the old price.
#[test]
fn d8_no_pending_growth_prices_exactly_as_before() {
    let mut w = world(RISK_FEE_ONLY);
    let alice = new_staker(&mut w, ALICE);
    assert!(deposit(&mut w, &alice, ALICE).is_ok());
    bind_like(&mut w, 19); // seed recorded == fund: G = 0
    let bob = new_staker(&mut w, BOB);
    assert!(deposit(&mut w, &bob, BOB).is_ok());
    let lp = token_amount(&w.svm, &bob.lp_ata);
    assert_eq!(lp, BOB, "no growth pending: 1:1 at an unmoved share price");
}

/// The mark-to-close price is exact: with growth pending, a deposit buys fewer LP, and the
/// LP it buys is worth exactly the deposit once the growth is booked.
#[test]
fn d8_pending_growth_is_priced_into_the_deposit() {
    let (mut w, _alice) = fo_live();
    let jit = new_staker(&mut w, BOB);
    assert!(deposit(&mut w, &jit, BOB).is_ok());
    let lp = token_amount(&w.svm, &jit.lp_ata);
    // booked value 10M, + 2M pending: BOB buys at 12M / (10M LP incl. dead shares).
    assert!(
        lp < BOB,
        "pending growth must raise the share price: minted {lp} for {BOB}"
    );
}

/// Raw SPL donation into the pool vault (token balances are forged funding): surplus the
/// pre-terminal reading cannot know about when a deposit is priced, so only the maturity gate
/// stands between a late depositor and it.
fn donate(w: &mut World, amount: u64) {
    let mut a = w.svm.get_account(&w.vault).unwrap();
    let cur = u64::from_le_bytes(a.data[64..72].try_into().unwrap());
    a.data[64..72].copy_from_slice(&(cur + amount).to_le_bytes());
    let vault = w.vault;
    w.svm.set_account(vault, a).unwrap();
}

const DON: u64 = 2_000_000;

/// The pinned `resolved_slot` offset really is the resolve slot on the deployed wrapper.
#[test]
fn d8_resolved_slot_offset_is_pinned() {
    use percolator_stake::state::read_wrapper_resolved_slot;
    use percolator_stake::wrapper_layout::MARKET_RESOLVED_SLOT_OFF;
    let (mut w, _alice) = fo_live();
    w.warp(7);
    let before = w.svm.get_account(&w.market).unwrap().data;
    assert_eq!(
        read_wrapper_resolved_slot(&before),
        None,
        "Live: no resolved slot"
    );
    assert_eq!(
        &before[MARKET_RESOLVED_SLOT_OFF..MARKET_RESOLVED_SLOT_OFF + 8],
        &[0u8; 8]
    );
    let slot = w.slot();
    admin_resolve(&mut w);
    let after = w.svm.get_account(&w.market).unwrap().data;
    assert_eq!(read_wrapper_resolved_slot(&after), Some(slot));
}

/// (ii) the gate alone, as a backstop: surplus that appears AFTER a deposit is priced (so
/// mark-to-close cannot have priced it) is not shared by LP minted within the gate of the
/// terminal. Young LP is paid at most what it cost; the incumbent keeps the whole surplus.
#[test]
fn d8_gate_young_lp_does_not_share_surplus_the_price_could_not_see() {
    let (mut w, alice) = fo_live();
    let jit = new_staker(&mut w, JIT);
    assert!(deposit(&mut w, &jit, JIT).is_ok());
    donate(&mut w, DON);
    let (jp, ap) = resolve_and_exit_after(&mut w, &alice, &jit, SEED, 1);
    assert!(
        jp <= JIT + TOL,
        "young LP shared the surplus: paid {jp} for {JIT}"
    );
    assert!(
        ap + 2 * TOL >= ALICE + GROWTH + DON,
        "incumbent got {ap}, expected about {}",
        ALICE + GROWTH + DON
    );
    assert_eq!(w.vault_balance(), w.tpv(), "conservation: vault == books");
}

/// Resolve `k` slots after the deposit; the boundary is exclusive: LP minted at `d` is young for
/// a terminal at `d + k` iff `k < MATURITY_GATE_SLOTS`.
fn resolve_and_exit_after(
    w: &mut World,
    alice: &Staker,
    jit: &Staker,
    fund: u64,
    k: u64,
) -> (u64, u64) {
    w.warp(k);
    admin_resolve(w);
    w.warp(300);
    let r = recover_terminal(w, fund);
    assert!(r.is_ok(), "tag 29: {}", logs(&r));
    let jp = exit_all(w, jit, Tail::Slab);
    let ap = exit_all(w, alice, Tail::Slab);
    (jp, ap)
}

#[test]
fn d8_gate_boundary_is_exclusive_at_n_slots() {
    use percolator_stake::state::MATURITY_GATE_SLOTS as N;
    // k = N - 1: young, capped at cost.
    let (mut w, alice) = fo_live();
    let jit = new_staker(&mut w, JIT);
    assert!(deposit(&mut w, &jit, JIT).is_ok());
    donate(&mut w, DON);
    let (jp, _) = resolve_and_exit_after(&mut w, &alice, &jit, SEED, N - 1);
    assert!(
        jp <= JIT + TOL,
        "N-1 slots before terminal is young: paid {jp}"
    );
    // k = N: mature, shares the surplus pro rata (the donation was not priced).
    let (mut w, alice) = fo_live();
    let jit = new_staker(&mut w, JIT);
    assert!(deposit(&mut w, &jit, JIT).is_ok());
    donate(&mut w, DON);
    let (jp, _) = resolve_and_exit_after(&mut w, &alice, &jit, SEED, N);
    assert!(
        jp > JIT + DON / 2,
        "N slots before terminal is mature and shares the donation: paid {jp}"
    );
}

/// A long-term staker is never touched: LP held since long before the terminal exits with its
/// full share of the growth and the donation.
#[test]
fn d8_gate_mature_incumbent_keeps_the_surplus() {
    let (mut w, alice) = fo_live();
    donate(&mut w, DON);
    w.warp(1);
    admin_resolve(&mut w);
    w.warp(300);
    assert!(recover_terminal(&mut w, SEED).is_ok());
    let ap = exit_all(&mut w, &alice, Tail::Slab);
    assert!(ap + TOL >= ALICE + GROWTH + DON, "incumbent got {ap}");
}

/// The tombstone erases the market's resolved_slot: AdminCloseSlab recorded it first, so the
/// gate still applies after CloseSlab.
#[test]
fn d8_gate_survives_the_close_slab_tombstone() {
    let (mut w, _alice) = fo_live();
    let jit = new_staker(&mut w, JIT);
    assert!(deposit(&mut w, &jit, JIT).is_ok());
    donate(&mut w, DON);
    w.warp(1);
    admin_resolve(&mut w);
    let t = w.slot();
    assert!(direct_tag41(&mut w, SEED).is_ok());
    let r = close_slab(&mut w);
    assert!(r.is_ok(), "AdminCloseSlab: {}", logs(&r));
    assert_eq!(w.terminal(), WrapperTerminal::Closed);
    assert_eq!(
        w.pool().terminal_slot_record(),
        Some(t),
        "tag 30 recorded the terminal slot"
    );
    w.warp(300);
    let paid = exit_all(&mut w, &jit, Tail::Slab);
    assert!(
        paid <= JIT + TOL,
        "young LP shared the surplus after the tombstone: paid {paid}"
    );
}

/// Partial exits: the young part is the LAST burned (mature LP first), and its bookkeeping
/// shrinks with it; a full exit clears it. (A non-genesis staker: the genesis record also
/// counts the 1,000 dead-share LP that no token account holds.)
#[test]
fn d8_gate_partial_exit_burns_mature_first_and_clears_the_young_record() {
    let (mut w, _alice) = fo_live();
    let top = 1_000_000u64;
    let bob = new_staker(&mut w, BOB + top);
    assert!(deposit(&mut w, &bob, BOB).is_ok());
    w.warp(1_000); // bob's first 2M is mature
    assert!(deposit(&mut w, &bob, top).is_ok()); // a young tranche on top
    let (dpda, _) = derive_deposit_pda(&w.stake_id, &w.pool, &bob.kp.pubkey());
    let rec = |w: &World| {
        let d = w.svm.get_account(&dpda).unwrap().data;
        let r = |o: usize| u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
        // StakeDeposit: 8 header + 32 pool + 32 user + 8 slot + 8 lp = 88; _reserved at 88.
        (r(88 + 16), r(88 + 24), r(88 + 32))
    };
    let (yl, yc, ys) = rec(&w);
    assert!(
        yl > 0 && yc == top && ys == w.slot(),
        "young tranche recorded: {yl} {yc} {ys}"
    );
    w.warp(1);
    admin_resolve(&mut w);
    w.warp(300);
    assert!(recover_terminal(&mut w, SEED).is_ok());
    let lp_total = token_amount(&w.svm, &bob.lp_ata);
    let mature = lp_total - yl;
    let r = withdraw(&mut w, &bob, mature, Tail::Slab);
    assert!(r.is_ok(), "{}", logs(&r));
    assert_eq!(
        rec(&w),
        (yl, yc, ys),
        "burning only mature LP leaves the young record"
    );
    let before = token_amount(&w.svm, &bob.ata);
    let r = withdraw(&mut w, &bob, yl, Tail::Slab);
    assert!(r.is_ok(), "{}", logs(&r));
    let paid = token_amount(&w.svm, &bob.ata) - before;
    assert!(
        paid <= top + 2,
        "the young tranche is paid at most its cost: {paid} > {top}"
    );
    assert_eq!(rec(&w), (0, 0, 0), "a full exit clears the young record");
}

/// (i) alone: a deposit placed N slots before the terminal is MATURE (the gate does not touch
/// it), and mark-to-close pricing by itself still leaves it nothing of the incumbents' growth.
#[test]
fn d8_pricing_alone_closes_the_jit_when_the_gate_does_not_apply() {
    use percolator_stake::state::MATURITY_GATE_SLOTS as N;
    let (mut w, alice) = fo_live();
    let jit = new_staker(&mut w, JIT);
    assert!(deposit(&mut w, &jit, JIT).is_ok());
    let (jp, ap) = resolve_and_exit_after(&mut w, &alice, &jit, SEED, N);
    assert_jit_captures_nothing(jp, ap, ALICE);
}

// ─────────────────────────────────────────────────────────────────────────────
// GH#331: the wrapper's staker fee leg on a Live FIRST_LOSS market. Real fee-bearing trades
// (wrapper TradeNoCpi) accrue it in the wrapper; the permissionless wrapper tag 87 pays it into
// `pool.vault`, where the pre-accrue books it to whoever holds LP at that moment. Forged, besides
// funding: the zero-filled wrapper-owned portfolio accounts (what a client's create_account
// produces).

const PF_LEN: usize = 10_603;
const PF_ID_OFF: usize = PF_LEN - 24;
const PF_SEQ_OFF: usize = PF_LEN - 16;
const PF_CONTROL_OFF: usize = PF_LEN - 24 - 104 + 96;
const TRADE_PRICE: u64 = 100;
const TRADE_FEE_BPS: u64 = 500;
const TRADER_CAP: u64 = 30_000_000_000;
const SIZE_Q: i128 = 1_000_000 * 1_000_000;
/// The staker leg one open + close of SIZE_Q accrues at these parameters.
const LEG: u64 = 1_600_000;

/// `insurance_reserve_accrued_atoms - insurance_reserve_withdrawn_atoms`, read raw.
fn staker_leg_owed(w: &World) -> u64 {
    use percolator_stake::state::{
        WRAPPER_OFF_INSURANCE_RESERVE_ACCRUED as ACC, WRAPPER_OFF_INSURANCE_RESERVE_WITHDRAWN as WD,
    };
    let d = w.svm.get_account(&w.market).unwrap().data;
    let r = |o: usize| u128::from_le_bytes(d[o..o + 16].try_into().unwrap());
    (r(ACC) - r(WD)) as u64
}

struct Trader {
    kp: Keypair,
    pf: Pubkey,
}

fn pf_epoch(w: &World, pf: &Pubkey) -> u64 {
    (read_u64(&w.svm, pf, PF_CONTROL_OFF) >> 1) & ((1u64 << 49) - 1)
}

/// Wrapper InitPortfolio (1) + portfolio Deposit (3) of `amount`.
fn trader(w: &mut World, amount: u64) -> Trader {
    let kp = Keypair::new();
    w.svm.airdrop(&kp.pubkey(), 10_000_000_000).unwrap();
    let pf = Pubkey::new_unique();
    let wid = w.wrapper_id;
    let acct = Account {
        lamports: 1_000_000_000,
        data: vec![0u8; PF_LEN],
        owner: wid,
        executable: false,
        rent_epoch: 0,
    };
    w.svm.set_account(pf, acct).unwrap();
    let payer = w.payer.insecure_clone();
    let ix = Instruction {
        program_id: wid,
        accounts: vec![
            AccountMeta::new(kp.pubkey(), true),
            AccountMeta::new(w.market, false),
            AccountMeta::new(pf, false),
        ],
        data: vec![1u8],
    };
    let r = send(&mut w.svm, &payer, &[&kp], ix);
    assert!(r.is_ok(), "InitPortfolio: {}", logs(&r));
    let src = Pubkey::new_unique();
    let (mint, k) = (w.mint, kp.pubkey());
    set_token_account(&mut w.svm, src, &mint, &k, amount);
    let mut d = vec![3u8];
    d.extend_from_slice(&read_u64(&w.svm, &pf, PF_ID_OFF).to_le_bytes());
    d.extend_from_slice(&read_u64(&w.svm, &pf, PF_SEQ_OFF).to_le_bytes());
    d.extend_from_slice(&(amount as u128).to_le_bytes());
    let ix = Instruction {
        program_id: wid,
        accounts: vec![
            AccountMeta::new(k, true),
            AccountMeta::new(w.market, false),
            AccountMeta::new(pf, false),
            AccountMeta::new(src, false),
            AccountMeta::new(w.wrapper_vault, false),
            AccountMeta::new_readonly(token_program(), false),
        ],
        data: d,
    };
    let r = send(&mut w.svm, &payer, &[&kp], ix);
    assert!(r.is_ok(), "portfolio Deposit: {}", logs(&r));
    Trader { kp, pf }
}

/// Wrapper TradeNoCpi (6) of `size_q` at TRADE_PRICE with a real TRADE_FEE_BPS fee.
fn trade(w: &mut World, a: &Trader, b: &Trader, size_q: i128) {
    let mut d = vec![6u8];
    d.extend_from_slice(&read_u64(&w.svm, &a.pf, PF_ID_OFF).to_le_bytes());
    d.extend_from_slice(&pf_epoch(w, &a.pf).to_le_bytes());
    d.extend_from_slice(&read_u64(&w.svm, &b.pf, PF_ID_OFF).to_le_bytes());
    d.extend_from_slice(&pf_epoch(w, &b.pf).to_le_bytes());
    d.extend_from_slice(&0u16.to_le_bytes());
    d.extend_from_slice(&read_u64(&w.svm, &w.market, ASSET0_MARKET_ID_OFF).to_le_bytes());
    d.extend_from_slice(&size_q.to_le_bytes());
    d.extend_from_slice(&TRADE_PRICE.to_le_bytes());
    d.extend_from_slice(&TRADE_FEE_BPS.to_le_bytes());
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
    let (ak, bk, payer) = (
        a.kp.insecure_clone(),
        b.kp.insecure_clone(),
        w.payer.insecure_clone(),
    );
    let r = send(&mut w.svm, &payer, &[&ak, &bk], ix);
    assert!(r.is_ok(), "fee-bearing TradeNoCpi: {}", logs(&r));
}

/// One open + close of SIZE_Q between two fresh traders: accrues LEG to the staker leg.
fn fee_round_trip(w: &mut World) {
    let a = trader(w, TRADER_CAP);
    let b = trader(w, TRADER_CAP);
    trade(w, &a, &b, SIZE_Q);
    trade(w, &a, &b, -SIZE_Q);
}

/// Wrapper tag 87 (WithdrawInsuranceReserveToStake), signed by a random key. Returns the amount
/// it moved into `pool.vault`.
fn tag87(w: &mut World) -> Result<u64, Option<u32>> {
    let cranker = Keypair::new();
    w.svm.airdrop(&cranker.pubkey(), 1_000_000_000).unwrap();
    let ix = Instruction {
        program_id: w.wrapper_id,
        accounts: vec![
            AccountMeta::new(cranker.pubkey(), true),
            AccountMeta::new(w.market, false),
            AccountMeta::new_readonly(w.pool, false),
            AccountMeta::new(w.vault, false),
            AccountMeta::new(w.wrapper_vault, false),
            AccountMeta::new_readonly(w.wrapper_vault_auth, false),
            AccountMeta::new_readonly(token_program(), false),
        ],
        data: vec![87u8],
    };
    let payer = w.payer.insecure_clone();
    let v0 = w.vault_balance();
    let r = send(&mut w.svm, &payer, &[&cranker], ix);
    match r {
        Ok(()) => Ok(w.vault_balance() - v0),
        Err(_) => Err(custom(&r)),
    }
}

/// FIRST_LOSS, Live, NO forged state: alice 10M and bob 2M stake, a sync deploys 6M, then one
/// fee round trip accrues LEG to the staker leg, not yet paid (nobody has cranked tag 87).
fn fl_fees() -> (World, Staker, Staker) {
    let mut w = world(RISK_FIRST_LOSS);
    let alice = new_staker(&mut w, ALICE);
    assert!(deposit(&mut w, &alice, ALICE).is_ok());
    let bob = new_staker(&mut w, BOB);
    assert!(deposit(&mut w, &bob, BOB).is_ok());
    let r = sync(&mut w);
    assert!(r.is_ok(), "sync: {}", logs(&r));
    w.warp(1_000);
    fee_round_trip(&mut w);
    assert_eq!(
        staker_leg_owed(&w),
        LEG,
        "real trades accrued the staker leg"
    );
    (w, alice, bob)
}

/// The value a FIRST_LOSS Deposit prices LP against before this fix: booked liquid value +
/// stake-class units at the entry reading.
fn fl_entry_value(w: &World) -> u64 {
    let deployed = w.units().map_or(0, |u| {
        percolator_stake::math::deployed_value(u.units_stake, u.units_total, u.snap_mint).unwrap()
    });
    w.tpv() + deployed
}

/// Exit `s` at the first slot its cooldown allows; returns the collateral paid.
fn exit_after_cooldown(w: &mut World, s: &Staker) -> u64 {
    let cd = w.pool().cooldown_slots;
    w.warp(cd + 1);
    exit_all(w, s, Tail::V5)
}

/// RED before GH#331 (the JIT staker takes floor(LEG * JIT / (JIT + 12M)) = 1,428,571 of the
/// 1.6M leg; bob gets 2,028,571 instead of ~2,266,666), GREEN after: the deposit is priced with
/// the owed leg, so the crank it then triggers moves nothing to it.
#[test]
fn staker_leg_jit_deposit_then_tag87_captures_nothing() {
    let (mut w, _alice, bob) = fl_fees();
    let jit = new_staker(&mut w, JIT);
    let r = deposit(&mut w, &jit, JIT);
    assert!(r.is_ok(), "jit deposit: {}", logs(&r));
    assert_eq!(
        tag87(&mut w),
        Ok(LEG),
        "the permissionless crank pays the whole leg"
    );
    let paid = exit_after_cooldown(&mut w, &jit);
    let profit = paid as i128 - JIT as i128;
    assert!(
        profit <= 0 && profit > -(TOL as i128),
        "JIT staker captured {profit} of the {LEG} staker leg (paid {paid} for {JIT})"
    );
    // The incumbents keep the leg: bob's pro-rata share of it (2M of 12M), less dead-share dust.
    let bob_paid = exit_all(&mut w, &bob, Tail::V5);
    let want = BOB + LEG * BOB / (ALICE + BOB);
    assert!(
        bob_paid.abs_diff(want) < TOL,
        "bob got {bob_paid}, expected about {want}"
    );
}

/// Exactness: the priced leg is what tag 87 pays in the same slot, and nothing once paid.
#[test]
fn staker_leg_reader_matches_the_real_tag87_payout() {
    use percolator_stake::state::read_wrapper_staker_fee_leg;
    let (mut w, _alice, _bob) = fl_fees();
    let leg = |w: &World| {
        let d = w.svm.get_account(&w.market).unwrap().data;
        read_wrapper_staker_fee_leg(&d, &w.vault_auth.to_bytes())
    };
    assert_eq!(leg(&w), Some(LEG as u128));
    assert_eq!(tag87(&mut w), Ok(LEG));
    assert_eq!(leg(&w), Some(0));
    // Nothing owed: tag 87 refuses (NoInsuranceReserveToClaim) and the reader agrees.
    assert!(tag87(&mut w).is_err());
}

/// Crank first: the leg is booked before the deposit prices, so the price is the one the pool
/// always used (booked value incl. the payout, + deployed units), to the atom.
#[test]
fn staker_leg_crank_first_prices_exactly_as_before() {
    let (mut w, _alice, _bob) = fl_fees();
    assert_eq!(tag87(&mut w), Ok(LEG));
    let want = percolator_stake::math::calc_lp_for_deposit(
        w.pool().total_lp_supply,
        fl_entry_value(&w) + LEG, // the deposit's pre-accrue books the payout first
        JIT,
    )
    .unwrap();
    let jit = new_staker(&mut w, JIT);
    assert!(deposit(&mut w, &jit, JIT).is_ok());
    assert_eq!(token_amount(&w.svm, &jit.lp_ata), want);
    let paid = exit_after_cooldown(&mut w, &jit);
    assert!(
        paid <= JIT && paid + TOL > JIT,
        "round trip paid {paid} for {JIT}"
    );
}

/// No fee history (nothing owed): an honest deposit mints exactly what it did before.
#[test]
fn staker_leg_nothing_owed_prices_exactly_as_before() {
    let mut w = world(RISK_FIRST_LOSS);
    let alice = new_staker(&mut w, ALICE);
    assert!(deposit(&mut w, &alice, ALICE).is_ok());
    assert!(sync(&mut w).is_ok());
    w.warp(1_000);
    assert_eq!(staker_leg_owed(&w), 0);
    let want = percolator_stake::math::calc_lp_for_deposit(
        w.pool().total_lp_supply,
        fl_entry_value(&w),
        BOB,
    )
    .unwrap();
    let bob = new_staker(&mut w, BOB);
    assert!(deposit(&mut w, &bob, BOB).is_ok());
    assert_eq!(token_amount(&w.svm, &bob.lp_ata), want);
}

/// With no real LP holder (only the dead shares) the owed leg is not priced: the deposit mints
/// exactly what it did before (that backlog is left as it was, see `accrue_fees_inner`).
#[test]
fn staker_leg_is_not_priced_without_real_lp_holders() {
    let mut w = world(RISK_FIRST_LOSS);
    let alice = new_staker(&mut w, ALICE);
    assert!(deposit(&mut w, &alice, ALICE).is_ok());
    w.warp(1_000);
    fee_round_trip(&mut w);
    exit_all(&mut w, &alice, Tail::V5);
    assert_eq!(
        w.pool().total_lp_supply,
        percolator_stake::state::MINIMUM_LIQUIDITY,
        "only the dead shares are left"
    );
    assert_eq!(staker_leg_owed(&w), LEG);
    let want = percolator_stake::math::calc_lp_for_deposit(
        w.pool().total_lp_supply,
        fl_entry_value(&w),
        BOB,
    )
    .unwrap();
    let bob = new_staker(&mut w, BOB);
    let r = deposit(&mut w, &bob, BOB);
    assert!(r.is_ok(), "deposit: {}", logs(&r));
    assert_eq!(token_amount(&w.svm, &bob.lp_ata), want);
}

/// FEE_ONLY: tag 87 never pays this pool (StakePoolModeMismatch, 59), and its deposit price does
/// not move with the wrapper's staker leg.
#[test]
fn staker_leg_fee_only_pool_is_not_priced() {
    let mut w = world(RISK_FEE_ONLY);
    let alice = new_staker(&mut w, ALICE);
    assert!(deposit(&mut w, &alice, ALICE).is_ok());
    bind_like(&mut w, 19);
    w.warp(1_000);
    fee_round_trip(&mut w);
    assert_eq!(staker_leg_owed(&w), LEG);
    assert_eq!(tag87(&mut w), Err(Some(59)));
    let want = percolator_stake::math::calc_lp_for_deposit(w.pool().total_lp_supply, w.tpv(), JIT)
        .unwrap();
    let jit = new_staker(&mut w, JIT);
    assert!(deposit(&mut w, &jit, JIT).is_ok());
    assert_eq!(token_amount(&w.svm, &jit.lp_ata), want);
}

/// A FIRST_LOSS pool that is not the market's insurance authority (no Bind): tag 87 refuses it
/// (wrapper StakePoolAuthorityMismatch, 56), so the leg the wrapper has accrued is not priced.
#[test]
fn staker_leg_unbound_pool_is_not_priced() {
    let mut w = world_with_bind(RISK_FIRST_LOSS, false);
    let alice = new_staker(&mut w, ALICE);
    assert!(deposit(&mut w, &alice, ALICE).is_ok());
    w.warp(1_000);
    fee_round_trip(&mut w);
    assert_eq!(staker_leg_owed(&w), LEG);
    assert_eq!(tag87(&mut w), Err(Some(56)));
    let want = percolator_stake::math::calc_lp_for_deposit(
        w.pool().total_lp_supply,
        fl_entry_value(&w),
        BOB,
    )
    .unwrap();
    let bob = new_staker(&mut w, BOB);
    assert!(deposit(&mut w, &bob, BOB).is_ok());
    assert_eq!(token_amount(&w.svm, &bob.lp_ata), want);
}
