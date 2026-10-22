//! GH#311 on the CLOSE-OUT line (deployed v2.2 stake 0f88ff1): a permissionless DIRECT wrapper
//! tag 41 pays a Resolved market's insurance into `pool.vault` without stake booking it. A
//! Withdraw that lands before the next tag 29 used to price against the unbooked value and
//! under-pay (50% in the reporter's PoC); the difference went to the remaining stakers.
//!
//! The rule under test (close-out model, `StakePool::closeout_creator_share`): on a Resolved
//! market, Withdraw first books exactly what tag 29 would book, i.e. the vault surplus minus the
//! creator's close-out share `min(surplus, min(seed, creator class released) - forwarded)`
//! (FIRST_LOSS: released = the wrapper's `creator_paid_to_stake`, read from the same freshly
//! refreshed `InsuranceUnitsV20` the Withdraw already prices with; FEE_ONLY: the seed alone). The
//! creator's share stays unbooked in the vault for tag 29 to forward. Live markets book nothing
//! (#290). So every ordering below must give the staker exactly what the tag-29-first CONTROL
//! gives, and the creator exactly the close-out share.
//!
//! This differs from PR #312 (merged on `devnet/v22-fresh-ids`, a different lineage), which
//! excluded the whole unforwarded `creator_paid_to_stake`: the `growth` tests below, where the
//! creator class released more than the seed recorded at bind, tell the two rules apart.
//!
//! REAL stake .so + REAL wrapper .so under LiteSVM. The stake program is loaded at 7JrgAUHi, the
//! id the deployed v2.2 wrapper pins, so the wrapper classes the pool's vault_auth as the STAKE
//! unit class. Artifacts (a missing .so is a HARD FAILURE, never a skip):
//!   * stake:   `GH311_STAKE_SO`, default `target/deploy/percolator_stake.so`;
//!   * wrapper: `GH311_WRAPPER_SO`, default `../percolator-prog/target/deploy/percolator_prog.so`.
//!     It must pin stake 7JrgAUHi: use the deployed v2.2 wrapper (6kpg2wi7, percolator-prog
//!     153c62fc `--features devnet`, sha256 01e159ce…). A wrapper pinning another stake id fails
//!     the `PIN` asserts in `scene` (every unit would be creator class).
//!
//! Forged state, and only this: token balances used as funding; the close-out seed record in
//! `*_forged_seed` tests (to model creator-unit growth above the seed); the unit ledger's class
//! counts in `*_forged_ledger` tests (to model a creator-class loss); a Live-mode vault donation.

#![allow(clippy::result_large_err, clippy::too_many_arguments)]

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
    if risk_mode == RISK_FIRST_LOSS {
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

/// Everything an assertion needs after a path has run.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    bob_paid: u64,
    creator_got: u64,
    vault: u64,
    pool_value: u64,
    total_returned: u64,
    total_fees: u64,
}

fn outcome(w: &World, bob_paid: u64) -> Outcome {
    let p = w.pool();
    Outcome {
        bob_paid,
        creator_got: token_amount(&w.svm, &w.creator_ata),
        vault: w.vault_balance(),
        pool_value: p.total_pool_value().unwrap(),
        total_returned: p.total_returned,
        total_fees: p.total_fees_earned,
    }
}

/// CONTROL: tag 29 releases the whole fund first (creator share forwarded, rest booked), then
/// bob exits. Every other ordering must match it.
fn control(kind: Kind) -> Outcome {
    let (mut w, _alice, bob) = fl_scene(kind);
    let r = recover_terminal(&mut w, FUND);
    assert!(r.is_ok(), "control tag 29: {}", logs(&r));
    let paid = exit_all(&mut w, &bob, Tail::V5);
    outcome(&w, paid)
}

/// The creator's close-out share of a FIRST_LOSS scene.
fn fl_creator_share(w: &World, kind: Kind) -> u64 {
    let released = w.units().unwrap().creator_paid_to_stake as u64;
    let seed = if kind == Kind::Growth { SEED_LOW } else { SEED };
    seed.min(released)
}

// ─────────────────────────────────────────────────────────────────────────────
// FIRST_LOSS: direct tag 41 -> Withdraw (the filed underpay)
// ─────────────────────────────────────────────────────────────────────────────

fn direct41_then_withdraw(kind: Kind) {
    let c = control(kind);
    let (mut w, _alice, bob) = fl_scene(kind);
    let r = direct_tag41(&mut w, FUND);
    assert!(r.is_ok(), "direct tag 41: {}", logs(&r));
    let u = w.units().unwrap();
    assert_eq!(u.units_stake, 0, "the wrapper burned the stake class");
    assert_eq!(
        w.vault_balance(),
        DEPLOYED + FUND,
        "6M liquid + the 11M fund"
    );
    assert_eq!(
        w.pool().creator_total_forwarded_atoms(),
        0,
        "nothing forwarded yet"
    );
    let paid = exit_all(&mut w, &bob, Tail::V5);
    assert_eq!(
        paid, c.bob_paid,
        "{kind:?}: bob must get what the tag-29-first control pays (got {paid}, control {})",
        c.bob_paid
    );
    // The creator's close-out share is still in the vault, unbooked; nothing else is.
    let share = fl_creator_share(&w, kind);
    assert_eq!(
        w.vault_balance() - w.tpv(),
        share,
        "{kind:?}: exactly the creator's share unbooked"
    );
}

/// The reporter's PoC (`poc2_attack_direct_tag41_underpays_bob`) on the close-out line: seed ==
/// creator class released. Before the fix bob got 1,000,000 of 2,000,000.
#[test]
fn gh311_fl_direct_tag41_then_withdraw_pays_the_control() {
    direct41_then_withdraw(Kind::Plain);
}

/// Growth above the seed belongs to the stakers (close-out rule): bob's share includes it. This
/// is the case where PR #312's rule (exclude all of `creator_paid_to_stake`) would under-pay bob
/// by his share of the 2M growth.
#[test]
fn gh311_fl_growth_direct_tag41_then_withdraw_pays_the_control_forged_seed() {
    let c = control(Kind::Growth);
    assert!(
        c.bob_paid > BOB,
        "PIN: the control pays bob part of the growth ({})",
        c.bob_paid
    );
    direct41_then_withdraw(Kind::Growth);
}

/// The creator class lost value (creator gets what is left of the seed, < seed).
#[test]
fn gh311_fl_loss_direct_tag41_then_withdraw_pays_the_control_forged_ledger() {
    direct41_then_withdraw(Kind::Loss);
}

/// Both stakers leave after a direct tag 41, then tag 29 settles: stakers together get exactly
/// the control's total, the creator exactly the close-out share, nothing is booked twice, and
/// nothing is left in the vault but the dead-share floor's value.
fn direct41_everyone_exits_then_tag29(kind: Kind) {
    // Reference: tag 29 first, then both exit.
    let (mut w, alice, bob) = fl_scene(kind);
    assert!(recover_terminal(&mut w, FUND).is_ok());
    let ref_paid = exit_all(&mut w, &bob, Tail::V5) + exit_all(&mut w, &alice, Tail::V5);
    let ref_creator = token_amount(&w.svm, &w.creator_ata);
    let ref_left = w.vault_balance();

    let (mut w, alice, bob) = fl_scene(kind);
    assert!(direct_tag41(&mut w, FUND).is_ok());
    let paid = exit_all(&mut w, &bob, Tail::V5) + exit_all(&mut w, &alice, Tail::V5);
    assert_eq!(
        paid, ref_paid,
        "{kind:?}: stakers' total matches the control"
    );
    let share = fl_creator_share(&w, kind);
    let before = w.pool();
    let r = recover_terminal(&mut w, 0);
    assert!(r.is_ok(), "tag 29 after the exits: {}", logs(&r));
    assert_eq!(
        token_amount(&w.svm, &w.creator_ata),
        share,
        "{kind:?}: creator gets its share"
    );
    assert_eq!(token_amount(&w.svm, &w.creator_ata), ref_creator);
    let after = w.pool();
    assert_eq!(
        after.total_returned, before.total_returned,
        "no double booking (principal)"
    );
    assert_eq!(
        after.total_fees_earned, before.total_fees_earned,
        "no double booking (fees)"
    );
    assert_eq!(
        w.vault_balance(),
        ref_left,
        "{kind:?}: same residue as the control"
    );
    assert_eq!(w.vault_balance(), w.tpv(), "vault == books");
}

#[test]
fn gh311_fl_direct_tag41_everyone_exits_then_tag29_forwards_exact_share() {
    direct41_everyone_exits_then_tag29(Kind::Plain);
}

#[test]
fn gh311_fl_growth_direct_tag41_everyone_exits_then_tag29_forwards_exact_share_forged_seed() {
    direct41_everyone_exits_then_tag29(Kind::Growth);
}

#[test]
fn gh311_fl_loss_direct_tag41_everyone_exits_then_tag29_forwards_exact_share_forged_ledger() {
    direct41_everyone_exits_then_tag29(Kind::Loss);
}

// ─────────────────────────────────────────────────────────────────────────────
// FIRST_LOSS: direct tag 41 -> tag 29 / tag 30 (already correct on 0f88ff1; regression guards)
// ─────────────────────────────────────────────────────────────────────────────

fn direct41_then_tag29_matches_control(kind: Kind) {
    let c = control(kind);
    let (mut w, _alice, bob) = fl_scene(kind);
    assert!(direct_tag41(&mut w, FUND).is_ok());
    let r = recover_terminal(&mut w, 0);
    assert!(
        r.is_ok(),
        "tag 29 (amount 0) after a direct tag 41: {}",
        logs(&r)
    );
    let paid = exit_all(&mut w, &bob, Tail::V5);
    assert_eq!(
        outcome(&w, paid),
        c,
        "{kind:?}: tag 41 -> 29 -> withdraw == control"
    );
}

#[test]
fn gh311_fl_direct_tag41_then_tag29_matches_the_control() {
    direct41_then_tag29_matches_control(Kind::Plain);
}

#[test]
fn gh311_fl_growth_direct_tag41_then_tag29_matches_the_control_forged_seed() {
    direct41_then_tag29_matches_control(Kind::Growth);
}

#[test]
fn gh311_fl_loss_direct_tag41_then_tag29_matches_the_control_forged_ledger() {
    direct41_then_tag29_matches_control(Kind::Loss);
}

/// tag 41 -> Withdraw (books) -> tag 29: the Withdraw's booking and tag 29's forward add up to the
/// control exactly (the creator is never short, the stakers never double-credited).
fn direct41_withdraw_then_tag29(kind: Kind) {
    let (mut w, alice, bob) = fl_scene(kind);
    assert!(recover_terminal(&mut w, FUND).is_ok());
    let ref_creator = token_amount(&w.svm, &w.creator_ata);
    let ref_tpv = w.tpv();
    let ref_alice_value = {
        let p = w.pool();
        let lp = token_amount(&w.svm, &alice.lp_ata);
        (lp as u128 * ref_tpv as u128 / p.total_lp_supply as u128) as u64
    };
    let _ = bob;

    let (mut w, alice, bob) = fl_scene(kind);
    assert!(direct_tag41(&mut w, FUND).is_ok());
    let _ = exit_all(&mut w, &bob, Tail::V5);
    let r = recover_terminal(&mut w, 0);
    assert!(r.is_ok(), "tag 29: {}", logs(&r));
    assert_eq!(
        token_amount(&w.svm, &w.creator_ata),
        ref_creator,
        "{kind:?}: creator share"
    );
    let p = w.pool();
    let lp = token_amount(&w.svm, &alice.lp_ata);
    let alice_value = (lp as u128 * w.tpv() as u128 / p.total_lp_supply as u128) as u64;
    assert!(
        alice_value.abs_diff(ref_alice_value) <= 1,
        "{kind:?}: alice's share value {alice_value} vs control {ref_alice_value}"
    );
    assert_eq!(w.vault_balance(), w.tpv(), "vault == books");
}

#[test]
fn gh311_fl_direct_tag41_withdraw_then_tag29_conserves() {
    direct41_withdraw_then_tag29(Kind::Plain);
}

#[test]
fn gh311_fl_growth_direct_tag41_withdraw_then_tag29_conserves_forged_seed() {
    direct41_withdraw_then_tag29(Kind::Growth);
}

#[test]
fn gh311_fl_loss_direct_tag41_withdraw_then_tag29_conserves_forged_ledger() {
    direct41_withdraw_then_tag29(Kind::Loss);
}

/// tag 41 -> tag 30 -> tag 29 (amount 0 on the tombstone): tag 30 reserves the seed-capped share
/// (it has no units account, so the cap is the seed alone: >= the true share) and books the rest;
/// tag 29 then forwards the exact share and books any over-reservation to the stakers. End
/// state == the control's books.
fn direct41_close_then_tag29(kind: Kind) {
    let (mut w, _alice, _bob) = fl_scene(kind);
    assert!(recover_terminal(&mut w, FUND).is_ok());
    let ref_creator = token_amount(&w.svm, &w.creator_ata);
    let ref_tpv = w.tpv();

    let (mut w, _alice, _bob) = fl_scene(kind);
    assert!(direct_tag41(&mut w, FUND).is_ok());
    let r = close_slab(&mut w);
    assert!(r.is_ok(), "AdminCloseSlab: {}", logs(&r));
    assert_eq!(w.terminal(), WrapperTerminal::Closed);
    let seed = w.pool().creator_seed_atoms();
    assert_eq!(
        w.vault_balance() - w.tpv(),
        seed,
        "{kind:?}: tag 30 reserves the seed cap"
    );
    let r = recover_terminal(&mut w, 0);
    assert!(r.is_ok(), "tag 29 on the tombstone: {}", logs(&r));
    assert_eq!(
        token_amount(&w.svm, &w.creator_ata),
        ref_creator,
        "{kind:?}: creator share"
    );
    assert_eq!(w.tpv(), ref_tpv, "{kind:?}: stakers' books == control");
    assert_eq!(w.vault_balance(), w.tpv(), "vault == books");
}

#[test]
fn gh311_fl_direct_tag41_close_slab_then_tag29_matches_the_control() {
    direct41_close_then_tag29(Kind::Plain);
}

#[test]
fn gh311_fl_growth_direct_tag41_close_slab_then_tag29_matches_the_control_forged_seed() {
    direct41_close_then_tag29(Kind::Growth);
}

#[test]
fn gh311_fl_loss_direct_tag41_close_slab_then_tag29_matches_the_control_forged_ledger() {
    direct41_close_then_tag29(Kind::Loss);
}

// ─────────────────────────────────────────────────────────────────────────────
// FIRST_LOSS: partial tag 41, repeated withdrawals, Live (#290), account checks
// ─────────────────────────────────────────────────────────────────────────────

/// A partial direct tag 41 inside the stake class (no creator value released): the creator's
/// share is 0, so Withdraw books it all, exactly as tag 29 with the same amount would.
#[test]
fn gh311_fl_partial_direct_tag41_within_stake_class_matches_tag29() {
    const PARTIAL: u64 = 3_000_000;
    let (mut w, _alice, bob) = fl_scene(Kind::Plain);
    assert!(recover_terminal(&mut w, PARTIAL).is_ok());
    let ctrl_paid = exit_all(&mut w, &bob, Tail::V5);
    let ctrl = outcome(&w, ctrl_paid);

    let (mut w, _alice, bob) = fl_scene(Kind::Plain);
    assert!(direct_tag41(&mut w, PARTIAL).is_ok());
    assert_eq!(
        w.units().unwrap().creator_paid_to_stake,
        0,
        "PIN: the stake class covered it"
    );
    let paid = exit_all(&mut w, &bob, Tail::V5);
    let o = outcome(&w, paid);
    assert_eq!(o.bob_paid, ctrl.bob_paid);
    assert_eq!(o.total_returned, ctrl.total_returned);
    assert_eq!(o.pool_value, ctrl.pool_value);
    assert_eq!(o.vault, ctrl.vault);
}

/// Two withdrawals after one direct tag 41: the second books nothing new (idempotent) and the
/// two halves add up to the single-exit payout.
#[test]
fn gh311_fl_split_withdrawals_book_once() {
    let c = control(Kind::Growth);
    let (mut w, _alice, bob) = fl_scene(Kind::Growth);
    assert!(direct_tag41(&mut w, FUND).is_ok());
    let lp = token_amount(&w.svm, &bob.lp_ata);
    let before = token_amount(&w.svm, &bob.ata);
    let r = withdraw(&mut w, &bob, lp / 2, Tail::V5);
    assert!(r.is_ok(), "{}", logs(&r));
    let p1 = w.pool();
    w.warp(10);
    let r = withdraw(&mut w, &bob, lp - lp / 2, Tail::V5);
    assert!(r.is_ok(), "{}", logs(&r));
    let p2 = w.pool();
    assert_eq!(
        p2.total_returned, p1.total_returned,
        "second withdraw books no principal"
    );
    assert_eq!(
        p2.total_fees_earned, p1.total_fees_earned,
        "second withdraw books no fees"
    );
    let paid = token_amount(&w.svm, &bob.ata) - before;
    assert!(
        paid.abs_diff(c.bob_paid) <= 1,
        "split exits {paid} vs control {}",
        c.bob_paid
    );
}

/// #290: tokens donated straight into pool.vault while the market is LIVE are not recovery and
/// must not reprice shares; Withdraw books nothing.
#[test]
fn gh311_fl_live_donation_is_not_booked_by_withdraw() {
    let mut w = world(RISK_FIRST_LOSS);
    let bob = new_staker(&mut w, BOB);
    assert!(deposit(&mut w, &bob, BOB).is_ok());
    w.warp(100);
    let (vault, mint, va) = (w.vault, w.mint, w.vault_auth);
    let bal = w.vault_balance();
    set_token_account(&mut w.svm, vault, &mint, &va, bal + 3_000_000);
    assert_eq!(w.terminal(), WrapperTerminal::NotTerminal);
    let tpv_before = w.tpv();
    let paid = exit_all(&mut w, &bob, Tail::V5);
    assert!(
        paid <= BOB,
        "the donation did not reprice shares (paid {paid})"
    );
    let p = w.pool();
    assert_eq!(p.total_returned, 0, "nothing booked as recovery");
    assert_eq!(p.total_fees_earned, 0, "nothing booked as fees");
    assert_eq!(p.total_pool_value().unwrap(), tpv_before - paid);
}

/// Account 11 must be the wrapper's InsuranceUnitsV20 PDA for this market: a random key is
/// refused before anything is booked.
#[test]
fn gh311_fl_withdraw_with_a_wrong_units_account_is_refused() {
    let (mut w, _alice, bob) = fl_scene(Kind::Plain);
    assert!(direct_tag41(&mut w, FUND).is_ok());
    let before = w.pool();
    let lp = token_amount(&w.svm, &bob.lp_ata);
    let r = withdraw(&mut w, &bob, lp, Tail::V5WrongUnits);
    assert_eq!(custom(&r), Some(E_INSURANCE_UNITS_INVALID), "{}", logs(&r));
    let after = w.pool();
    assert_eq!(after.total_returned, before.total_returned);
    assert_eq!(after.total_fees_earned, before.total_fees_earned);
}

/// The market account must be this pool's: a FIRST_LOSS withdraw naming another wrapper-owned
/// account as the market is refused (InvalidAccount) before anything is booked.
#[test]
fn gh311_fl_withdraw_with_a_foreign_market_is_refused() {
    let (mut w, _alice, bob) = fl_scene(Kind::Plain);
    assert!(direct_tag41(&mut w, FUND).is_ok());
    // A copy of the market at another address, owned by the wrapper.
    let fake = Pubkey::new_unique();
    let acct = w.svm.get_account(&w.market).unwrap();
    w.svm.set_account(fake, acct).unwrap();
    let real = w.market;
    w.market = fake;
    let lp = token_amount(&w.svm, &bob.lp_ata);
    let before = w.pool();
    let r = withdraw(&mut w, &bob, lp, Tail::V5);
    w.market = real;
    assert!(r.is_err(), "a foreign market must be refused");
    assert_eq!(custom(&r), Some(E_INVALID_ACCOUNT), "{}", logs(&r));
    assert_eq!(w.pool().total_returned, before.total_returned);
}

// ─────────────────────────────────────────────────────────────────────────────
// FEE_ONLY: the same window (the whole fund is creator class; growth above the seed is the
// stakers')
// ─────────────────────────────────────────────────────────────────────────────

fn fo_control(growth: bool) -> Outcome {
    let (mut w, _alice, bob) = fo_scene(growth);
    let r = recover_terminal(&mut w, SEED);
    assert!(r.is_ok(), "FEE_ONLY control tag 29: {}", logs(&r));
    let paid = exit_all(&mut w, &bob, Tail::Slab);
    outcome(&w, paid)
}

/// FEE_ONLY, growth above the seed (forged 3M record, 5M fund): a direct tag 41 then a Withdraw
/// that passes the #290 slab pays the control (bob's share of the 2M growth included).
#[test]
fn gh311_fo_growth_direct_tag41_then_withdraw_pays_the_control_forged_seed() {
    let c = fo_control(true);
    assert!(
        c.bob_paid > BOB,
        "PIN: the control pays bob part of the growth ({})",
        c.bob_paid
    );
    let (mut w, _alice, bob) = fo_scene(true);
    assert!(direct_tag41(&mut w, SEED).is_ok());
    let paid = exit_all(&mut w, &bob, Tail::Slab);
    assert_eq!(paid, c.bob_paid, "FEE_ONLY: bob gets what the control pays");
    assert_eq!(
        w.vault_balance() - w.tpv(),
        SEED_LOW,
        "the creator's seed stays unbooked"
    );
    let r = recover_terminal(&mut w, 0);
    assert!(r.is_ok(), "{}", logs(&r));
    assert_eq!(
        token_amount(&w.svm, &w.creator_ata),
        SEED_LOW,
        "creator: the seed, never more"
    );
    assert_eq!(w.vault_balance(), w.tpv(), "vault == books");
}

/// FEE_ONLY, no growth (fund == seed): the whole payment is the creator's, so Withdraw books
/// nothing and bob gets exactly his deposit, as in the control.
#[test]
fn gh311_fo_direct_tag41_fund_equal_seed_books_nothing_for_stakers() {
    let c = fo_control(false);
    let (mut w, _alice, bob) = fo_scene(false);
    assert!(direct_tag41(&mut w, SEED).is_ok());
    let tpv_before = w.tpv();
    let paid = exit_all(&mut w, &bob, Tail::Slab);
    assert_eq!(paid, c.bob_paid);
    assert_eq!(
        w.tpv(),
        tpv_before - paid,
        "nothing booked: the fund is the creator's seed"
    );
    assert!(recover_terminal(&mut w, 0).is_ok());
    assert_eq!(token_amount(&w.svm, &w.creator_ata), SEED);
}

/// GH#315 (PR #316): a FEE_ONLY mode-0 Withdraw WITHOUT the optional slab cannot see that the
/// market is terminal, so it cannot book the #313 terminal surplus before pricing. It used to
/// proceed and book nothing ("can only under-pay, never over-pay"); under-paying the withdrawer
/// IS the #311 harm (the shortfall accrues to the stakers who stay), so it now fails closed with
/// `NotEnoughAccountKeys` and moves nothing. This test previously pinned the OLD behaviour
/// (`gh311_fo_withdraw_without_slab_books_nothing`: paid <= BOB with no booking); that pin is
/// intentionally inverted because the behaviour it pinned is the defect #316 removes. The retry
/// WITH the slab still succeeds and pays the slab-supplied control.
#[test]
fn gh311_fo_withdraw_without_slab_is_refused() {
    let c = fo_control(true);
    let (mut w, _alice, bob) = fo_scene(true);
    assert!(direct_tag41(&mut w, SEED).is_ok());
    let tpv_before = w.tpv();
    let vault_before = w.vault_balance();
    let lp = token_amount(&w.svm, &bob.lp_ata);
    let bob_before = token_amount(&w.svm, &bob.ata);
    assert!(lp > 0, "the measured withdraw must be a real, non-zero redemption");
    let r = withdraw(&mut w, &bob, lp, Tail::None);
    assert!(
        matches!(
            r.as_ref().map_err(|e| e.err.clone()),
            Err(TransactionError::InstructionError(
                _,
                InstructionError::NotEnoughAccountKeys
            ))
        ),
        "withdraw without the slab must be refused: {}",
        logs(&r)
    );
    assert_eq!(w.tpv(), tpv_before, "refused: nothing booked or paid");
    assert_eq!(w.vault_balance(), vault_before, "refused: vault untouched");
    assert_eq!(token_amount(&w.svm, &bob.ata), bob_before, "refused: bob paid nothing");
    // The same withdrawal with the slab succeeds.
    let paid = exit_all(&mut w, &bob, Tail::Slab);
    assert_eq!(paid, c.bob_paid, "with the slab bob is paid the tag-29-first control");
}

// ─────────────────────────────────────────────────────────────────────────────
// GH#309 port on the close-out line (#313 gate condition 3 / F-3): a Withdraw on the CloseSlab
// tombstone books with the units figure before it prices
// ─────────────────────────────────────────────────────────────────────────────

/// tag 41 -> tag 30 -> Withdraw (no tag 29 in between): tag 30 reserved the seed cap alone; the
/// Withdraw reads the surviving units ledger raw and books whatever the seed cap over-reserved,
/// so bob is paid exactly the tag-29-first control. A later tag 29 (amount 0) then forwards the
/// creator's exact share and books nothing twice. Kind::Loss is F-3's case (seed > true share);
/// Plain and Growth pin that nothing else moves.
fn direct41_close_then_withdraw(kind: Kind) {
    let c = control(kind);
    let (mut w, _alice, bob) = fl_scene(kind);
    assert!(direct_tag41(&mut w, FUND).is_ok());
    let r = close_slab(&mut w);
    assert!(r.is_ok(), "AdminCloseSlab: {}", logs(&r));
    assert_eq!(w.terminal(), WrapperTerminal::Closed);
    let seed = w.pool().creator_seed_atoms();
    assert_eq!(
        w.vault_balance() - w.tpv(),
        seed,
        "{kind:?}: tag 30 reserves the seed cap"
    );
    assert!(
        w.units().is_some(),
        "PIN: the units ledger survives CloseSlab"
    );
    let share = fl_creator_share(&w, kind);
    if kind == Kind::Loss {
        assert!(share < seed, "PIN: F-3 scene, seed {seed} > share {share}");
    }
    let paid = exit_all(&mut w, &bob, Tail::V5);
    assert_eq!(
        paid, c.bob_paid,
        "{kind:?}: Withdraw on the tombstone pays the control (got {paid}, control {})",
        c.bob_paid
    );
    assert_eq!(
        w.vault_balance() - w.tpv(),
        share,
        "{kind:?}: only the creator's true share left unbooked"
    );
    let before = w.pool();
    let r = recover_terminal(&mut w, 0);
    assert!(r.is_ok(), "tag 29 on the tombstone: {}", logs(&r));
    assert_eq!(
        token_amount(&w.svm, &w.creator_ata),
        c.creator_got,
        "{kind:?}: creator gets the control's share"
    );
    let after = w.pool();
    assert_eq!(after.total_returned, before.total_returned, "no double booking (principal)");
    assert_eq!(after.total_fees_earned, before.total_fees_earned, "no double booking (fees)");
    assert_eq!(w.vault_balance(), w.tpv(), "vault == books");
}

#[test]
fn gh309_fl_direct_tag41_close_slab_then_withdraw_pays_the_control() {
    direct41_close_then_withdraw(Kind::Plain);
}

#[test]
fn gh309_fl_growth_direct_tag41_close_slab_then_withdraw_pays_the_control_forged_seed() {
    direct41_close_then_withdraw(Kind::Growth);
}

#[test]
fn gh309_fl_loss_direct_tag41_close_slab_then_withdraw_pays_the_control_forged_ledger() {
    direct41_close_then_withdraw(Kind::Loss);
}

/// On the tombstone account 11 must still be the units PDA for this market (raw read, same checks
/// as tag 29): a random key is refused before anything is booked.
#[test]
fn gh309_fl_tombstone_withdraw_with_a_wrong_units_account_is_refused() {
    let (mut w, _alice, bob) = fl_scene(Kind::Loss);
    assert!(direct_tag41(&mut w, FUND).is_ok());
    assert!(close_slab(&mut w).is_ok());
    assert_eq!(w.terminal(), WrapperTerminal::Closed);
    let before = w.pool();
    let lp = token_amount(&w.svm, &bob.lp_ata);
    let r = withdraw(&mut w, &bob, lp, Tail::V5WrongUnits);
    assert_eq!(custom(&r), Some(E_INSURANCE_UNITS_INVALID), "{}", logs(&r));
    let after = w.pool();
    assert_eq!(after.total_returned, before.total_returned);
    assert_eq!(after.total_fees_earned, before.total_fees_earned);
}

/// On the tombstone a units ledger that is not the wrapper's (same address, foreign owner) is
/// refused: the raw read checks the owner, as tag 29 does.
#[test]
fn gh309_fl_tombstone_withdraw_with_a_foreign_owned_units_ledger_is_refused() {
    let (mut w, _alice, bob) = fl_scene(Kind::Loss);
    assert!(direct_tag41(&mut w, FUND).is_ok());
    assert!(close_slab(&mut w).is_ok());
    let mut acct = w.svm.get_account(&w.units).unwrap();
    acct.owner = Pubkey::new_unique();
    let units = w.units;
    w.svm.set_account(units, acct).unwrap();
    let lp = token_amount(&w.svm, &bob.lp_ata);
    let r = withdraw(&mut w, &bob, lp, Tail::V5);
    assert_eq!(custom(&r), Some(E_INSURANCE_UNITS_INVALID), "{}", logs(&r));
}

/// FEE_ONLY on the tombstone: tag 30 already booked with the seed cap, which IS the FEE_ONLY
/// share (`None`, as tag 29 uses), so the Withdraw books nothing more and pays the control.
#[test]
fn gh309_fo_growth_direct_tag41_close_slab_then_withdraw_pays_the_control_forged_seed() {
    let c = fo_control(true);
    let (mut w, _alice, bob) = fo_scene(true);
    assert!(direct_tag41(&mut w, SEED).is_ok());
    let r = close_slab(&mut w);
    assert!(r.is_ok(), "AdminCloseSlab: {}", logs(&r));
    assert_eq!(w.terminal(), WrapperTerminal::Closed);
    let paid = exit_all(&mut w, &bob, Tail::Slab);
    assert_eq!(paid, c.bob_paid, "FEE_ONLY: bob gets what the control pays");
    assert_eq!(w.vault_balance() - w.tpv(), SEED_LOW, "the seed stays unbooked");
    assert!(recover_terminal(&mut w, 0).is_ok());
    assert_eq!(token_amount(&w.svm, &w.creator_ata), SEED_LOW);
    assert_eq!(w.vault_balance(), w.tpv(), "vault == books");
}

/// On the tombstone account 11 must be the units PDA itself: a wrapper-owned COPY of the real
/// ledger (same bytes, same market) at another address is refused (35), so the raw read cannot be
/// fed a stale or doctored copy.
#[test]
fn gh309_fl_tombstone_withdraw_with_a_copied_units_ledger_is_refused() {
    let (mut w, _alice, bob) = fl_scene(Kind::Loss);
    assert!(direct_tag41(&mut w, FUND).is_ok());
    assert!(close_slab(&mut w).is_ok());
    let copy = Pubkey::new_unique();
    let acct = w.svm.get_account(&w.units).unwrap();
    assert_eq!(acct.owner, w.wrapper_id, "PIN: the copy is wrapper-owned");
    w.svm.set_account(copy, acct).unwrap();
    let real = w.units;
    w.units = copy;
    let lp = token_amount(&w.svm, &bob.lp_ata);
    let r = withdraw(&mut w, &bob, lp, Tail::V5);
    w.units = real;
    assert_eq!(custom(&r), Some(E_INSURANCE_UNITS_INVALID), "{}", logs(&r));
}

/// On the tombstone an UNCREATED units ledger is accepted only when no staker principal was ever
/// flushed; here 6M was (`total_flushed > 0`), so an emptied PDA is refused (35) rather than
/// falling back to the seed cap.
#[test]
fn gh309_fl_tombstone_withdraw_with_an_uncreated_ledger_after_a_flush_is_refused() {
    let (mut w, _alice, bob) = fl_scene(Kind::Loss);
    assert!(direct_tag41(&mut w, FUND).is_ok());
    assert!(close_slab(&mut w).is_ok());
    assert!(w.pool().total_flushed > 0, "PIN: the scene flushed principal");
    let units = w.units;
    w.svm
        .set_account(
            units,
            solana_sdk::account::Account {
                lamports: 0,
                data: vec![],
                owner: system_program::id(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    let lp = token_amount(&w.svm, &bob.lp_ata);
    let r = withdraw(&mut w, &bob, lp, Tail::V5);
    assert_eq!(custom(&r), Some(E_INSURANCE_UNITS_INVALID), "{}", logs(&r));
}
