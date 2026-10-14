//! v5 "staking as real insurance" (Phase 4 item 6, S3) and "creator seed return" (growth plan
//! §2.10, S1), end to end on the REAL stake .so + REAL wrapper .so under LiteSVM.
//!
//! What runs for real: wrapper InitMarket, the creator's insurance seed (wrapper tag 9), stake
//! InitPool (16-byte form = FIRST_LOSS defaults 5,000 / 3,000 / 500), Bind (19), BurnAssetAdmin
//! (21), consented deposits (tag 1, 16-byte form), SyncInsuranceDeployment (31, through wrapper
//! tags 116 / 9 / 57 and the `InsuranceUnitsV20` ledger), Propose/CommitDeployTarget (32/33),
//! withdrawals, AdminResolveMarket (24) and RecoverTerminalInsurance (29, wrapper tag 41).
//!
//! Forged state, and only this: token balances used as funding; the stake program's
//! ProgramData account (so the upgrade authority can be proven to `ProposeDeployTarget`; LiteSVM
//! loads programs without one); and, in ONE test, the wrapper unit ledger's class counts, to
//! model a drop in unit value (named `_forged_ledger`; the real-engine insurance loss is the
//! wrapper suite's `p4_wave_d::xprog_insurance_loss_spreads_pro_rata_over_stakers_and_classes`).
//!
//! The wrapper .so must pin THIS stake id (A6DVNubv, the v2.2 RC devnet pin): the canonical RC
//! artifact `artifacts/v22-combination-2026-10-08/wrapper-v22rem-c6ee0b6e-devnet.so`
//! (sha256 53fddfe7…). The fresh-ID devnet artifact pins 7JrgAUHi and classes every unit as the
//! creator's, so it cannot run these tests. Default path `../percolator-prog/target/deploy/
//! percolator_prog.so`; override with `F9_WRAPPER_SO`. A missing .so is a hard failure here
//! (not a silent skip). Rebuild `target/deploy/percolator_stake.so` after changing the source.

#![allow(clippy::result_large_err, clippy::too_many_arguments)]

use litesvm::LiteSVM;
use percolator_stake::state::{
    deposit_consent_bytes, derive_deposit_pda, derive_pool_pda, derive_vault_authority,
    derive_wrapper_ins_units, read_wrapper_ins_units, StakePool, WrapperInsUnits,
    MINIMUM_LIQUIDITY, STAKE_POOL_SIZE,
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
const STAKE_ID: &str = "A6DVNubvzMMETQinK6bipekkaTTrkUu2RMw2kBoJrdkE";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const MARKET_LEN_V22_CAP1: usize = 4059;
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;

/// The creator's insurance seed (wrapper tag 9 before the pool exists).
const SEED: u64 = 5_000_000;

// Stake error codes.
const E_CONSENT_REQUIRED: u32 = 33;
const E_DEPRECATED_V5: u32 = 34;
const E_INSURANCE_UNITS_INVALID: u32 = 35;
const E_SYNC_COOLDOWN: u32 = 37;
const E_NOT_PROTOCOL_AUTHORITY: u32 = 39;
const E_NO_PENDING_TARGET: u32 = 40;
const E_NOT_SUPPORTED_ON_FIRST_LOSS: u32 = 41;
const E_ASSET_ADMIN_NOT_BURNED: u32 = 42;
const E_NOTHING_TO_SYNC: u32 = 43;

fn stake_so() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/deploy/percolator_stake.so")
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

/// Wrapper InitMarket, the same 219-byte form the F-9 suite uses.
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

    /// (liquid, deployed at the EXIT reading of the LAST snapshot, LP supply), the way the
    /// program values a withdrawal (`process_withdraw`, first-loss arm).
    fn valuation(&self) -> (u64, u64, u64) {
        let p = self.pool();
        let liquid = p.total_pool_value().unwrap();
        let deployed = match self.units() {
            Some(u) => percolator_stake::math::deployed_value(u.units_stake, u.units_total, u.snap_free)
                .unwrap(),
            None => 0,
        };
        (liquid, deployed, p.total_lp_supply)
    }

    fn send_stake(&mut self, signers: &[&Keypair], accounts: Vec<AccountMeta>, data: Vec<u8>) -> TxResult {
        let payer = self.payer.insecure_clone();
        let ix = Instruction {
            program_id: self.stake_id,
            accounts,
            data,
        };
        send(&mut self.svm, &payer, signers, ix)
    }
}

/// Live market (admin = marketauth = asset-0 authorities) -> the creator seeds the insurance
/// with SEED (tag 9) -> real 16-byte InitPool (FIRST_LOSS with the protocol defaults) ->
/// real Bind (19) -> optionally BurnAssetAdmin (21). No staker yet; the units ledger does not
/// exist until the first first-loss deposit.
fn world(burn_asset_admin: bool) -> World {
    let (so, wso) = (stake_so(), wrapper_so());
    assert!(
        so.exists() && wso.exists(),
        "v5 e2e needs both .so files (stake={} wrapper={}); see the module doc",
        so.display(),
        wso.display()
    );
    let mut svm = LiteSVM::new().with_spl_programs();
    // Start away from slot 0: the program stores slot stamps as `slot.max(1)` (0 = "none"), so a
    // world at slot 0 would shift every cooldown / timelock boundary by one slot.
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
    let wrapper_vault_auth = Pubkey::find_program_address(&[b"vault", market.as_ref()], &wrapper_id).0;
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

    // The creator's seed: wrapper tag 9 while the admin is still the insurance authority.
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
    // 16-byte InitPool: FIRST_LOSS with the protocol defaults (target 5,000, buffer 3,000,
    // hysteresis 500). Cooldown 5 slots, uncapped.
    let mut ipd = vec![0u8];
    ipd.extend_from_slice(&5u64.to_le_bytes());
    ipd.extend_from_slice(&0u64.to_le_bytes());
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
    };
    let p = w.pool();
    assert!(p.is_first_loss(), "16-byte InitPool = FIRST_LOSS");
    assert_eq!(
        (p.deploy_target_bps, p.liquid_buffer_bps, p.hysteresis_bps),
        (5_000, 3_000, 500)
    );
    let admin = w.admin.insecure_clone();
    for tag in if burn_asset_admin { vec![19u8, 21u8] } else { vec![19u8] } {
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
    w
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

/// Stake tag 1 (or 16 for DepositJunior) with the v5 tail. `consent` is appended verbatim
/// after the amount (None = the 9-byte legacy form).
fn deposit_raw(w: &mut World, tag: u8, s: &Staker, amount: u64, consent: Option<Vec<u8>>) -> TxResult {
    let (dpda, _) = derive_deposit_pda(&w.stake_id, &w.pool, &s.kp.pubkey());
    let mut data = vec![tag];
    data.extend_from_slice(&amount.to_le_bytes());
    if let Some(c) = consent {
        data.extend_from_slice(&c);
    }
    let accounts = vec![
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
        AccountMeta::new(w.market, false),
        AccountMeta::new(w.units, false),
        AccountMeta::new_readonly(w.wrapper_id, false),
    ];
    let kp = s.kp.insecure_clone();
    w.send_stake(&[&kp], accounts, data)
}

/// A consented deposit signing the pool's CURRENT parameters (target incl. a pending raise).
fn deposit(w: &mut World, s: &Staker, amount: u64) -> TxResult {
    let p = w.pool();
    let t = if p.pending_target_slot != 0 {
        p.deploy_target_bps.max(p.pending_target_bps as u16)
    } else {
        p.deploy_target_bps
    };
    deposit_raw(
        w,
        1,
        s,
        amount,
        Some(deposit_consent_bytes(t, p.liquid_buffer_bps, p.hysteresis_bps).to_vec()),
    )
}

fn withdraw(w: &mut World, s: &Staker, lp: u64) -> TxResult {
    let (dpda, _) = derive_deposit_pda(&w.stake_id, &w.pool, &s.kp.pubkey());
    let mut data = vec![2u8];
    data.extend_from_slice(&lp.to_le_bytes());
    let accounts = vec![
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
        AccountMeta::new(w.market, false),
        AccountMeta::new(w.units, false),
        AccountMeta::new_readonly(w.wrapper_id, false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];
    let kp = s.kp.insecure_clone();
    w.send_stake(&[&kp], accounts, data)
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

fn propose_target(w: &mut World, signer: &Keypair, target: u16, program_data: Option<Pubkey>) -> TxResult {
    let mut data = vec![32u8];
    data.extend_from_slice(&target.to_le_bytes());
    let mut accounts = vec![
        AccountMeta::new_readonly(signer.pubkey(), true),
        AccountMeta::new(w.pool, false),
    ];
    if let Some(pd) = program_data {
        accounts.push(AccountMeta::new_readonly(pd, false));
    }
    w.send_stake(&[signer], accounts, data)
}

fn commit_target(w: &mut World) -> TxResult {
    let anyone = Keypair::new();
    w.svm.airdrop(&anyone.pubkey(), 1_000_000_000).unwrap();
    let accounts = vec![
        AccountMeta::new_readonly(anyone.pubkey(), true),
        AccountMeta::new(w.pool, false),
    ];
    w.send_stake(&[&anyone], accounts, vec![33])
}

/// Forge the stake program's ProgramData account naming `authority` as the upgrade authority
/// (LiteSVM loads the program without one). Layout: enum tag 3, slot u64, Option<Pubkey>.
fn set_upgrade_authority(w: &mut World, authority: &Pubkey) -> Pubkey {
    let loader = solana_sdk::bpf_loader_upgradeable::id();
    let (pd, _) = Pubkey::find_program_address(&[w.stake_id.as_ref()], &loader);
    let mut data = vec![0u8; 45];
    data[0..4].copy_from_slice(&3u32.to_le_bytes());
    data[12] = 1;
    data[13..45].copy_from_slice(authority.as_ref());
    w.svm
        .set_account(
            pd,
            Account {
                lamports: 1_000_000_000,
                data,
                owner: loader,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    pd
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

/// Stake tag 29 (permissionless) on a FIRST_LOSS pool: [9] units PDA, [10] creator account.
fn recover_terminal(w: &mut World, amount: u64) -> TxResult {
    let caller = Pubkey::new_unique();
    let mut data = vec![29u8];
    data.extend_from_slice(&amount.to_le_bytes());
    let accounts = vec![
        AccountMeta::new_readonly(caller, false),
        AccountMeta::new(w.pool, false),
        AccountMeta::new(w.vault, false),
        AccountMeta::new_readonly(w.vault_auth, false),
        AccountMeta::new(w.market, false),
        AccountMeta::new(w.wrapper_vault, false),
        AccountMeta::new_readonly(w.wrapper_vault_auth, false),
        AccountMeta::new_readonly(token_program(), false),
        AccountMeta::new_readonly(w.wrapper_id, false),
        AccountMeta::new(w.units, false),
        AccountMeta::new(w.creator_ata, false),
    ];
    w.send_stake(&[], accounts, data)
}

/// Value of `lp` shares at the given valuation.
fn share_value(lp: u64, (liquid, deployed, supply): (u64, u64, u64)) -> u64 {
    ((lp as u128) * ((liquid + deployed) as u128) / supply as u128) as u64
}

// ═════════════════════════════════════════════════════════════════════════════
// S3: consent (I-S2)
// ═════════════════════════════════════════════════════════════════════════════

/// I-S2 / S-5: a FIRST_LOSS deposit must sign the current risk-text version AND the pool's
/// deployment parameters (target incl. a pending raise, buffer, hysteresis). No consent, a
/// stale version, or any one parameter off by one is refused with ConsentRequired and moves
/// nothing; the exact consent is accepted. DepositJunior is not available on FIRST_LOSS at all.
#[test]
fn s3_consent_mismatch_refused_and_exact_consent_accepted() {
    let mut w = world(false);
    let a = new_staker(&mut w, 10_000_000);
    let v = percolator_stake::state::CONSENT_VERSION_FIRST_LOSS;
    let consent = |ver: u8, t: u16, b: u16, h: u16| {
        let mut c = vec![ver];
        c.extend_from_slice(&t.to_le_bytes());
        c.extend_from_slice(&b.to_le_bytes());
        c.extend_from_slice(&h.to_le_bytes());
        c
    };
    let cases: Vec<(&str, Option<Vec<u8>>)> = vec![
        ("no consent (9-byte form)", None),
        ("stale version", Some(consent(v - 1, 5_000, 3_000, 500))),
        ("future version", Some(consent(v + 1, 5_000, 3_000, 500))),
        ("target off by one", Some(consent(v, 4_999, 3_000, 500))),
        ("buffer off by one", Some(consent(v, 5_000, 3_001, 500))),
        ("hysteresis off by one", Some(consent(v, 5_000, 3_000, 499))),
    ];
    for (label, c) in cases {
        let r = deposit_raw(&mut w, 1, &a, 10_000_000, c);
        assert_eq!(custom(&r), Some(E_CONSENT_REQUIRED), "{label}: {}", logs(&r));
        assert_eq!(token_amount(&w.svm, &w.vault), 0, "{label}: nothing moved");
    }
    let r = deposit_raw(&mut w, 16, &a, 10_000_000, None);
    assert_eq!(custom(&r), Some(E_NOT_SUPPORTED_ON_FIRST_LOSS), "DepositJunior: {}", logs(&r));
    let r = deposit_raw(&mut w, 1, &a, 10_000_000, Some(consent(v, 5_000, 3_000, 500)));
    assert!(r.is_ok(), "exact consent: {}", logs(&r));
    assert_eq!(token_amount(&w.svm, &w.vault), 10_000_000);
    assert_eq!(token_amount(&w.svm, &a.lp_ata), 10_000_000 - MINIMUM_LIQUIDITY);
    let u = w.units().expect("the first first-loss deposit created the units ledger");
    assert_eq!(u.units_creator, SEED as u128, "the pre-existing seed is creator-class");
    assert_eq!(u.units_stake, 0);
}

// ═════════════════════════════════════════════════════════════════════════════
// S3: sync (I-S4), cooldown, recovery, the admin flush is gone (I-S1)
// ═════════════════════════════════════════════════════════════════════════════

/// I-S4: the permissionless sync deploys exactly up to the target (50% of pool value) and
/// keeps the liquid buffer (30%), minting stake-class units at the entry price; a second sync
/// inside `sync_cooldown_slots` is refused; after the cooldown, a balanced pool has nothing to
/// sync. The deployment needs BurnAssetAdmin first. The creator-admin flush (tag 3) and the v4
/// recovery (tag 23) are gone (DeprecatedV5), for the admin and anyone else.
#[test]
fn s3_sync_deploys_to_target_keeps_buffer_and_is_rate_limited() {
    // Without BurnAssetAdmin the deployment is refused.
    {
        let mut w = world(false);
        let a = new_staker(&mut w, 10_000_000);
        assert!(deposit(&mut w, &a, 10_000_000).is_ok());
        let r = sync(&mut w);
        assert_eq!(custom(&r), Some(E_ASSET_ADMIN_NOT_BURNED), "{}", logs(&r));
    }
    let mut w = world(true);
    let a = new_staker(&mut w, 10_000_000);
    assert!(deposit(&mut w, &a, 10_000_000).is_ok());

    // I-S1: tag 3 / tag 23 are removed for every caller.
    let admin = w.admin.insecure_clone();
    for (tag, label) in [(3u8, "FlushToInsurance"), (23u8, "RecoverFlushedInsurance")] {
        let mut d = vec![tag];
        d.extend_from_slice(&1_000_000u64.to_le_bytes());
        let accounts = vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(w.pool, false),
            AccountMeta::new(w.vault, false),
            AccountMeta::new_readonly(w.vault_auth, false),
            AccountMeta::new(w.market, false),
            AccountMeta::new(w.wrapper_vault, false),
            AccountMeta::new_readonly(w.wrapper_id, false),
            AccountMeta::new_readonly(token_program(), false),
        ];
        let r = w.send_stake(&[&admin], accounts, d);
        assert_eq!(custom(&r), Some(E_DEPRECATED_V5), "{label}: {}", logs(&r));
    }
    assert_eq!(token_amount(&w.svm, &w.vault), 10_000_000, "nothing moved");

    let u0 = w.units().unwrap();
    let wv0 = token_amount(&w.svm, &w.wrapper_vault);
    let r = sync(&mut w);
    assert!(r.is_ok(), "sync top-up: {}", logs(&r));
    let u1 = w.units().unwrap();
    // V = 10M liquid + 0 deployed; target 5M; buffer ceil(3M); top-up min(5M, 10M - 3M) = 5M.
    assert_eq!(token_amount(&w.svm, &w.wrapper_vault) - wv0, 5_000_000, "deployed exactly to target");
    assert_eq!(token_amount(&w.svm, &w.vault), 5_000_000);
    assert_eq!(
        u1.units_stake,
        5_000_000u128 * u0.units_total / u0.snap_mint,
        "stake-class units at the entry price"
    );
    assert_eq!(u1.units_creator, u0.units_creator, "creator units untouched");
    let p = w.pool();
    assert_eq!(p.total_flushed, 5_000_000);
    let (liquid, deployed, _) = w.valuation();
    assert_eq!((liquid, deployed), (5_000_000, 5_000_000));
    assert!(
        (liquid as u128) * 10_000 >= 3_000u128 * (liquid + deployed) as u128,
        "liquid buffer kept"
    );
    assert!(deployed as u128 * 10_000 <= 5_000u128 * (liquid + deployed) as u128 + 500u128 * (liquid + deployed) as u128);

    // Rate limit.
    let r = sync(&mut w);
    assert_eq!(custom(&r), Some(E_SYNC_COOLDOWN), "{}", logs(&r));
    w.warp(p.sync_cooldown_slots);
    let r = sync(&mut w);
    assert_eq!(custom(&r), Some(E_NOTHING_TO_SYNC), "balanced: {}", logs(&r));

    // A withdrawal is paid from liquidity at liquid + deployed value, and never beyond the
    // liquid part (the deployed part waits for a sync recovery).
    w.warp(10);
    let lp = token_amount(&w.svm, &a.lp_ata);
    let r = withdraw(&mut w, &a, lp);
    assert_eq!(custom(&r), Some(36), "beyond the liquid value: {}", logs(&r));
    let half = lp / 2;
    let expect = share_value(half, w.valuation());
    let before = token_amount(&w.svm, &a.ata);
    assert!(withdraw(&mut w, &a, half).is_ok());
    let got = token_amount(&w.svm, &a.ata) - before;
    assert!(got <= expect && got + 1 >= expect, "half the stake: got {got} expect {expect}");
}

/// The sync RECOVERS the excess when the deployment is above target + hysteresis (here after
/// the admin LOWERS the target, timelocked), through wrapper tag 57 on the healthy market:
/// exactly `deployed - target` returns to the vault, `ceil(r*U/I_free)` stake units burn,
/// creator units do not move, and `total_returned` records it.
#[test]
fn s3_sync_recovers_excess_after_target_lowered() {
    let mut w = world(true);
    let a = new_staker(&mut w, 10_000_000);
    assert!(deposit(&mut w, &a, 10_000_000).is_ok());
    assert!(sync(&mut w).is_ok());
    let admin = w.admin.insecure_clone();
    let r = propose_target(&mut w, &admin, 1_000, None);
    assert!(r.is_ok(), "admin lowers: {}", logs(&r));
    let r = commit_target(&mut w);
    assert_eq!(custom(&r), Some(E_NO_PENDING_TARGET), "inside the timelock: {}", logs(&r));
    w.warp(percolator_stake::state::DEPLOY_TARGET_TIMELOCK_MIN_SLOTS);
    let r = commit_target(&mut w);
    assert!(r.is_ok(), "commit after the timelock: {}", logs(&r));
    assert_eq!(w.pool().deploy_target_bps, 1_000);

    // Refresh-free expectations from the last snapshot (no insurance moved since).
    let u0 = w.units().unwrap();
    let (liquid, deployed, _) = w.valuation();
    let target = (liquid + deployed) / 10; // 10% of 10M
    let r_amt = deployed - target;
    let vault0 = token_amount(&w.svm, &w.vault);
    let r = sync(&mut w);
    assert!(r.is_ok(), "sync recovery: {}", logs(&r));
    let u1 = w.units().unwrap();
    assert_eq!(token_amount(&w.svm, &w.vault) - vault0, r_amt, "recovered exactly deployed - target");
    let burned = u0.units_stake - u1.units_stake;
    let expect_burn = ((r_amt as u128) * u0.units_total).div_ceil(u0.snap_free);
    assert_eq!(burned, expect_burn, "stake units burned at the exit price (rounded against the pool)");
    assert_eq!(u1.units_creator, u0.units_creator, "creator units untouched");
    assert_eq!(w.pool().total_returned, r_amt);
    let (l1, d1, _) = w.valuation();
    assert_eq!(d1, target, "deployed == target after a recovery");
    assert_eq!(l1, liquid + r_amt);
}

// ═════════════════════════════════════════════════════════════════════════════
// S3: deploy-target governance
// ═════════════════════════════════════════════════════════════════════════════

/// The admin may only LOWER the target, the stake protocol (upgrade) authority may RAISE it,
/// both behind the >= 216,000-slot timelock; an admin proposal may not overwrite a pending
/// protocol raise; a pending raise is part of what a new depositor must consent to (S-5).
#[test]
fn s3_deploy_target_raise_needs_upgrade_authority_and_timelock() {
    let mut w = world(true);
    let admin = w.admin.insecure_clone();
    // Admin raise refused, with or without a (wrong) ProgramData account.
    let r = propose_target(&mut w, &admin, 6_000, None);
    assert_eq!(custom(&r), Some(E_NOT_PROTOCOL_AUTHORITY), "admin raise: {}", logs(&r));
    let ua = Keypair::new();
    w.svm.airdrop(&ua.pubkey(), 1_000_000_000).unwrap();
    let pd = set_upgrade_authority(&mut w, &ua.pubkey());
    let r = propose_target(&mut w, &admin, 6_000, Some(pd));
    assert_eq!(custom(&r), Some(E_NOT_PROTOCOL_AUTHORITY), "admin is not the UA: {}", logs(&r));
    // Equal target counts as a raise (no-op proposals are protocol-only).
    let r = propose_target(&mut w, &admin, 5_000, None);
    assert_eq!(custom(&r), Some(E_NOT_PROTOCOL_AUTHORITY), "admin same target: {}", logs(&r));
    // Out of protocol bounds, even for the UA.
    let r = propose_target(&mut w, &ua, 8_001, Some(pd));
    assert_eq!(custom(&r), Some(38), "above 8,000: {}", logs(&r));
    // A stranger (not admin, not UA) cannot lower either.
    let stranger = Keypair::new();
    w.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    let r = propose_target(&mut w, &stranger, 1_000, None);
    assert_eq!(custom(&r), Some(2), "stranger lower: {}", logs(&r));

    // The UA raises.
    let r = propose_target(&mut w, &ua, 6_000, Some(pd));
    assert!(r.is_ok(), "UA raise: {}", logs(&r));
    // The admin cannot overwrite the pending protocol proposal.
    let r = propose_target(&mut w, &admin, 1_000, None);
    assert_eq!(custom(&r), Some(E_NOT_PROTOCOL_AUTHORITY), "admin overwrite: {}", logs(&r));
    // A new depositor must consent to the pending (higher) target.
    let s = new_staker(&mut w, 2_000_000);
    let r = deposit_raw(&mut w, 1, &s, 2_000_000, Some(deposit_consent_bytes(5_000, 3_000, 500).to_vec()));
    assert_eq!(custom(&r), Some(E_CONSENT_REQUIRED), "consent to the old target: {}", logs(&r));
    assert!(deposit(&mut w, &s, 2_000_000).is_ok(), "consent to the pending target");
    // Timelock: not before 216,000 slots (the pool cooldown is only 5).
    w.warp(percolator_stake::state::DEPLOY_TARGET_TIMELOCK_MIN_SLOTS - 10);
    let r = commit_target(&mut w);
    assert_eq!(custom(&r), Some(E_NO_PENDING_TARGET), "early commit: {}", logs(&r));
    assert_eq!(w.pool().deploy_target_bps, 5_000);
    w.warp(10);
    let r = commit_target(&mut w);
    assert!(r.is_ok(), "commit: {}", logs(&r));
    let p = w.pool();
    assert_eq!((p.deploy_target_bps, p.pending_target_slot), (6_000, 0));
}

// ═════════════════════════════════════════════════════════════════════════════
// S3: losses are pro rata (I-S3)
// ═════════════════════════════════════════════════════════════════════════════

/// I-S3 on the stake side: when the value of the deployed units drops, every staker's LP loses
/// the same fraction, and a leaver is paid exactly its post-loss value. The drop is FORGED in the
/// wrapper ledger (creator-class units added with no atoms, so `I/U` falls exactly as an
/// insurance spend makes it fall; the class invariant `U = Us + Uc` is kept). Stake prices only
/// `Us * I / U`, so this is the full stake-side response; the real engine loss is the wrapper's
/// XP-2.
#[test]
fn s3_unit_value_drop_lowers_lp_price_pro_rata_forged_ledger() {
    let mut w = world(true);
    let a = new_staker(&mut w, 6_000_000);
    let b = new_staker(&mut w, 3_000_000);
    assert!(deposit(&mut w, &a, 6_000_000).is_ok());
    assert!(deposit(&mut w, &b, 3_000_000).is_ok());
    assert!(sync(&mut w).is_ok());
    let (lp_a, lp_b) = (token_amount(&w.svm, &a.lp_ata), token_amount(&w.svm, &b.lp_ata));
    let v0 = w.valuation();
    let (va0, vb0) = (share_value(lp_a, v0), share_value(lp_b, v0));
    // Halve the unit value: add U creator units backed by nothing.
    let mut acct = w.svm.get_account(&w.units).unwrap();
    let u = w.units().unwrap();
    let off_total = percolator_stake::state::WRAPPER_INS_UNITS_OFF_UNITS_TOTAL;
    let off_creator = percolator_stake::state::WRAPPER_INS_UNITS_OFF_UNITS_CREATOR;
    acct.data[off_total..off_total + 16].copy_from_slice(&(u.units_total * 2).to_le_bytes());
    acct.data[off_creator..off_creator + 16]
        .copy_from_slice(&(u.units_creator + u.units_total).to_le_bytes());
    w.svm.set_account(w.units, acct).unwrap();
    let v1 = w.valuation();
    assert!(v1.1 < v0.1, "deployed value fell: {} -> {}", v0.1, v1.1);
    let (va1, vb1) = (share_value(lp_a, v1), share_value(lp_b, v1));
    assert!(va1 < va0 && vb1 < vb0);
    // Same fraction (cross-multiplied, rounding tolerance of one atom per share value).
    assert!(
        ((va1 as u128) * (vb0 as u128)).abs_diff((vb1 as u128) * (va0 as u128)) <= (va0 + vb0) as u128,
        "pro rata: A {va1}/{va0} B {vb1}/{vb0}"
    );
    // B (a third of the pool) exits at the post-loss price.
    w.warp(10);
    let before = token_amount(&w.svm, &b.ata);
    let r = withdraw(&mut w, &b, lp_b);
    assert!(r.is_ok(), "B exits: {}", logs(&r));
    let got = token_amount(&w.svm, &b.ata) - before;
    assert!(got <= vb1 && got + 1 >= vb1, "B paid its post-loss value {vb1}, got {got}");
    assert!(got < 3_000_000, "B bears its share of the loss");
}

// ═════════════════════════════════════════════════════════════════════════════
// S1: creator seed return at terminal
// ═════════════════════════════════════════════════════════════════════════════

/// S1, stakers exist and deployed: at terminal the wrapper pays the stake class its own units'
/// value first (booked back to the stakers as recovered principal) and the creator class the
/// rest (forwarded to the creator). Partial for the creator: exactly the seed (its units), not
/// the stakers' deployment. The staker then redeems its whole deposit.
#[test]
fn s1_terminal_partial_when_stakers_exist() {
    let mut w = world(true);
    let a = new_staker(&mut w, 10_000_000);
    assert!(deposit(&mut w, &a, 10_000_000).is_ok());
    assert!(sync(&mut w).is_ok());
    assert_eq!(w.pool().total_flushed, 5_000_000);
    admin_resolve(&mut w);
    let fund = token_amount(&w.svm, &w.wrapper_vault);
    assert_eq!(fund, SEED + 5_000_000);
    let r = recover_terminal(&mut w, fund);
    assert!(r.is_ok(), "terminal: {}", logs(&r));
    assert_eq!(token_amount(&w.svm, &w.wrapper_vault), 0);
    assert_eq!(token_amount(&w.svm, &w.creator_ata), SEED, "S1: the creator gets exactly its seed");
    let p = w.pool();
    assert_eq!(p.creator_forwarded_atoms, SEED);
    assert_eq!(p.total_returned, 5_000_000, "the stakers' deployment came back as principal");
    assert_eq!(p.total_pool_value(), Some(10_000_000));
    assert_eq!(token_amount(&w.svm, &w.vault), 10_000_000, "vault == books");
    let u = w.units().unwrap();
    assert_eq!((u.units_stake, u.units_creator, u.units_total), (0, 0, 0), "every unit burned");
    // The staker redeems everything (the liquid limit no longer binds: nothing is deployed).
    w.warp(10);
    let lp = token_amount(&w.svm, &a.lp_ata);
    let before = token_amount(&w.svm, &a.ata);
    let r = withdraw(&mut w, &a, lp);
    assert!(r.is_ok(), "{}", logs(&r));
    let got = token_amount(&w.svm, &a.ata) - before;
    assert!(got + 1 >= 10_000_000 - MINIMUM_LIQUIDITY && got <= 10_000_000, "staker made whole: {got}");
}

/// S1, NO staker ever: a FIRST_LOSS pool that nobody deposited into never created the wrapper's
/// units ledger (tag 116 runs on the first first-loss deposit or sync, and only while Live), so
/// after resolution the ledger can never exist. The whole insurance fund is the creator's seed:
/// RecoverTerminalInsurance takes the pre-units tag-41 path and forwards all of it.
/// NEGATIVE CONTROL: the pre-S1 .so (aebbff6) requires the ledger to be wrapper-owned and
/// refuses with InsuranceUnitsInvalid (35) for ever; the seed is stranded in the wrapper.
#[test]
fn s1_terminal_full_seed_when_no_staker_ever() {
    let mut w = world(true);
    assert!(w.svm.get_account(&w.units).is_none(), "PRE: never unitised");
    admin_resolve(&mut w);
    let r = recover_terminal(&mut w, SEED);
    assert!(r.is_ok(), "terminal on a never-unitised first-loss pool: {}", logs(&r));
    assert_eq!(token_amount(&w.svm, &w.creator_ata), SEED, "S1: all of the seed returned");
    assert_eq!(token_amount(&w.svm, &w.wrapper_vault), 0);
    assert_eq!(token_amount(&w.svm, &w.vault), 0, "nothing stranded in the pool");
    let p = w.pool();
    assert_eq!(p.creator_surplus_forwarded_atoms(), SEED);
    assert_eq!(p.total_fees_earned, 0);
    assert!(p.market_resolved());
    // A fake "ledger" at the PDA address is impossible (wrapper-owned PDA), but a wrong key is
    // refused, and a second call finds nothing.
    let r = recover_terminal(&mut w, 0);
    assert_eq!(custom(&r), Some(31), "idempotent: {}", logs(&r));
    let real_units = w.units;
    w.units = Pubkey::new_unique();
    let r = recover_terminal(&mut w, 0);
    assert_eq!(custom(&r), Some(E_INSURANCE_UNITS_INVALID), "wrong ledger key: {}", logs(&r));
    w.units = real_units;
}

/// S1, stakers came and all left before resolution (no real staker at terminal, nothing
/// deployed): every insurance atom is creator-class and is forwarded; nothing is booked to the
/// dead shares or stranded.
#[test]
fn s1_terminal_full_seed_when_all_stakers_left() {
    let mut w = world(true);
    let a = new_staker(&mut w, 10_000_000);
    assert!(deposit(&mut w, &a, 10_000_000).is_ok());
    w.warp(10);
    let lp = token_amount(&w.svm, &a.lp_ata);
    assert!(withdraw(&mut w, &a, lp).is_ok());
    assert!(!w.pool().has_real_lp_holders());
    admin_resolve(&mut w);
    let r = recover_terminal(&mut w, SEED);
    assert!(r.is_ok(), "{}", logs(&r));
    assert_eq!(token_amount(&w.svm, &w.creator_ata), SEED);
    let p = w.pool();
    assert_eq!(token_amount(&w.svm, &w.vault), p.total_pool_value().unwrap(), "vault == books");
    assert_eq!(p.total_fees_earned, 0, "nothing booked to the dead shares");
}

/// S2 at terminal: on a pool where stakers DID deploy (so the surplus is not wholly the
/// creator's), the pre-stake fee backlog still goes to the creator, not to the stakers who
/// joined later. The backlog is FORGED (pool bytes 472..480 plus the matching unbooked atoms in
/// the vault, i.e. exactly what `AccrueFees` leaves behind when the wrapper paid the 16% leg
/// before the first staker; the accrual itself is unit-tested in
/// `processor::tests::s2_backlog_is_recorded_as_owed_to_the_creator`).
/// NEGATIVE CONTROL: on the pre-S2 .so the backlog bytes are ignored and the atoms are booked as
/// staker fees (creator receives only the seed; the fee assert fails).
#[test]
fn s2_backlog_forwarded_to_creator_at_terminal_forged_backlog() {
    const BACKLOG: u64 = 700_000;
    let mut w = world(true);
    let a = new_staker(&mut w, 10_000_000);
    assert!(deposit(&mut w, &a, 10_000_000).is_ok());
    assert!(sync(&mut w).is_ok());
    // Forge the S2 state: owed counter + the unbooked atoms in the vault.
    let mut acct = w.svm.get_account(&w.pool).unwrap();
    acct.data[472..480].copy_from_slice(&BACKLOG.to_le_bytes());
    w.svm.set_account(w.pool, acct).unwrap();
    let vault_now = token_amount(&w.svm, &w.vault);
    let (mint, va, vault) = (w.mint, w.vault_auth, w.vault);
    set_token_account(&mut w.svm, vault, &mint, &va, vault_now + BACKLOG);
    assert_eq!(w.pool().s2_backlog_owed_atoms(), BACKLOG);
    admin_resolve(&mut w);
    let fund = token_amount(&w.svm, &w.wrapper_vault);
    let r = recover_terminal(&mut w, fund);
    assert!(r.is_ok(), "{}", logs(&r));
    assert_eq!(
        token_amount(&w.svm, &w.creator_ata),
        SEED + BACKLOG,
        "creator: its seed (creator units) + the pre-stake backlog"
    );
    let p = w.pool();
    assert_eq!(p.s2_backlog_owed_atoms(), 0);
    assert_eq!(p.creator_surplus_forwarded_atoms(), BACKLOG);
    assert_eq!(p.total_fees_earned, 0, "the backlog is not booked to the stakers");
    assert_eq!(p.total_pool_value(), Some(10_000_000));
    assert_eq!(token_amount(&w.svm, &w.vault), 10_000_000, "vault == books");
}
