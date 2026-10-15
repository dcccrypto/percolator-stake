//! GH#311: a permissionless DIRECT wrapper tag 41 must not break the class attribution of a
//! v5 FIRST_LOSS pool's terminal insurance.
//!
//! On a Resolved, bound market anyone can call wrapper tag 41 (`WithdrawInsurance`) for the pool's
//! `vault_auth`. The payment lands in `pool.vault` and the wrapper's terminal burn
//! (`ins_units_terminal_burn`) splits it: the STAKE class's own value, plus -- beyond it -- the
//! CREATOR's seed, recorded in `creator_paid_to_stake`. Stake tag 29 forwards that seed to
//! `pool.admin` (`creator_forwarded_atoms`) and books only the rest to stakers. A direct call
//! skips tag 29, so before the fix:
//!
//!   * a first-loss Withdraw before the next crank priced against UNBOOKED stake-class value
//!     and under-paid (the filed symptom, 50% in the PoC);
//!   * the obvious fix (book the whole vault surplus) OVER-pays, because the surplus also
//!     holds the creator's seed;
//!   * tag 30 (AdminCloseSlab) booked the whole surplus, creator seed included, to stakers.
//!
//! The rule under test: book `vault - total_pool_value() - (creator_paid_to_stake -
//! creator_forwarded_atoms)`, i.e. the stake class only; the creator's part stays in the vault
//! until tag 29 forwards it to pool.admin.
//!
//! REAL stake .so + REAL wrapper .so (v2.2, VERSION 19, built `--features devnet`) under
//! LiteSVM; set `F9_WRAPPER_SO` to the wrapper .so (default
//! `../percolator-prog/target/deploy/percolator_prog.so`). The harness below is copied from
//! `f9_terminal_insurance_recovery_e2e.rs` (which keeps its own private copy). The stake
//! program is loaded at the id the wrapper's devnet build PINS (7JrgAUHi), so the wrapper
//! classifies the pool's vault_auth as the STAKE unit class.
//!
//! Rebuild `target/deploy/percolator_stake.so` (`cargo build-sbf -- --features devnet`)
//! after changing the source, or these tests exercise stale bytes.

#![allow(clippy::result_large_err, clippy::too_many_arguments, dead_code)]

use litesvm::LiteSVM;
use percolator_stake::state::{
    derive_deposit_pda, derive_pool_pda, derive_vault_authority, read_wrapper_terminal, StakePool,
    WrapperTerminal, MINIMUM_LIQUIDITY, STAKE_POOL_SIZE, WRAPPER_OFF_MODE,
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
// v5: the stake program is loaded at the id the wrapper's devnet build PINS (A6DVNubv, the v2.1 fresh id), so the
// wrapper recognises the pool's vault_auth as the STAKE unit class (Phase 4 item 6). Every other
// F-9 assertion is id-independent.
const STAKE_ID: &str = "7JrgAUHi4PxaRv5JKHoGAxodDFbozYexpERei66Xgq4V";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
// v2.2 (wrapper VERSION 19) market account length for capacity 1: 592 + 806 + 2437.
// (v2.1 / VERSION 18: 3675; see f3_dead_share_accrue_guard_e2e.rs.)
const MARKET_LEN_V18_CAP1: usize = 4059;
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;
// Asset-0 raw offsets: the SAME constants the program reads at runtime (v2.2 layout 19; the
// pin test `wrapper_layout_v22_pin` re-derives them against the real wrapper types).
use percolator_stake::wrapper_layout::{
    ASSET0_AUTHORITY_EPOCH_OFF, ASSET0_INSURANCE_TOP_UP_OFF, ASSET0_MARKET_ID_OFF,
};

const BUDGET: u64 = 5_000_000;
const STAKE: u64 = 10_000_000;

// Stake error codes.
const E_MARKET_RESOLVED: u32 = 8;
const E_INVALID_PDA: u32 = 10;
const E_UNAUTHORIZED: u32 = 2;
const E_INVALID_ACCOUNT: u32 = 16;
const E_MARKET_NOT_TERMINAL: u32 = 30;
const E_NOTHING_TO_RECOVER: u32 = 31;
const E_UNSUPPORTED_WRAPPER_LAYOUT: u32 = 32;
// Wrapper EngineLockActive.
const W_ENGINE_LOCK_ACTIVE: u32 = 21;

fn stake_so() -> PathBuf {
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
    d[45] = 1; // is_initialized, decimals 0, no authorities
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
            owner: Pubkey::from_str(TOKEN_PROGRAM).unwrap(),
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
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    let ata_program = Pubkey::from_str(ATA_PROGRAM).unwrap();
    Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &ata_program,
    )
    .0
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
    assert_eq!(out.len(), 219);
    out
}

fn send(
    svm: &mut LiteSVM,
    payer: &Keypair,
    signers: &[&Keypair],
    ix: Instruction,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let mut all: Vec<&Keypair> = vec![payer];
    all.extend_from_slice(signers);
    // Fresh blockhash per tx so identical retries are not deduplicated.
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

fn custom(r: &Result<(), litesvm::types::FailedTransactionMetadata>) -> Option<u32> {
    match r {
        Err(e) => match &e.err {
            TransactionError::InstructionError(_, InstructionError::Custom(c)) => Some(*c),
            _ => None,
        },
        Ok(()) => None,
    }
}

fn logs(r: &Result<(), litesvm::types::FailedTransactionMetadata>) -> String {
    match r {
        Err(e) => format!("{:?}\n{}", e.err, e.meta.logs.join("\n")),
        Ok(()) => "Ok".into(),
    }
}

fn read_pool(svm: &LiteSVM, pool: &Pubkey) -> StakePool {
    let d = svm.get_account(pool).unwrap().data;
    *bytemuck::from_bytes::<StakePool>(&d[..STAKE_POOL_SIZE])
}

fn read_u64(svm: &LiteSVM, key: &Pubkey, off: usize) -> u64 {
    let d = svm.get_account(key).unwrap().data;
    u64::from_le_bytes(d[off..off + 8].try_into().unwrap())
}

fn market_mode_byte(svm: &LiteSVM, market: &Pubkey) -> u8 {
    svm.get_account(market).unwrap().data[WRAPPER_OFF_MODE]
}

fn terminal(svm: &LiteSVM, market: &Pubkey) -> WrapperTerminal {
    read_wrapper_terminal(&svm.get_account(market).unwrap().data)
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
    alice: Option<Staker>,
}

struct Staker {
    kp: Keypair,
    ata: Pubkey,
    lp_ata: Pubkey,
}

/// Live market (admin = marketauth = asset-0 authorities) -> admin TopUpInsurance
/// `BUDGET` (the stand-in for liquidation fees / a creator seed) -> real InitPool
/// (marketauth -> pool PDA) -> a real staker deposits `STAKE` -> real Bind (tag 19,
/// insurance_authority -> vault_auth). Live, not yet resolved.
thread_local! {
    /// v5 risk mode of the pool `world` creates (2 = FEE_ONLY for the legacy F-9 suite).
    static RISK_MODE: std::cell::Cell<u8> = const { std::cell::Cell::new(2) };
}

fn world(name: &str) -> Option<World> {
    let (so, wso) = (stake_so(), wrapper_so());
    if !so.exists() || !wso.exists() {
        eprintln!(
            "SKIP {name}: .so missing (stake={} wrapper={})",
            so.display(),
            wso.display()
        );
        return None;
    }
    let mut svm = LiteSVM::new().with_spl_programs();
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
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
            data: encode_init_market_v17(),
        },
    )
    .unwrap_or_else(|e| panic!("InitMarket: {:?}\n{}", e.err, e.meta.logs.join("\n")));
    assert_eq!(
        market_mode_byte(&svm, &market),
        0,
        "PIN: Live market has mode byte 0 at WRAPPER_OFF_MODE"
    );

    // Admin (still the asset-0 insurance authority) tops insurance up directly: tag 9.
    let src = Pubkey::new_unique();
    set_token_account(&mut svm, src, &mint, &admin.pubkey(), BUDGET);
    let mut d = vec![9u8];
    d.extend_from_slice(&read_u64(&svm, &market, ASSET0_MARKET_ID_OFF).to_le_bytes());
    d.extend_from_slice(&(read_u64(&svm, &market, ASSET0_INSURANCE_TOP_UP_OFF) + 1).to_le_bytes());
    d.extend_from_slice(&read_u64(&svm, &market, ASSET0_AUTHORITY_EPOCH_OFF).to_le_bytes());
    d.extend_from_slice(&(BUDGET as u128).to_le_bytes());
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
                AccountMeta::new_readonly(token_program, false),
            ],
            data: d,
        },
    )
    .unwrap_or_else(|e| panic!("TopUpInsurance: {:?}\n{}", e.err, e.meta.logs.join("\n")));
    assert_eq!(token_amount(&svm, &wrapper_vault), BUDGET);

    // Real InitPool.
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
                owner: token_program,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    }
    let mut ipd = vec![0u8];
    ipd.extend_from_slice(&5u64.to_le_bytes()); // cooldown 5 slots
    ipd.extend_from_slice(&0u64.to_le_bytes()); // uncapped
                                                // v5 (Phase 4 item 6): the 23-byte InitPool with an explicit risk mode. The F-9 suite
                                                // below pins the terminal mechanics of a pool that never deployed (FEE_ONLY, no
                                                // consent, no units); `f9_v5_first_loss_terminal_returns_creator_seed_s1` covers the
                                                // FIRST_LOSS path (units ledger + S1).
    let risk_mode = RISK_MODE.with(|c| c.get());
    ipd.push(risk_mode);
    let target: u16 = if risk_mode == 1 { 5_000 } else { 0 };
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
                AccountMeta::new_readonly(token_program, false),
                AccountMeta::new_readonly(system_program::id(), false),
                AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
            ],
            data: ipd,
        },
    )
    .unwrap_or_else(|e| panic!("InitPool: {:?}\n{}", e.err, e.meta.logs.join("\n")));

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
        alice: None,
    };
    w.alice = Some(deposit(&mut w, STAKE).expect("staker deposit while Live"));
    // Real Bind (tag 19).
    let (admin_k, payer_k) = (w.admin.insecure_clone(), w.payer.insecure_clone());
    send(
        &mut w.svm,
        &payer_k,
        &[&admin_k],
        Instruction {
            program_id: w.stake_id,
            accounts: vec![
                AccountMeta::new(w.admin.pubkey(), true),
                AccountMeta::new_readonly(w.pool, false),
                AccountMeta::new_readonly(w.vault_auth, false),
                AccountMeta::new(w.market, false),
                AccountMeta::new_readonly(w.wrapper_id, false),
            ],
            data: vec![19u8],
        },
    )
    .unwrap_or_else(|e| panic!("Bind: {:?}\n{}", e.err, e.meta.logs.join("\n")));
    Some(w)
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

fn deposit_as(
    w: &mut World,
    s: &Staker,
    amount: u64,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
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
        AccountMeta::new_readonly(Pubkey::from_str(TOKEN_PROGRAM).unwrap(), false),
        AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];
    if RISK_MODE.with(|c| c.get()) == 1 {
        // v5 FIRST_LOSS: consent byte, writable market, units ledger, wrapper program.
        data.extend_from_slice(&percolator_stake::state::deposit_consent_bytes(
            5_000, 3_000, 500,
        ));
        accounts.push(AccountMeta::new(w.market, false));
        accounts.push(AccountMeta::new(
            percolator_stake::state::derive_wrapper_ins_units(&w.wrapper_id, &w.market).0,
            false,
        ));
        accounts.push(AccountMeta::new_readonly(w.wrapper_id, false));
    } else {
        accounts.push(AccountMeta::new_readonly(w.market, false));
    }
    let ix = Instruction {
        program_id: w.stake_id,
        accounts,
        data,
    };
    let payer = w.payer.insecure_clone();
    send(&mut w.svm, &payer, &[&s.kp], ix)
}

fn deposit(w: &mut World, amount: u64) -> Result<Staker, String> {
    let s = new_staker(w, amount);
    let r = deposit_as(w, &s, amount);
    r.map(|_| s).map_err(|e| format!("{:?}", e.err))
}

fn withdraw(
    w: &mut World,
    s: &Staker,
    lp: u64,
    pass_slab: bool,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
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
        AccountMeta::new_readonly(Pubkey::from_str(TOKEN_PROGRAM).unwrap(), false),
        AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
    ];
    if pass_slab {
        accounts.push(AccountMeta::new_readonly(w.market, false));
    }
    let payer = w.payer.insecure_clone();
    send(
        &mut w.svm,
        &payer,
        &[&s.kp],
        Instruction {
            program_id: w.stake_id,
            accounts,
            data,
        },
    )
}

/// Stake tag 24 (pool PDA signs wrapper ResolveMarket). total_flushed == 0, so H-1 passes.
fn admin_resolve(w: &mut World) {
    let (admin, payer) = (w.admin.insecure_clone(), w.payer.insecure_clone());
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
    send(&mut w.svm, &payer, &[&admin], ix).unwrap_or_else(|e| {
        panic!(
            "AdminResolveMarket: {:?}\n{}",
            e.err,
            e.meta.logs.join("\n")
        )
    });
}

struct RecoverOpts {
    vault: Option<Pubkey>,
    vault_auth: Option<Pubkey>,
    stray: Option<Pubkey>,
}
const DEFAULT_OPTS: RecoverOpts = RecoverOpts {
    vault: None,
    vault_auth: None,
    stray: None,
};

/// Stake tag 29, sent by a RANDOM non-signing caller (permissionless).
fn recover_terminal(
    w: &mut World,
    amount: u64,
    o: RecoverOpts,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let caller = Pubkey::new_unique();
    let mut accounts = vec![
        AccountMeta::new_readonly(caller, false),
        AccountMeta::new(w.pool, false),
        AccountMeta::new(o.vault.unwrap_or(w.vault), false),
        AccountMeta::new_readonly(o.vault_auth.unwrap_or(w.vault_auth), false),
        AccountMeta::new(w.market, false),
        AccountMeta::new(w.wrapper_vault, false),
        AccountMeta::new_readonly(w.wrapper_vault_auth, false),
        AccountMeta::new_readonly(Pubkey::from_str(TOKEN_PROGRAM).unwrap(), false),
        AccountMeta::new_readonly(w.wrapper_id, false),
    ];
    if let Some(k) = o.stray {
        accounts.push(AccountMeta::new(k, false));
    }
    let mut data = vec![29u8];
    data.extend_from_slice(&amount.to_le_bytes());
    let payer = w.payer.insecure_clone();
    send(
        &mut w.svm,
        &payer,
        &[],
        Instruction {
            program_id: w.stake_id,
            accounts,
            data,
        },
    )
}

/// Wrapper tag 41 sent DIRECTLY by a third party, naming vault_auth (unsigned) as
/// the authority and `dest` (owned by vault_auth) as the payout account.
fn third_party_tag41(
    w: &mut World,
    amount: u64,
    dest: Pubkey,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let mut data = vec![41u8];
    data.extend_from_slice(&(amount as u128).to_le_bytes());
    let ix = Instruction {
        program_id: w.wrapper_id,
        accounts: vec![
            AccountMeta::new_readonly(w.vault_auth, false),
            AccountMeta::new(w.market, false),
            AccountMeta::new(dest, false),
            AccountMeta::new(w.wrapper_vault, false),
            AccountMeta::new_readonly(w.wrapper_vault_auth, false),
            AccountMeta::new_readonly(Pubkey::from_str(TOKEN_PROGRAM).unwrap(), false),
        ],
        data,
    };
    let payer = w.payer.insecure_clone();
    send(&mut w.svm, &payer, &[], ix)
}

/// Stake tag 30, signed by `signer`. `pool_dest` is created owned by the pool PDA.
fn admin_close_slab(
    w: &mut World,
    signer: &Keypair,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let pool_dest = Pubkey::new_unique();
    let (mint, pool) = (w.mint, w.pool);
    set_token_account(&mut w.svm, pool_dest, &mint, &pool, 0);
    let ix = Instruction {
        program_id: w.stake_id,
        accounts: vec![
            AccountMeta::new(signer.pubkey(), true),
            AccountMeta::new(w.pool, false),
            AccountMeta::new(w.market, false),
            AccountMeta::new(w.wrapper_vault, false),
            AccountMeta::new_readonly(w.wrapper_vault_auth, false),
            AccountMeta::new(pool_dest, false),
            AccountMeta::new_readonly(Pubkey::from_str(TOKEN_PROGRAM).unwrap(), false),
            AccountMeta::new(w.mint, false),
            AccountMeta::new(w.vault, false),
            AccountMeta::new_readonly(w.wrapper_id, false),
        ],
        data: vec![30u8],
    };
    let payer = w.payer.insecure_clone();
    send(&mut w.svm, &payer, &[signer], ix)
}

// ─────────────────────────────────────────────────────────────────────────────
// GH#311 scene + helpers
// ─────────────────────────────────────────────────────────────────────────────

const BOB_STAKE: u64 = 2_000_000;
const SYNC_TARGET_DEPLOYED: u64 = 6_000_000; // 50% of the 12M pool

fn units_pda(w: &World) -> Pubkey {
    percolator_stake::state::derive_wrapper_ins_units(&w.wrapper_id, &w.market).0
}

fn read_units(w: &World) -> percolator_stake::state::WrapperInsUnits {
    percolator_stake::state::read_wrapper_ins_units(
        &w.svm.get_account(&units_pda(w)).expect("units ledger").data,
        &w.market.to_bytes(),
    )
    .expect("units ledger parses")
}

fn tok() -> Pubkey {
    Pubkey::from_str(TOKEN_PROGRAM).unwrap()
}

/// The reporter's PoC world: a first-loss pool, creator seed 5M (creator class), alice 10M and
/// bob 2M staked, a permissionless sync deploys 6M (50%) of the 12M pool -> units
/// {stake 6M, creator 5M}; then the market is resolved. Bob's cooldown has elapsed.
fn scene(name: &str) -> Option<(World, Staker)> {
    RISK_MODE.with(|c| c.set(1));
    let mut w = world(name)?;
    let bob = new_staker(&mut w, BOB_STAKE);
    deposit_as(&mut w, &bob, BOB_STAKE).expect("bob deposits while Live");
    // BurnAssetAdmin (tag 21): a sync top-up requires it.
    let (admin, payer) = (w.admin.insecure_clone(), w.payer.insecure_clone());
    send(
        &mut w.svm,
        &payer,
        &[&admin],
        Instruction {
            program_id: w.stake_id,
            accounts: vec![
                AccountMeta::new_readonly(w.admin.pubkey(), true),
                AccountMeta::new(w.pool, false),
                AccountMeta::new_readonly(w.vault_auth, false),
                AccountMeta::new(w.market, false),
                AccountMeta::new_readonly(w.wrapper_id, false),
            ],
            data: vec![21u8],
        },
    )
    .unwrap_or_else(|e| panic!("BurnAssetAdmin: {}", logs(&Err(e))));
    let slot = w.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    w.svm.warp_to_slot(slot + 50);
    let units = units_pda(&w);
    let ix = Instruction {
        program_id: w.stake_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(w.pool, false),
            AccountMeta::new(w.vault, false),
            AccountMeta::new_readonly(w.vault_auth, false),
            AccountMeta::new(w.market, false),
            AccountMeta::new(w.wrapper_vault, false),
            AccountMeta::new_readonly(w.wrapper_vault_auth, false),
            AccountMeta::new(units, false),
            AccountMeta::new_readonly(tok(), false),
            AccountMeta::new_readonly(w.wrapper_id, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: vec![31u8],
    };
    let r = send(&mut w.svm, &payer, &[], ix);
    assert!(r.is_ok(), "SyncInsuranceDeployment: {}", logs(&r));
    let u = read_units(&w);
    assert_eq!(
        u.units_stake, SYNC_TARGET_DEPLOYED as u128,
        "PIN: stake class deployed"
    );
    assert_eq!(
        u.units_creator, BUDGET as u128,
        "PIN: creator class = the seed"
    );
    admin_resolve(&mut w);
    let slot = w.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    w.svm.warp_to_slot(slot + 100);
    Some((w, bob))
}

/// Stake tag 29, v5 shape (units ledger + the creator's token account).
fn recover_v5(
    w: &mut World,
    amount: u64,
    creator_ata: Pubkey,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let units = units_pda(w);
    let mut data = vec![29u8];
    data.extend_from_slice(&amount.to_le_bytes());
    let payer = w.payer.insecure_clone();
    send(
        &mut w.svm,
        &payer,
        &[],
        Instruction {
            program_id: w.stake_id,
            accounts: vec![
                AccountMeta::new_readonly(Pubkey::new_unique(), false),
                AccountMeta::new(w.pool, false),
                AccountMeta::new(w.vault, false),
                AccountMeta::new_readonly(w.vault_auth, false),
                AccountMeta::new(w.market, false),
                AccountMeta::new(w.wrapper_vault, false),
                AccountMeta::new_readonly(w.wrapper_vault_auth, false),
                AccountMeta::new_readonly(tok(), false),
                AccountMeta::new_readonly(w.wrapper_id, false),
                AccountMeta::new(units, false),
                AccountMeta::new(creator_ata, false),
            ],
            data,
        },
    )
}

fn creator_ata(w: &mut World) -> Pubkey {
    let k = Pubkey::new_unique();
    let (mint, admin) = (w.mint, w.admin.pubkey());
    set_token_account(&mut w.svm, k, &mint, &admin, 0);
    k
}

/// Wrapper tag 41 sent DIRECTLY by a third party (no stake involvement), v5 shape: the units
/// ledger rides in the tail so the wrapper performs its class burn.
fn direct_tag41_v5(
    w: &mut World,
    amount: u64,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let mut data = vec![41u8];
    data.extend_from_slice(&(amount as u128).to_le_bytes());
    let ix = Instruction {
        program_id: w.wrapper_id,
        accounts: vec![
            AccountMeta::new_readonly(w.vault_auth, false),
            AccountMeta::new(w.market, false),
            AccountMeta::new(w.vault, false),
            AccountMeta::new(w.wrapper_vault, false),
            AccountMeta::new_readonly(w.wrapper_vault_auth, false),
            AccountMeta::new_readonly(tok(), false),
            AccountMeta::new(units_pda(w), false),
        ],
        data,
    };
    let payer = w.payer.insecure_clone();
    send(&mut w.svm, &payer, &[], ix)
}

/// First-loss Withdraw with the v5 account tail (market, units ledger, wrapper, system).
fn withdraw_v5_tail(
    w: &mut World,
    s: &Staker,
    lp: u64,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
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
        AccountMeta::new_readonly(tok(), false),
        AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
        AccountMeta::new(w.market, false),
        AccountMeta::new(units_pda(w), false),
        AccountMeta::new_readonly(w.wrapper_id, false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];
    let payer = w.payer.insecure_clone();
    send(
        &mut w.svm,
        &payer,
        &[&s.kp],
        Instruction {
            program_id: w.stake_id,
            accounts,
            data,
        },
    )
}

/// Stake tag 30 with the v5 units-ledger tail (`with_units`), signed by the admin. Retries once:
/// the P1 wrapper may need a second CloseSlab call to reach the tombstone.
fn close_slab_v5(
    w: &mut World,
    with_units: bool,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let admin = w.admin.insecure_clone();
    let mut last = Ok(());
    for _ in 0..3 {
        let pool_dest = Pubkey::new_unique();
        let (mint, pool) = (w.mint, w.pool);
        set_token_account(&mut w.svm, pool_dest, &mint, &pool, 0);
        let mut accounts = vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(w.pool, false),
            AccountMeta::new(w.market, false),
            AccountMeta::new(w.wrapper_vault, false),
            AccountMeta::new_readonly(w.wrapper_vault_auth, false),
            AccountMeta::new(pool_dest, false),
            AccountMeta::new_readonly(tok(), false),
            AccountMeta::new(w.mint, false),
            AccountMeta::new(w.vault, false),
            AccountMeta::new_readonly(w.wrapper_id, false),
        ];
        if with_units {
            accounts.push(AccountMeta::new_readonly(units_pda(w), false));
        }
        let ix = Instruction {
            program_id: w.stake_id,
            accounts,
            data: vec![30u8],
        };
        let payer = w.payer.insecure_clone();
        last = send(&mut w.svm, &payer, &[&admin], ix);
        if last.is_err() || terminal(&w.svm, &w.market) == WrapperTerminal::Closed {
            break;
        }
    }
    last
}

/// Everything an assertion needs after a path has run.
#[derive(Debug)]
struct Outcome {
    bob_paid: u64,
    creator_got: u64,
    vault: u64,
    pool_value: u64,
    total_returned: u64,
    total_fees: u64,
    forwarded: u64,
}

fn outcome(w: &World, bob: &Staker, bob_before: u64, creator: Pubkey) -> Outcome {
    let p = read_pool(&w.svm, &w.pool);
    Outcome {
        bob_paid: token_amount(&w.svm, &bob.ata) - bob_before,
        creator_got: token_amount(&w.svm, &creator),
        vault: token_amount(&w.svm, &w.vault),
        pool_value: p.total_pool_value().unwrap(),
        total_returned: p.total_returned,
        total_fees: p.total_fees_earned,
        forwarded: p.creator_forwarded_atoms,
    }
}

const FULL: u64 = SYNC_TARGET_DEPLOYED + BUDGET; // 11M: stake value 6M + creator seed 5M

/// CONTROL (reporter's `poc2_control_bob_withdraw_after_booking`): tag 29 first, then bob's
/// withdraw. This is the reference behaviour every other path must match.
fn run_control(name: &str) -> Option<Outcome> {
    let (mut w, bob) = scene(name)?;
    let creator = creator_ata(&mut w);
    let r = recover_v5(&mut w, FULL, creator);
    assert!(r.is_ok(), "control tag 29: {}", logs(&r));
    let lp = token_amount(&w.svm, &bob.lp_ata);
    let before = token_amount(&w.svm, &bob.ata);
    let r = withdraw_v5_tail(&mut w, &bob, lp);
    assert!(r.is_ok(), "control withdraw: {}", logs(&r));
    Some(outcome(&w, &bob, before, creator))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// The control is the reference: bob is made whole, the creator gets exactly the seed back, and
/// the stakers' pool is not credited with it.
#[test]
fn f311_control_tag29_first_pays_bob_in_full_and_returns_the_seed() {
    let Some(c) = run_control("f311_control") else {
        return;
    };
    assert_eq!(c.bob_paid, BOB_STAKE, "control: bob is made whole");
    assert_eq!(
        c.creator_got, BUDGET,
        "control: the seed went to the creator"
    );
    assert_eq!(c.forwarded, BUDGET);
}

/// (a) PoC `poc2_attack_direct_tag41_underpays_bob`: a direct tag 41, then bob withdraws BEFORE
/// anyone cranks tag 29. He must get exactly what the control paid (2,000,000), not the 50%
/// (1,000,000) the unbooked value gave him before the fix, and not the 2,833,333 the naive
/// "book the whole surplus" fix gave him.
#[test]
fn f311_direct_tag41_then_withdraw_pays_what_the_control_pays() {
    let Some(c) = run_control("f311_attack_control") else {
        return;
    };
    let (mut w, bob) = scene("f311_attack").expect("same .so as the control");
    let r = direct_tag41_v5(&mut w, FULL);
    assert!(r.is_ok(), "direct tag 41: {}", logs(&r));
    // The wrapper recorded the creator's seed; nothing has been booked or forwarded.
    let u = read_units(&w);
    assert_eq!(u.creator_paid_to_stake, BUDGET as u128);
    assert_eq!(u.units_stake, 0);
    assert_eq!(read_pool(&w.svm, &w.pool).creator_forwarded_atoms, 0);

    let lp = token_amount(&w.svm, &bob.lp_ata);
    let before = token_amount(&w.svm, &bob.ata);
    let r = withdraw_v5_tail(&mut w, &bob, lp);
    assert!(r.is_ok(), "withdraw after direct tag 41: {}", logs(&r));
    let paid = token_amount(&w.svm, &bob.ata) - before;
    assert_eq!(
        paid, c.bob_paid,
        "(a) same payout as the tag-29-first control"
    );
    assert_eq!(
        paid, BOB_STAKE,
        "bob is made whole, neither under- nor over-paid"
    );
}

/// (b) over-payment / creator seed on tag 41 -> Withdraw: the creator's 5M is never credited to
/// the stakers. After bob AND alice leave, the vault still holds exactly the creator's seed
/// (nothing of it was paid out to stakers); a later tag 29 forwards it to pool.admin and the
/// pool books nothing more (no double booking).
#[test]
fn f311_direct_tag41_withdraw_never_credits_the_creator_seed_to_stakers() {
    let Some((mut w, bob)) = scene("f311_creator_seed") else {
        return;
    };
    let alice = w.alice.take().unwrap();
    let r = direct_tag41_v5(&mut w, FULL);
    assert!(r.is_ok(), "direct tag 41: {}", logs(&r));
    // 6M liquid + 11M just paid in.
    assert_eq!(token_amount(&w.svm, &w.vault), 6_000_000 + FULL);

    let mut paid = 0u64;
    for s in [&bob, &alice] {
        let lp = token_amount(&w.svm, &s.lp_ata);
        let before = token_amount(&w.svm, &s.ata);
        let r = withdraw_v5_tail(&mut w, s, lp);
        assert!(r.is_ok(), "withdraw: {}", logs(&r));
        paid += token_amount(&w.svm, &s.ata) - before;
    }
    // Stakers together can never take more than they put in (12M); the dead-share floor stays.
    assert!(
        paid <= 12_000_000,
        "OVER-PAYMENT: stakers took {paid} of a 12M pool"
    );
    assert!(
        paid + 2_000 >= 12_000_000,
        "UNDER-PAYMENT: stakers took only {paid}"
    );
    // Everything that is not the stakers' is still in the vault and is the creator's seed.
    let vault = token_amount(&w.svm, &w.vault);
    assert!(
        vault >= BUDGET,
        "the creator's seed ({BUDGET}) must still be in the vault, found {vault}"
    );
    let before_29 = read_pool(&w.svm, &w.pool);
    let creator = creator_ata(&mut w);
    let r = recover_v5(&mut w, 0, creator);
    assert!(r.is_ok(), "tag 29 forwards the seed: {}", logs(&r));
    assert_eq!(
        token_amount(&w.svm, &creator),
        BUDGET,
        "the seed reached pool.admin"
    );
    let after_29 = read_pool(&w.svm, &w.pool);
    assert_eq!(after_29.creator_forwarded_atoms, BUDGET);
    // (c) no double booking: tag 29 books nothing the withdraw already booked.
    assert_eq!(after_29.total_returned, before_29.total_returned);
    assert_eq!(after_29.total_fees_earned, before_29.total_fees_earned);
}

/// (b)+(c) tag 41 -> tag 29: the creator gets the seed, stakers get the stake class, and the
/// result is identical to the control (tag 29 does the whole thing).
#[test]
fn f311_direct_tag41_then_tag29_matches_the_control() {
    let Some(c) = run_control("f311_t41_t29_control") else {
        return;
    };
    let (mut w, bob) = scene("f311_t41_t29").expect("same .so as the control");
    let r = direct_tag41_v5(&mut w, FULL);
    assert!(r.is_ok(), "direct tag 41: {}", logs(&r));
    let creator = creator_ata(&mut w);
    let r = recover_v5(&mut w, 0, creator);
    assert!(r.is_ok(), "tag 29 (amount 0): {}", logs(&r));
    let lp = token_amount(&w.svm, &bob.lp_ata);
    let before = token_amount(&w.svm, &bob.ata);
    let r = withdraw_v5_tail(&mut w, &bob, lp);
    assert!(r.is_ok(), "withdraw: {}", logs(&r));
    let o = outcome(&w, &bob, before, creator);
    assert_eq!(o.bob_paid, c.bob_paid);
    assert_eq!(o.creator_got, c.creator_got);
    assert_eq!(o.creator_got, BUDGET);
    assert_eq!(o.total_returned, c.total_returned);
    assert_eq!(o.total_fees, c.total_fees);
    assert_eq!(o.pool_value, c.pool_value);
}

/// (b) tag 41 -> tag 30 (the deployed mis-attribution): AdminCloseSlab used to book the whole
/// vault surplus, creator seed included, so `total_pool_value()` absorbed 17M of a 12M pool.
/// Now only the stake class is booked, the seed stays in the vault, and tag 29 (amount 0, legal
/// on a closed market) still forwards it to the creator afterwards.
#[test]
fn f311_direct_tag41_then_close_slab_does_not_book_the_creator_seed() {
    let Some((mut w, _bob)) = scene("f311_t41_t30") else {
        return;
    };
    let r = direct_tag41_v5(&mut w, FULL);
    assert!(r.is_ok(), "direct tag 41: {}", logs(&r));
    let r = close_slab_v5(&mut w, true);
    assert!(r.is_ok(), "AdminCloseSlab: {}", logs(&r));
    assert_eq!(terminal(&w.svm, &w.market), WrapperTerminal::Closed);
    let p = read_pool(&w.svm, &w.pool);
    let vault = token_amount(&w.svm, &w.vault);
    let tpv = p.total_pool_value().unwrap();
    assert_eq!(vault, 17_000_000, "PIN: 6M liquid + 11M terminal payment");
    assert_eq!(
        tpv, 12_000_000,
        "stakers' pool is its own 12M; the creator's seed is NOT booked (was 17M)"
    );
    assert_eq!(
        vault - tpv,
        BUDGET,
        "exactly the creator's seed is unbooked"
    );
    // The seed is still recoverable by the creator through tag 29, amount 0, on the tombstone.
    let creator = creator_ata(&mut w);
    let r = recover_v5(&mut w, 0, creator);
    assert!(r.is_ok(), "tag 29 after close: {}", logs(&r));
    assert_eq!(token_amount(&w.svm, &creator), BUDGET);
    assert_eq!(
        read_pool(&w.svm, &w.pool).total_pool_value().unwrap(),
        12_000_000
    );
}

/// Tag 30 on a first-loss pool without the units ledger is refused: it cannot tell the classes
/// apart, so it must not book (fail closed) instead of guessing.
#[test]
fn f311_close_slab_on_a_first_loss_pool_requires_the_units_ledger() {
    let Some((mut w, _bob)) = scene("f311_t30_needs_units") else {
        return;
    };
    let r = direct_tag41_v5(&mut w, FULL);
    assert!(r.is_ok(), "direct tag 41: {}", logs(&r));
    let r = close_slab_v5(&mut w, false);
    assert!(r.is_err(), "tag 30 without the ledger must refuse");
}

/// A partial direct tag 41 that the stake class covers (no creator value paid) is booked in
/// full by Withdraw and matches tag 29 with the same amount.
#[test]
fn f311_partial_direct_tag41_within_stake_value_is_booked_in_full() {
    const PARTIAL: u64 = 3_000_000;
    let (mut w, bob) = match scene("f311_partial_ctrl") {
        Some(x) => x,
        None => return,
    };
    let creator = creator_ata(&mut w);
    let r = recover_v5(&mut w, PARTIAL, creator);
    assert!(r.is_ok(), "control tag 29: {}", logs(&r));
    let lp = token_amount(&w.svm, &bob.lp_ata);
    let before = token_amount(&w.svm, &bob.ata);
    assert!(withdraw_v5_tail(&mut w, &bob, lp).is_ok());
    let ctrl = outcome(&w, &bob, before, creator);

    let (mut w, bob) = scene("f311_partial").expect("same .so");
    let r = direct_tag41_v5(&mut w, PARTIAL);
    assert!(r.is_ok(), "direct tag 41: {}", logs(&r));
    assert_eq!(
        read_units(&w).creator_paid_to_stake,
        0,
        "the stake class covered it"
    );
    let lp = token_amount(&w.svm, &bob.lp_ata);
    let before = token_amount(&w.svm, &bob.ata);
    let r = withdraw_v5_tail(&mut w, &bob, lp);
    assert!(r.is_ok(), "withdraw: {}", logs(&r));
    let o = outcome(&w, &bob, before, creator);
    assert_eq!(o.bob_paid, ctrl.bob_paid);
    assert_eq!(o.total_returned, ctrl.total_returned);
    assert_eq!(o.pool_value, ctrl.pool_value);
}

/// (d) Live-mode donations stay unbooked (#290): tokens sent straight into pool.vault while the
/// market is Live are not recovery and must not move the share price.
#[test]
fn f311_live_mode_donation_is_not_booked_by_withdraw() {
    RISK_MODE.with(|c| c.set(1));
    let Some(mut w) = world("f311_live_donation") else {
        return;
    };
    let bob = new_staker(&mut w, BOB_STAKE);
    deposit_as(&mut w, &bob, BOB_STAKE).expect("bob deposits while Live");
    let slot = w.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    w.svm.warp_to_slot(slot + 100);
    // A donation straight into the vault.
    let (vault, mint) = (w.vault, w.mint);
    let bal = token_amount(&w.svm, &vault);
    set_token_account(
        &mut w.svm,
        vault,
        &mint,
        &w.vault_auth.clone(),
        bal + 3_000_000,
    );
    let tpv_before = read_pool(&w.svm, &w.pool).total_pool_value().unwrap();
    let lp = token_amount(&w.svm, &bob.lp_ata);
    let before = token_amount(&w.svm, &bob.ata);
    let r = withdraw_v5_tail(&mut w, &bob, lp);
    assert!(r.is_ok(), "live withdraw: {}", logs(&r));
    let paid = token_amount(&w.svm, &bob.ata) - before;
    assert!(
        paid <= BOB_STAKE,
        "the donation did not reprice shares (paid {paid})"
    );
    let p = read_pool(&w.svm, &w.pool);
    assert_eq!(p.total_returned, 0, "nothing booked as recovery");
    assert_eq!(p.total_fees_earned, 0, "nothing booked as fees");
    assert_eq!(p.total_pool_value().unwrap(), tpv_before - paid);
}
