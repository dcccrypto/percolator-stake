//! F-9 (independent test suite 2026-09-30, HIGH conditional): on a stake-BOUND
//! market the asset-0 `insurance_authority` is the stake `vault_auth` PDA. Once
//! the market is Resolved, wrapper tag 57 (behind stake tag 23) is refused, and
//! stake had no CPI for the wrapper's terminal `WithdrawInsurance` (tag 41). So
//! the insurance budget was stranded, and CloseSlab failed with 21 forever.
//!
//! Fix under test:
//!   * stake tag 29 `RecoverTerminalInsurance`: permissionless. CPIs wrapper tag 41
//!     into `pool.vault` only, and books the pool's terminal surplus for stakers.
//!   * stake tag 30 `AdminCloseSlab`: the CloseSlab proxy. InitPool rotated
//!     `marketauth` to the pool PDA, so no key could sign CloseSlab directly.
//!   * Deposit / DepositJunior refuse (8) once the wrapper market is Resolved.
//!
//! REAL stake .so + REAL wrapper .so under LiteSVM. The market, the pool, the stake
//! deposit, the bind, the resolve, the terminal withdrawal and the close all run
//! through the real programs. The only forged state is token balances used as
//! funding. The wrapper .so defaults to `../percolator-prog/target/deploy/percolator_prog.so`;
//! set `F9_WRAPPER_SO` to run against another build (the deployed v18.2 and the P1
//! builds were both run; see the ledger).
//!
//! Rebuild `target/deploy/percolator_stake.so` (`cargo build-sbf`) after changing
//! the source, or these tests exercise stale bytes.

#![allow(clippy::result_large_err, clippy::too_many_arguments)]

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
// v5: the stake program is loaded at the id the wrapper's devnet build PINS (VmpVUArR), so the
// wrapper recognises the pool's vault_auth as the STAKE unit class (Phase 4 item 6). Every other
// F-9 assertion is id-independent.
const STAKE_ID: &str = "VmpVUArRnVkrjaPXQ2qaqCQa3ZrZFgsz7rjeALitF5w";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
// v18 market account length for capacity 1 (see f3_dead_share_accrue_guard_e2e.rs).
const MARKET_LEN_V18_CAP1: usize = 3675;
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;
// Asset-0 raw offsets on the v18 layout (src/cpi.rs ground-truth block).
const ASSET0_MARKET_ID_OFF: usize = 2374;
const ASSET0_AUTHORITY_EPOCH_OFF: usize = 1934;
const ASSET0_INSURANCE_TOP_UP_OFF: usize = 1846;

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
        data.push(percolator_stake::state::CONSENT_VERSION_FIRST_LOSS);
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

/// The headline: a stake-owned, bound, Resolved market with a 5M insurance budget.
///   BEFORE: CloseSlab (via the proxy) is refused 21 while the budget is outstanding.
///   tag 29 (permissionless): exactly BUDGET moves wrapper -> pool.vault, and exactly
///   BUDGET is booked to stakers.
///   tag 30: the market retires to a tombstone, and the rent refund reaches the admin.
///   The staker then withdraws principal + the whole budget (less dead-share dust).
/// NEGATIVE CONTROL: on the pre-fix stake .so (2212e17), tag 29 and tag 30 do not
/// exist (InvalidInstructionData), so this test fails at the first tag-29 assert.
#[test]
fn f9_bound_resolved_market_returns_budget_to_stakers_and_retires() {
    let Some(mut w) = world("f9_bound_resolved_market_returns_budget_to_stakers_and_retires")
    else {
        return;
    };
    let pool0 = read_pool(&w.svm, &w.pool);
    assert_eq!(pool0.total_pool_value(), Some(STAKE));
    assert_eq!(token_amount(&w.svm, &w.vault), STAKE);

    admin_resolve(&mut w);
    assert_eq!(
        market_mode_byte(&w.svm, &w.market),
        1,
        "PIN: Resolved market has mode byte 1 at WRAPPER_OFF_MODE"
    );
    assert_eq!(terminal(&w.svm, &w.market), WrapperTerminal::Resolved);

    // The finding, reproduced: while the budget is outstanding the market cannot close.
    let admin = w.admin.insecure_clone();
    let r = admin_close_slab(&mut w, &admin);
    assert_eq!(
        custom(&r),
        Some(W_ENGINE_LOCK_ACTIVE),
        "CloseSlab must refuse while the budget is outstanding: {}",
        logs(&r)
    );

    let wv0 = token_amount(&w.svm, &w.wrapper_vault);
    assert_eq!(wv0, BUDGET);
    let r = recover_terminal(&mut w, BUDGET, DEFAULT_OPTS);
    assert!(r.is_ok(), "tag 29: {}", logs(&r));
    let pool1 = read_pool(&w.svm, &w.pool);
    assert_eq!(
        token_amount(&w.svm, &w.wrapper_vault),
        0,
        "wrapper released the whole budget"
    );
    assert_eq!(
        token_amount(&w.svm, &w.vault),
        STAKE + BUDGET,
        "pool.vault received exactly the budget"
    );
    assert_eq!(
        pool1.total_fees_earned - pool0.total_fees_earned,
        BUDGET,
        "stakers credited exactly the budget"
    );
    assert_eq!(
        pool1.total_pool_value(),
        Some(STAKE + BUDGET),
        "pool value == vault balance"
    );
    assert!(
        pool1.market_resolved(),
        "tag 29 sets the local resolved flag"
    );

    // Idempotent: nothing left to withdraw or book.
    let r = recover_terminal(&mut w, 0, DEFAULT_OPTS);
    assert_eq!(custom(&r), Some(E_NOTHING_TO_RECOVER), "{}", logs(&r));
    let r = recover_terminal(&mut w, 1, DEFAULT_OPTS);
    assert_eq!(
        custom(&r),
        Some(W_ENGINE_LOCK_ACTIVE),
        "wrapper caps tag 41 at the remaining capacity: {}",
        logs(&r)
    );

    // Retire: tag 30 closes the market; the rent refund goes to the admin.
    let admin_l0 = w.svm.get_account(&w.admin.pubkey()).unwrap().lamports;
    let pool_l0 = w.svm.get_account(&w.pool).unwrap().lamports;
    let r = admin_close_slab(&mut w, &admin);
    assert!(r.is_ok(), "tag 30: {}", logs(&r));
    assert_eq!(
        terminal(&w.svm, &w.market),
        WrapperTerminal::Closed,
        "market is a CloseSlab tombstone"
    );
    assert_eq!(
        w.svm.get_account(&w.pool).unwrap().lamports,
        pool_l0,
        "pool PDA lamports unchanged"
    );
    let admin_l1 = w.svm.get_account(&w.admin.pubkey()).unwrap().lamports;
    assert!(admin_l1 > admin_l0, "rent refund forwarded to the admin");
    assert_eq!(
        read_pool(&w.svm, &w.pool).total_pool_value(),
        Some(STAKE + BUDGET)
    );

    // Book-only on a closed market still works (and finds nothing).
    let r = recover_terminal(&mut w, 0, DEFAULT_OPTS);
    assert_eq!(custom(&r), Some(E_NOTHING_TO_RECOVER), "{}", logs(&r));
    let r = recover_terminal(&mut w, 1, DEFAULT_OPTS);
    assert_eq!(
        custom(&r),
        Some(E_MARKET_NOT_TERMINAL),
        "a closed market has nothing to withdraw: {}",
        logs(&r)
    );
}

/// Stakers actually get the budget: a staker who deposited while Live redeems their
/// whole LP after the terminal recovery and receives principal + their pro-rata share
/// of the budget. Withdraw works both with the slab account omitted and, while the
/// market is still Resolved (not closed), with it passed.
#[test]
fn f9_staker_redeems_principal_plus_budget() {
    let Some(mut w) = world("f9_staker_redeems_principal_plus_budget") else {
        return;
    };
    // Second staker so we hold the keypair (world()'s first staker is dropped).
    let bob = deposit(&mut w, STAKE).expect("second staker while Live");
    let bob_lp = token_amount(&w.svm, &bob.lp_ata);
    admin_resolve(&mut w);
    assert!(recover_terminal(&mut w, BUDGET, DEFAULT_OPTS).is_ok());
    let slot = w.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    w.svm.warp_to_slot(slot + 100);
    let before = token_amount(&w.svm, &bob.ata);
    let r = withdraw(&mut w, &bob, bob_lp, true);
    assert!(r.is_ok(), "withdraw: {}", logs(&r));
    let got = token_amount(&w.svm, &bob.ata) - before;
    // Bob holds bob_lp of total_lp (2*STAKE, 1,000 dead). Pool value 2*STAKE + BUDGET.
    let pool = read_pool(&w.svm, &w.pool);
    eprintln!(
        "F-9 redeem: bob got {got} for {bob_lp} LP; pool now value {:?}",
        pool.total_pool_value()
    );
    assert!(
        got > STAKE + BUDGET / 2 - 1_000,
        "bob gets principal + ~half the budget, got {got}"
    );
    assert!(got <= STAKE + BUDGET / 2, "and not more than his share");
}

/// JIT guard: once the WRAPPER is Resolved (here via tag 24, but equally by a
/// permissionless stale resolve that never touches the stake pool), a new deposit
/// is refused with MarketResolved (8), BEFORE tag 29 has run. Without this gate a
/// depositor could buy in at the pre-recovery price and take a cut of the budget.
/// NEGATIVE CONTROL: remove the `reject_deposit_into_terminal_market` call in
/// process_deposit -> this test fails (the deposit succeeds). Recorded in the ledger.
#[test]
fn f9_deposit_refused_once_wrapper_is_resolved() {
    let Some(mut w) = world("f9_deposit_refused_once_wrapper_is_resolved") else {
        return;
    };
    admin_resolve(&mut w);
    assert!(
        !read_pool(&w.svm, &w.pool).market_resolved(),
        "PRE: the local flag is NOT set by the resolve"
    );
    let s = new_staker(&mut w, STAKE);
    let r = deposit_as(&mut w, &s, STAKE);
    assert_eq!(
        custom(&r),
        Some(E_MARKET_RESOLVED),
        "deposit into a resolved market: {}",
        logs(&r)
    );
    assert_eq!(token_amount(&w.svm, &w.vault), STAKE, "nothing moved");
}

/// Live market: tag 29 is refused (30) — while Live, tag 23 is the path.
#[test]
fn f9_recover_terminal_refused_while_live() {
    let Some(mut w) = world("f9_recover_terminal_refused_while_live") else {
        return;
    };
    let r = recover_terminal(&mut w, BUDGET, DEFAULT_OPTS);
    assert_eq!(custom(&r), Some(E_MARKET_NOT_TERMINAL), "{}", logs(&r));
    let r = recover_terminal(&mut w, 0, DEFAULT_OPTS);
    assert_eq!(custom(&r), Some(E_MARKET_NOT_TERMINAL), "{}", logs(&r));
    assert_eq!(token_amount(&w.svm, &w.wrapper_vault), BUDGET);
}

/// Destination pinning: an attacker cannot redirect the payout. A substitute
/// "vault" (even one owned by vault_auth) or a wrong vault_auth is refused before
/// any CPI; the wrapper's own dest-owner check would refuse an attacker-owned dest.
#[test]
fn f9_recover_terminal_destination_is_pinned() {
    let Some(mut w) = world("f9_recover_terminal_destination_is_pinned") else {
        return;
    };
    admin_resolve(&mut w);
    let thief = Pubkey::new_unique();
    let thief_ata = Pubkey::new_unique();
    let mint = w.mint;
    set_token_account(&mut w.svm, thief_ata, &mint, &thief, 0);
    let r = recover_terminal(
        &mut w,
        BUDGET,
        RecoverOpts {
            vault: Some(thief_ata),
            ..DEFAULT_OPTS
        },
    );
    assert_eq!(custom(&r), Some(E_INVALID_PDA), "{}", logs(&r));
    let decoy = Pubkey::new_unique();
    let va = w.vault_auth;
    set_token_account(&mut w.svm, decoy, &mint, &va, 0);
    let r = recover_terminal(
        &mut w,
        BUDGET,
        RecoverOpts {
            vault: Some(decoy),
            ..DEFAULT_OPTS
        },
    );
    assert_eq!(custom(&r), Some(E_INVALID_PDA), "{}", logs(&r));
    let r = recover_terminal(
        &mut w,
        BUDGET,
        RecoverOpts {
            vault_auth: Some(thief),
            ..DEFAULT_OPTS
        },
    );
    assert_eq!(custom(&r), Some(E_INVALID_PDA), "{}", logs(&r));
    assert_eq!(
        token_amount(&w.svm, &w.wrapper_vault),
        BUDGET,
        "nothing moved"
    );
    // A stray that is NOT owned by vault_auth cannot be "swept" (no signature over it).
    let r = recover_terminal(
        &mut w,
        0,
        RecoverOpts {
            stray: Some(thief_ata),
            ..DEFAULT_OPTS
        },
    );
    assert_eq!(custom(&r), Some(E_INVALID_ACCOUNT), "{}", logs(&r));
    // Over-ask: the wrapper's terminal-capacity gate refuses; nothing moves.
    let r = recover_terminal(&mut w, BUDGET + 1, DEFAULT_OPTS);
    assert_eq!(custom(&r), Some(W_ENGINE_LOCK_ACTIVE), "{}", logs(&r));
    assert_eq!(token_amount(&w.svm, &w.vault), STAKE);
    // The honest call still works afterwards.
    assert!(recover_terminal(&mut w, BUDGET, DEFAULT_OPTS).is_ok());
}

/// Griefing 1: a third party front-runs with a DIRECT wrapper tag 41 into pool.vault.
/// The tokens arrive unbooked; tag 29 (amount 0) books them for stakers.
#[test]
fn f9_third_party_direct_tag41_is_still_booked() {
    let Some(mut w) = world("f9_third_party_direct_tag41_is_still_booked") else {
        return;
    };
    admin_resolve(&mut w);
    let vault = w.vault;
    let r = third_party_tag41(&mut w, BUDGET, vault);
    assert!(
        r.is_ok(),
        "PRE: wrapper tag 41 is permissionless into a vault_auth-owned dest: {}",
        logs(&r)
    );
    let p0 = read_pool(&w.svm, &w.pool);
    assert_eq!(token_amount(&w.svm, &w.vault), STAKE + BUDGET);
    assert_eq!(p0.total_pool_value(), Some(STAKE), "PRE: unbooked surplus");
    let r = recover_terminal(&mut w, 0, DEFAULT_OPTS);
    assert!(r.is_ok(), "{}", logs(&r));
    let p1 = read_pool(&w.svm, &w.pool);
    assert_eq!(p1.total_fees_earned - p0.total_fees_earned, BUDGET);
    assert_eq!(p1.total_pool_value(), Some(STAKE + BUDGET));
}

/// Griefing 2: a third party points wrapper tag 41 at a STRAY token account it
/// created with owner = vault_auth. Tag 29 sweeps it (account 9) and books it.
#[test]
fn f9_stray_vault_auth_payout_is_swept_and_booked() {
    let Some(mut w) = world("f9_stray_vault_auth_payout_is_swept_and_booked") else {
        return;
    };
    admin_resolve(&mut w);
    let stray = Pubkey::new_unique();
    let (mint, va) = (w.mint, w.vault_auth);
    set_token_account(&mut w.svm, stray, &mint, &va, 0);
    assert!(third_party_tag41(&mut w, BUDGET, stray).is_ok());
    assert_eq!(
        token_amount(&w.svm, &stray),
        BUDGET,
        "PRE: stranded outside pool.vault"
    );
    let r = recover_terminal(&mut w, 0, DEFAULT_OPTS);
    assert_eq!(
        custom(&r),
        Some(E_NOTHING_TO_RECOVER),
        "without the sweep account: {}",
        logs(&r)
    );
    let r = recover_terminal(
        &mut w,
        0,
        RecoverOpts {
            stray: Some(stray),
            ..DEFAULT_OPTS
        },
    );
    assert!(r.is_ok(), "{}", logs(&r));
    assert_eq!(token_amount(&w.svm, &stray), 0);
    assert_eq!(token_amount(&w.svm, &w.vault), STAKE + BUDGET);
    assert_eq!(
        read_pool(&w.svm, &w.pool).total_pool_value(),
        Some(STAKE + BUDGET)
    );
}

/// Tag 30 is admin-only, and requires a Resolved market.
#[test]
fn f9_admin_close_slab_is_admin_only_and_needs_resolved() {
    let Some(mut w) = world("f9_admin_close_slab_is_admin_only_and_needs_resolved") else {
        return;
    };
    let admin = w.admin.insecure_clone();
    let r = admin_close_slab(&mut w, &admin);
    assert_eq!(
        custom(&r),
        Some(E_MARKET_NOT_TERMINAL),
        "Live: {}",
        logs(&r)
    );
    admin_resolve(&mut w);
    assert!(recover_terminal(&mut w, BUDGET, DEFAULT_OPTS).is_ok());
    let stranger = Keypair::new();
    w.svm.airdrop(&stranger.pubkey(), 1_000_000_000).unwrap();
    let r = admin_close_slab(&mut w, &stranger);
    assert_eq!(custom(&r), Some(E_UNAUTHORIZED), "{}", logs(&r));
    assert_eq!(terminal(&w.svm, &w.market), WrapperTerminal::Resolved);
    assert!(admin_close_slab(&mut w, &admin).is_ok());
    assert_eq!(terminal(&w.svm, &w.market), WrapperTerminal::Closed);
}

/// Dead shares only: every real staker exited BEFORE resolution (real Withdraw).
/// The budget still leaves the wrapper (so the market can retire), but it is NOT
/// booked to the dead shares (F3): it stays in pool.vault unbooked, pool value is
/// unchanged, and the market still retires through tag 30.
#[test]
fn f9_dead_shares_only_budget_leaves_wrapper_but_is_not_booked() {
    let Some(mut w) = world("f9_dead_shares_only_budget_leaves_wrapper_but_is_not_booked") else {
        return;
    };
    let alice = w.alice.take().unwrap();
    let lp = token_amount(&w.svm, &alice.lp_ata);
    assert_eq!(lp, STAKE - MINIMUM_LIQUIDITY);
    let slot = w.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    w.svm.warp_to_slot(slot + 100);
    let r = withdraw(&mut w, &alice, lp, true);
    assert!(r.is_ok(), "alice exits while Live: {}", logs(&r));
    let p0 = read_pool(&w.svm, &w.pool);
    assert_eq!(
        p0.total_lp_supply, MINIMUM_LIQUIDITY,
        "PRE: dead shares only"
    );
    admin_resolve(&mut w);
    let r = recover_terminal(&mut w, BUDGET, DEFAULT_OPTS);
    assert!(
        r.is_ok(),
        "tokens still move out of the wrapper: {}",
        logs(&r)
    );
    let p1 = read_pool(&w.svm, &w.pool);
    assert_eq!(token_amount(&w.svm, &w.wrapper_vault), 0);
    assert_eq!(
        p1.total_fees_earned, p0.total_fees_earned,
        "F3: nothing booked to dead shares"
    );
    assert_eq!(p1.total_pool_value(), p0.total_pool_value());
    let admin = w.admin.insecure_clone();
    let r = admin_close_slab(&mut w, &admin);
    assert!(r.is_ok(), "{}", logs(&r));
    assert_eq!(terminal(&w.svm, &w.market), WrapperTerminal::Closed);
}

/// Security INFO (layout guard): on a Resolved market whose header VERSION reads
/// 17 instead of the pinned 18, the mode byte at 1218 proves nothing. Tag 29, tag 30
/// and Deposit must all refuse with UnsupportedWrapperLayout (32), and nothing may
/// move. Restoring VERSION 18 makes tag 29 work again (the refusal came from the
/// guard, not from the market). The VERSION flip is the only forged byte.
/// NEGATIVE CONTROL: drop the version check in `read_wrapper_terminal` and this
/// test fails (tag 29 succeeds on the version-17 header).
#[test]
fn f9_unpinned_wrapper_layout_is_refused() {
    let Some(mut w) = world("f9_unpinned_wrapper_layout_is_refused") else {
        return;
    };
    admin_resolve(&mut w);
    let set_version = |w: &mut World, v: u16| {
        let mut a = w.svm.get_account(&w.market).unwrap();
        a.data[8..10].copy_from_slice(&v.to_le_bytes());
        w.svm.set_account(w.market, a).unwrap();
    };
    set_version(&mut w, 17);
    assert_eq!(terminal(&w.svm, &w.market), WrapperTerminal::UnknownLayout);
    let r = recover_terminal(&mut w, BUDGET, DEFAULT_OPTS);
    assert_eq!(
        custom(&r),
        Some(E_UNSUPPORTED_WRAPPER_LAYOUT),
        "tag 29: {}",
        logs(&r)
    );
    let r = recover_terminal(&mut w, 0, DEFAULT_OPTS);
    assert_eq!(
        custom(&r),
        Some(E_UNSUPPORTED_WRAPPER_LAYOUT),
        "tag 29 (0): {}",
        logs(&r)
    );
    let admin = w.admin.insecure_clone();
    let r = admin_close_slab(&mut w, &admin);
    assert_eq!(
        custom(&r),
        Some(E_UNSUPPORTED_WRAPPER_LAYOUT),
        "tag 30: {}",
        logs(&r)
    );
    let s = new_staker(&mut w, STAKE);
    let r = deposit_as(&mut w, &s, STAKE);
    assert_eq!(
        custom(&r),
        Some(E_UNSUPPORTED_WRAPPER_LAYOUT),
        "deposit: {}",
        logs(&r)
    );
    assert_eq!(
        token_amount(&w.svm, &w.wrapper_vault),
        BUDGET,
        "nothing moved"
    );
    assert_eq!(token_amount(&w.svm, &w.vault), STAKE, "nothing moved");
    set_version(&mut w, 18);
    let r = recover_terminal(&mut w, BUDGET, DEFAULT_OPTS);
    assert!(r.is_ok(), "control: pinned layout works: {}", logs(&r));
}

/// v5 FIRST_LOSS terminal path (Phase 4 item 6, S1): the market's pre-existing insurance (the
/// creator's BUDGET seed) became CREATOR-class units when the first v5 deposit created the units
/// ledger. Nothing was deployed by stakers, so at terminal the wrapper pays the whole budget into
/// the pool vault as creator-class value (`creator_paid_to_stake_atoms`), and RecoverTerminalInsurance
/// FORWARDS it to the creator (pool.admin) instead of booking it to stakers. The staker redeems
/// exactly its own deposit.
#[test]
fn f9_v5_first_loss_terminal_returns_creator_seed_s1() {
    RISK_MODE.with(|c| c.set(1));
    let Some(mut w) = world("f9_v5_first_loss_terminal_returns_creator_seed_s1") else {
        return;
    };
    RISK_MODE.with(|c| c.set(2));
    assert!(read_pool(&w.svm, &w.pool).is_first_loss());
    let units = percolator_stake::state::derive_wrapper_ins_units(&w.wrapper_id, &w.market).0;
    let u = percolator_stake::state::read_wrapper_ins_units(
        &w.svm.get_account(&units).expect("units ledger created by the first v5 deposit").data,
        &w.market.to_bytes(),
    )
    .expect("units");
    assert_eq!(u.units_creator, BUDGET as u128, "the seed is creator-class");
    assert_eq!(u.units_stake, 0);
    admin_resolve(&mut w);
    let creator_ata = Pubkey::new_unique();
    let (mint, admin) = (w.mint, w.admin.pubkey());
    set_token_account(&mut w.svm, creator_ata, &mint, &admin, 0);
    let caller = Pubkey::new_unique();
    let mut data = vec![29u8];
    data.extend_from_slice(&BUDGET.to_le_bytes());
    let payer = w.payer.insecure_clone();
    let r = send(
        &mut w.svm,
        &payer,
        &[],
        Instruction {
            program_id: w.stake_id,
            accounts: vec![
                AccountMeta::new_readonly(caller, false),
                AccountMeta::new(w.pool, false),
                AccountMeta::new(w.vault, false),
                AccountMeta::new_readonly(w.vault_auth, false),
                AccountMeta::new(w.market, false),
                AccountMeta::new(w.wrapper_vault, false),
                AccountMeta::new_readonly(w.wrapper_vault_auth, false),
                AccountMeta::new_readonly(Pubkey::from_str(TOKEN_PROGRAM).unwrap(), false),
                AccountMeta::new_readonly(w.wrapper_id, false),
                AccountMeta::new(units, false),
                AccountMeta::new(creator_ata, false),
            ],
            data,
        },
    );
    assert!(r.is_ok(), "v5 terminal recovery: {}", logs(&r));
    assert_eq!(token_amount(&w.svm, &creator_ata), BUDGET, "S1: the seed went back to the creator");
    let pool = read_pool(&w.svm, &w.pool);
    assert_eq!(pool.creator_forwarded_atoms, BUDGET);
    assert_eq!(pool.total_fees_earned, 0, "the seed was not booked to stakers");
    // The staker's LP is worth exactly its deposit.
    let alice_lp = token_amount(&w.svm, &w.alice.as_ref().unwrap().lp_ata);
    let claim = percolator_stake::math::calc_collateral_for_withdraw(
        pool.total_lp_supply,
        pool.total_pool_value().unwrap(),
        alice_lp,
    )
    .unwrap();
    assert!(claim <= STAKE && claim + 2 >= STAKE - 1_000, "staker claim {claim} vs deposit {STAKE}");
}
