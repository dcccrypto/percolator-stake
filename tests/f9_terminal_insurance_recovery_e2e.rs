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
// v5: the stake program is loaded at the id the wrapper's devnet build PINS (A6DVNubv, the v2.1 fresh id), so the
// wrapper recognises the pool's vault_auth as the STAKE unit class (Phase 4 item 6). Every other
// F-9 assertion is id-independent.
/// I-3 (security review 2026-10-14): the stake program id the harness loads the stake .so at.
/// Default = the v2.2 RC id the canonical RC wrapper pins. Set `E2E_STAKE_ID` (e.g. `7JrgAUHi…`)
/// together with `F9_WRAPPER_SO` (a wrapper that pins THAT stake id, e.g. the deployed v2.2 dump)
/// and `E2E_STAKE_SO` (a stake .so built with that id) to run against the deployed bytes.
fn stake_id_str() -> String {
    std::env::var("E2E_STAKE_ID").unwrap_or_else(|_| "A6DVNubvzMMETQinK6bipekkaTTrkUu2RMw2kBoJrdkE".to_string())
}
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
const E_CREATOR_ACCOUNT_REQUIRED: u32 = 46;
const E_INSURANCE_CUSTODY_NOT_BOUND: u32 = 47;
const E_MULTI_ASSET_NOT_SUPPORTED: u32 = 48;
const E_INSURANCE_READINGS_DIVERGED: u32 = 44;
/// FEE_ONLY growth-plan reading: the engine `insurance` balance in a market account (pinned
/// v2.2 layout; `wrapper_layout::MARKET_INSURANCE_OFF`).
const MARKET_INSURANCE_OFF: usize = percolator_stake::wrapper_layout::MARKET_INSURANCE_OFF;
// Wrapper EngineLockActive.
const W_ENGINE_LOCK_ACTIVE: u32 = 21;

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
    /// S1: `pool.admin`'s (the creator's) collateral token account; RecoverTerminalInsurance
    /// forwards the creator's insurance seed here.
    creator_ata: Pubkey,
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
    /// M-1: atoms of a NON-creator claim (the staker-reserve fee leg, i.e. trade fees owed to
    /// someone else) forged into the engine insurance just before the bind. 0 = none.
    static PRE_BIND_CLAIM: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// M-1b: a forge run on the market just before the bind; and whether `world` binds at all.
    static PRE_BIND: std::cell::Cell<Option<fn(&mut World)>> = const { std::cell::Cell::new(None) };
    static SKIP_BIND: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn market_rd128(w: &World, off: usize) -> u128 {
    let d = w.svm.get_account(&w.market).unwrap().data;
    u128::from_le_bytes(d[off..off + 16].try_into().unwrap())
}

fn market_wr(w: &mut World, off: usize, bytes: &[u8]) {
    let mut m = w.svm.get_account(&w.market).unwrap();
    m.data[off..off + bytes.len()].copy_from_slice(bytes);
    w.svm.set_account(w.market, m).unwrap();
}

/// M-1: forge `x` atoms of another party's claim inside the engine insurance, exactly as an
/// accrued trade-fee leg sits there: engine `insurance` += x (market 941), the wrapper vault
/// holds the atoms, `insurance_reserve_accrued_atoms` += x (account 544..560); the BUDGETED
/// slice (market 1101) is untouched (fee legs are never credited to a budget).
fn forge_unbudgeted_claim(w: &mut World, x: u64) {
    let mut m = w.svm.get_account(&w.market).unwrap();
    let rd = |d: &[u8], o: usize| u128::from_le_bytes(d[o..o + 16].try_into().unwrap());
    let ins = rd(&m.data, MARKET_INSURANCE_OFF) + x as u128;
    m.data[MARKET_INSURANCE_OFF..MARKET_INSURANCE_OFF + 16].copy_from_slice(&ins.to_le_bytes());
    let vault_hdr = MARKET_INSURANCE_OFF - 16; // engine `vault` (u128) precedes `insurance`
    let v = rd(&m.data, vault_hdr) + x as u128;
    m.data[vault_hdr..vault_hdr + 16].copy_from_slice(&v.to_le_bytes());
    let r = rd(&m.data, 544) + x as u128;
    m.data[544..560].copy_from_slice(&r.to_le_bytes());
    w.svm.set_account(w.market, m).unwrap();
    let bal = token_amount(&w.svm, &w.wrapper_vault);
    let (wv, mint, wva) = (w.wrapper_vault, w.mint, w.wrapper_vault_auth);
    set_token_account(&mut w.svm, wv, &mint, &wva, bal + x);
}

fn world(name: &str) -> Option<World> {
    let (so, wso) = (stake_so(), wrapper_so());
    if !so.exists() || !wso.exists() {
        panic!(
            "MISSING ARTIFACT (a hard failure, never a skip: GH#311 S-3) {name}: .so missing (stake={} wrapper={})",
            so.display(),
            wso.display()
        );
    }
    let mut svm = LiteSVM::new().with_spl_programs();
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
        creator_ata: Pubkey::new_unique(),
    };
    {
        let (ca, mint, admin) = (w.creator_ata, w.mint, w.admin.pubkey());
        set_token_account(&mut w.svm, ca, &mint, &admin, 0);
    }
    w.alice = Some(deposit(&mut w, STAKE).expect("staker deposit while Live"));
    let claim = PRE_BIND_CLAIM.with(|c| c.get());
    if claim > 0 {
        forge_unbudgeted_claim(&mut w, claim);
    }
    if let Some(f) = PRE_BIND.with(|c| c.get()) {
        f(&mut w);
    }
    if SKIP_BIND.with(|c| c.get()) {
        return Some(w);
    }
    // Real Bind (tag 19). FEE_ONLY growth-plan reading: the pool is writable (the bind records
    // the creator's seed = the engine insurance now, i.e. BUDGET).
    let (admin_k, payer_k) = (w.admin.insecure_clone(), w.payer.insecure_clone());
    send(
        &mut w.svm,
        &payer_k,
        &[&admin_k],
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
        data.extend_from_slice(&percolator_stake::state::deposit_consent_bytes(5_000, 3_000, 500));
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
    no_creator: bool,
}
const DEFAULT_OPTS: RecoverOpts = RecoverOpts {
    vault: None,
    vault_auth: None,
    stray: None,
    no_creator: false,
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
    // S1 (FEE_ONLY): the creator's account rides in the same optional tail (told apart from the
    // stray by its SPL owner). `no_creator` drops it to prove the refusal.
    if !o.no_creator {
        accounts.push(AccountMeta::new(w.creator_ata, false));
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
///   tag 29 (permissionless): exactly BUDGET moves wrapper -> pool.vault, and (S1,
///   2026-10-14, growth-plan reading) exactly BUDGET is forwarded to the creator (pool.admin):
///   the bind recorded the creator's seed = BUDGET (the whole fund; there is no growth here),
///   and the creator gets min(seed remaining, surplus). Stakers' value is unchanged.
///   tag 30: the market retires to a tombstone, and the rent refund reaches the admin.
/// NEGATIVE CONTROL: on the pre-fix stake .so (2212e17), tag 29 and tag 30 do not
/// exist (InvalidInstructionData), so this test fails at the first tag-29 assert. On the
/// pre-S1 .so (aebbff6) the budget is booked to the stakers instead: the creator-balance and
/// pool-value asserts below fail (BUDGET booked as fees).
#[test]
fn f9_bound_resolved_market_returns_budget_to_creator_and_retires() {
    let Some(mut w) = world("f9_bound_resolved_market_returns_budget_to_creator_and_retires")
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
    // S1: without the creator's account the settlement refuses (it would otherwise have to book
    // the creator's seed to the stakers), and nothing moves.
    let r = recover_terminal(
        &mut w,
        BUDGET,
        RecoverOpts {
            no_creator: true,
            ..DEFAULT_OPTS
        },
    );
    assert_eq!(custom(&r), Some(E_CREATOR_ACCOUNT_REQUIRED), "{}", logs(&r));
    assert_eq!(token_amount(&w.svm, &w.wrapper_vault), BUDGET, "nothing moved");
    let r = recover_terminal(&mut w, BUDGET, DEFAULT_OPTS);
    assert!(r.is_ok(), "tag 29: {}", logs(&r));
    let pool1 = read_pool(&w.svm, &w.pool);
    assert_eq!(
        token_amount(&w.svm, &w.wrapper_vault),
        0,
        "wrapper released the whole budget"
    );
    assert_eq!(
        token_amount(&w.svm, &w.creator_ata),
        BUDGET,
        "S1: the creator got its whole seed back"
    );
    assert_eq!(
        token_amount(&w.svm, &w.vault),
        STAKE,
        "pool.vault keeps exactly the stakers' principal"
    );
    assert_eq!(
        pool1.total_fees_earned, pool0.total_fees_earned,
        "nothing booked to stakers"
    );
    assert_eq!(pool1.creator_surplus_forwarded_atoms(), BUDGET);
    assert_eq!(
        pool1.total_pool_value(),
        Some(STAKE),
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
    assert_eq!(read_pool(&w.svm, &w.pool).total_pool_value(), Some(STAKE));

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

/// S1 (2026-10-14, growth-plan reading): the whole terminal budget is the creator's seed
/// recorded at bind (no growth above it here), so it is not a windfall for stakers (growth is:
/// `f9_fee_only_growth_above_seed_stays_with_stakers_forged_seed`). A staker who deposited while
/// Live redeems exactly its principal after the terminal recovery (less nothing: the dead
/// shares hold their own 1,000); the creator receives the whole budget. Withdraw works both
/// with the slab account omitted and, while the market is still Resolved, with it passed.
/// NEGATIVE CONTROL: on the pre-S1 .so (aebbff6) bob receives principal + ~half the budget
/// and the creator 0, so both asserts fail.
#[test]
fn f9_staker_redeems_principal_creator_gets_budget_s1() {
    let Some(mut w) = world("f9_staker_redeems_principal_creator_gets_budget_s1") else {
        return;
    };
    // Second staker so we hold the keypair (world()'s first staker is dropped).
    let bob = deposit(&mut w, STAKE).expect("second staker while Live");
    let bob_lp = token_amount(&w.svm, &bob.lp_ata);
    admin_resolve(&mut w);
    assert!(recover_terminal(&mut w, BUDGET, DEFAULT_OPTS).is_ok());
    assert_eq!(token_amount(&w.svm, &w.creator_ata), BUDGET, "S1: creator seed returned");
    let slot = w.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    w.svm.warp_to_slot(slot + 100);
    let before = token_amount(&w.svm, &bob.ata);
    let r = withdraw(&mut w, &bob, bob_lp, true);
    assert!(r.is_ok(), "withdraw: {}", logs(&r));
    let got = token_amount(&w.svm, &bob.ata) - before;
    let pool = read_pool(&w.svm, &w.pool);
    eprintln!(
        "S1 redeem: bob got {got} for {bob_lp} LP; pool now value {:?}",
        pool.total_pool_value()
    );
    assert!(got <= STAKE && got + 1 >= STAKE, "bob gets exactly his principal, got {got}");
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
/// The tokens arrive unbooked; tag 29 (amount 0) settles them. S1 (2026-10-14, growth-plan
/// reading): they are the creator's seed recorded at bind (BUDGET), so they go to the creator,
/// never to the stakers (a staker would otherwise profit from this front-run).
/// NEGATIVE CONTROL: on the pre-S1 .so the BUDGET is booked as staker fees.
#[test]
fn f9_third_party_direct_tag41_is_still_settled_to_creator() {
    let Some(mut w) = world("f9_third_party_direct_tag41_is_still_settled_to_creator") else {
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
    assert_eq!(p1.total_fees_earned, p0.total_fees_earned, "nothing booked to stakers");
    assert_eq!(p1.total_pool_value(), Some(STAKE));
    assert_eq!(token_amount(&w.svm, &w.creator_ata), BUDGET);
    assert_eq!(token_amount(&w.svm, &w.vault), STAKE);
}

/// Griefing 2: a third party points wrapper tag 41 at a STRAY token account it
/// created with owner = vault_auth. Tag 29 sweeps it (the stray rides with the creator account
/// in the optional tail, in either order) and S1 forwards it to the creator.
#[test]
fn f9_stray_vault_auth_payout_is_swept_and_settled() {
    let Some(mut w) = world("f9_stray_vault_auth_payout_is_swept_and_settled") else {
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
    assert_eq!(token_amount(&w.svm, &w.vault), STAKE);
    assert_eq!(token_amount(&w.svm, &w.creator_ata), BUDGET);
    assert_eq!(read_pool(&w.svm, &w.pool).total_pool_value(), Some(STAKE));
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
/// The budget still leaves the wrapper (so the market can retire). It is not booked to the
/// dead shares (F3), and (S1, 2026-10-14) it is no longer stranded unbooked in pool.vault:
/// it goes back to the creator. The market still retires through tag 30.
/// NEGATIVE CONTROL: on the pre-S1 .so the budget stays in pool.vault for ever (creator 0).
#[test]
fn f9_dead_shares_only_budget_returns_to_creator_not_stranded() {
    let Some(mut w) = world("f9_dead_shares_only_budget_returns_to_creator_not_stranded") else {
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
    assert_eq!(token_amount(&w.svm, &w.creator_ata), BUDGET, "S1: not stranded");
    assert_eq!(
        token_amount(&w.svm, &w.vault),
        p1.total_pool_value().unwrap(),
        "vault == books (only the dead shares' own value is left)"
    );
    let admin = w.admin.insecure_clone();
    let r = admin_close_slab(&mut w, &admin);
    assert!(r.is_ok(), "{}", logs(&r));
    assert_eq!(terminal(&w.svm, &w.market), WrapperTerminal::Closed);
}

/// Security INFO (layout guard): on a Resolved market whose header VERSION reads
/// 17 (or 18, the v2.1 layout whose mode byte is 48 B earlier) instead of the pinned 19, the
/// mode byte at 1266 proves nothing. Tag 29, tag 30
/// and Deposit must all refuse with UnsupportedWrapperLayout (32), and nothing may
/// move. Restoring VERSION 19 makes tag 29 work again (the refusal came from the
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
    // The v2.1 header version (18) is refused too: its engine header is 48 B shorter, so the
    // mode byte this program reads would be a different field (silent misread, not an error).
    set_version(&mut w, 18);
    assert_eq!(terminal(&w.svm, &w.market), WrapperTerminal::UnknownLayout);
    set_version(&mut w, percolator_stake::state::WRAPPER_SUPPORTED_VERSION);
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
    assert_eq!(pool.creator_total_forwarded_atoms(), BUDGET);
    assert_eq!(pool.creator_seed_atoms(), BUDGET, "close-out: FIRST_LOSS bind recorded the seed");
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

// ── FEE_ONLY growth-plan reading (2026-10-14): seed recorded at bind, stakers keep growth ─────

/// FORGE the close-out seed record (bytes 457..464 + flag byte 333 bit 0). `None` = no record
/// (a pool bound before the close-out build: bytes and flag cleared).
fn forge_seed(w: &mut World, seed: Option<u64>) {
    let mut acct = w.svm.get_account(&w.pool).unwrap();
    acct.data[457..464].copy_from_slice(&seed.unwrap_or(0).to_le_bytes()[..7]);
    if seed.is_some() {
        acct.data[333] |= 1;
    } else {
        acct.data[333] &= !1;
    }
    w.svm.set_account(w.pool, acct).unwrap();
    let p = read_pool(&w.svm, &w.pool);
    assert_eq!(p.creator_seed_atoms(), seed.unwrap_or(0));
    assert_eq!(p.creator_seed_recorded(), seed.is_some());
}

fn bind_again(w: &mut World, pool_writable: bool) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let (admin_k, payer_k) = (w.admin.insecure_clone(), w.payer.insecure_clone());
    let pool_meta = if pool_writable {
        AccountMeta::new(w.pool, false)
    } else {
        AccountMeta::new_readonly(w.pool, false)
    };
    send(
        &mut w.svm,
        &payer_k,
        &[&admin_k],
        Instruction {
            program_id: w.stake_id,
            accounts: vec![
                AccountMeta::new(w.admin.pubkey(), true),
                pool_meta,
                AccountMeta::new_readonly(w.vault_auth, false),
                AccountMeta::new(w.market, false),
                AccountMeta::new_readonly(w.wrapper_id, false),
            ],
            data: vec![19u8],
        },
    )
}

/// The real Bind (tag 19) on a FEE_ONLY pool records the creator's seed = the engine insurance
/// balance read from the REAL wrapper market at byte 941 (pins `MARKET_INSURANCE_OFF` on the
/// real .so: the raw bytes there are exactly the BUDGET the creator topped up). A FEE_ONLY bind
/// with a read-only pool account is refused by stake (16) before any CPI; with a writable pool
/// the repeat bind reaches the wrapper and fails there (already bound), not with 16.
/// NEGATIVE CONTROL: on 3c715dc (no seed record) the record reads 0 and the read-only bind
/// reaches the wrapper (not 16).
#[test]
fn f9_fee_only_bind_records_creator_seed_from_real_wrapper() {
    let Some(mut w) = world("f9_fee_only_bind_records_creator_seed_from_real_wrapper") else {
        return;
    };
    let m = w.svm.get_account(&w.market).unwrap();
    let raw = u128::from_le_bytes(m.data[MARKET_INSURANCE_OFF..MARKET_INSURANCE_OFF + 16].try_into().unwrap());
    assert_eq!(raw, BUDGET as u128, "PIN: engine insurance at byte 941 on the real wrapper");
    assert_eq!(read_pool(&w.svm, &w.pool).creator_seed_atoms(), BUDGET);
    let r = bind_again(&mut w, false);
    assert_eq!(custom(&r), Some(E_INVALID_ACCOUNT), "{}", logs(&r));
    let r = bind_again(&mut w, true);
    assert!(r.is_err());
    assert_ne!(custom(&r), Some(E_INVALID_ACCOUNT), "{}", logs(&r));
    assert_eq!(read_pool(&w.svm, &w.pool).creator_seed_atoms(), BUDGET);
}

/// Growth above the seed stays with the FEE_ONLY stakers. FORGED: the seed record is lowered to
/// 3M (as if the creator had seeded 3M and the fund had grown to the 5M BUDGET; the harness has
/// no real fee path into a FEE_ONLY market's insurance). Two partial tag-29 withdrawals:
///   2M -> all of it to the creator (seed first), stakers +0;
///   3M -> 1M to the creator (seed remaining), 2M booked to stakers as fees.
/// Without the creator account while seed remains: 46.
/// NEGATIVE CONTROLS: on 1f694e1 (FEE_ONLY -> creator) the creator gets all 5M and stakers 0;
/// on 3c715dc (held routing) the creator gets 0 and stakers 5M.
#[test]
fn f9_fee_only_growth_above_seed_stays_with_stakers_forged_seed() {
    let Some(mut w) = world("f9_fee_only_growth_above_seed_stays_with_stakers_forged_seed") else {
        return;
    };
    const SEED: u64 = 3_000_000;
    forge_seed(&mut w, Some(SEED));
    let p0 = read_pool(&w.svm, &w.pool);
    admin_resolve(&mut w);
    let r = recover_terminal(
        &mut w,
        2_000_000,
        RecoverOpts {
            no_creator: true,
            ..DEFAULT_OPTS
        },
    );
    assert_eq!(custom(&r), Some(E_CREATOR_ACCOUNT_REQUIRED), "{}", logs(&r));
    let r = recover_terminal(&mut w, 2_000_000, DEFAULT_OPTS);
    assert!(r.is_ok(), "{}", logs(&r));
    let p1 = read_pool(&w.svm, &w.pool);
    assert_eq!(token_amount(&w.svm, &w.creator_ata), 2_000_000, "seed first");
    assert_eq!(p1.total_fees_earned, p0.total_fees_earned);
    assert_eq!(p1.creator_seed_remaining(), 1_000_000);
    let r = recover_terminal(&mut w, BUDGET - 2_000_000, DEFAULT_OPTS);
    assert!(r.is_ok(), "{}", logs(&r));
    let p2 = read_pool(&w.svm, &w.pool);
    assert_eq!(token_amount(&w.svm, &w.creator_ata), SEED, "creator gets exactly its seed");
    assert_eq!(p2.total_fees_earned - p0.total_fees_earned, BUDGET - SEED, "growth to stakers");
    assert_eq!(p2.creator_surplus_forwarded_atoms(), SEED);
    assert_eq!(p2.creator_seed_remaining(), 0);
    assert_eq!(p2.total_pool_value(), Some(STAKE + BUDGET - SEED));
    assert_eq!(token_amount(&w.svm, &w.vault), STAKE + BUDGET - SEED, "vault == books");
    assert_eq!(token_amount(&w.svm, &w.wrapper_vault), 0);
    // Nothing more is owed: the pre-S1 account shape now works and finds nothing.
    let r = recover_terminal(
        &mut w,
        0,
        RecoverOpts {
            no_creator: true,
            ..DEFAULT_OPTS
        },
    );
    assert_eq!(custom(&r), Some(E_NOTHING_TO_RECOVER), "{}", logs(&r));
}

/// A FEE_ONLY pool with NO seed recorded (bound before this build; FORGED by zeroing the
/// record) owes the creator nothing while real stakers exist: tag 29 in the pre-S1 shape books
/// the whole budget to the stakers, exactly as aebbff6 did. This is the documented fallback.
#[test]
fn f9_fee_only_no_seed_record_books_budget_to_stakers_forged() {
    let Some(mut w) = world("f9_fee_only_no_seed_record_books_budget_to_stakers_forged") else {
        return;
    };
    forge_seed(&mut w, None);
    let p0 = read_pool(&w.svm, &w.pool);
    admin_resolve(&mut w);
    let r = recover_terminal(
        &mut w,
        BUDGET,
        RecoverOpts {
            no_creator: true,
            ..DEFAULT_OPTS
        },
    );
    assert!(r.is_ok(), "{}", logs(&r));
    let p1 = read_pool(&w.svm, &w.pool);
    assert_eq!(p1.total_fees_earned - p0.total_fees_earned, BUDGET);
    assert_eq!(token_amount(&w.svm, &w.creator_ata), 0);
    assert_eq!(p1.total_pool_value(), Some(STAKE + BUDGET));
}

// ── CLOSE-OUT RULE (Khubair 2026-10-14, every v5 mode) — FEE_ONLY edge cases ─────────────────

/// Zero real stakers, fund above the seed. FORGED: the seed record lowered to 3M (the creator
/// seeded 3M, the fund grew to the 5M BUDGET). The creator gets exactly 3M; the 2M of growth is
/// NOT the creator's: it is left unbooked in pool.vault (nothing booked to the dead shares) and
/// recorded as unclaimed (pool bytes 281..288 + 334). A repeat call pays the creator nothing more;
/// the market still retires.
/// NEGATIVE CONTROL: on f372fa2 / 96a90483 (the live devnet build) the creator receives all 5M
/// (`terminal_surplus_to_creator` with no real staker) and the creator-balance assert fails.
#[test]
fn closeout_fee_only_zero_stakers_creator_capped_at_seed_rest_unclaimed() {
    let Some(mut w) = world("closeout_fee_only_zero_stakers_creator_capped_at_seed_rest_unclaimed")
    else {
        return;
    };
    const SEED: u64 = 3_000_000;
    let alice = w.alice.take().unwrap();
    let lp = token_amount(&w.svm, &alice.lp_ata);
    let slot = w.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    w.svm.warp_to_slot(slot + 100);
    assert!(withdraw(&mut w, &alice, lp, true).is_ok());
    forge_seed(&mut w, Some(SEED));
    let p0 = read_pool(&w.svm, &w.pool);
    assert!(!p0.has_real_lp_holders(), "PRE: dead shares only");
    admin_resolve(&mut w);
    let r = recover_terminal(&mut w, BUDGET, DEFAULT_OPTS);
    assert!(r.is_ok(), "{}", logs(&r));
    let p1 = read_pool(&w.svm, &w.pool);
    assert_eq!(token_amount(&w.svm, &w.creator_ata), SEED, "creator: the seed, never more");
    assert_eq!(p1.total_pool_value(), p0.total_pool_value(), "nothing booked to dead shares");
    assert_eq!(p1.total_fees_earned, p0.total_fees_earned);
    assert_eq!(p1.terminal_unclaimed_atoms(), BUDGET - SEED, "growth recorded as unclaimed");
    assert_eq!(
        token_amount(&w.svm, &w.vault),
        p1.total_pool_value().unwrap() + (BUDGET - SEED),
        "vault == books + unclaimed (to the atom)"
    );
    assert_eq!(token_amount(&w.svm, &w.wrapper_vault), 0);
    let r = recover_terminal(&mut w, 0, DEFAULT_OPTS);
    assert_eq!(custom(&r), Some(E_NOTHING_TO_RECOVER), "{}", logs(&r));
    assert_eq!(token_amount(&w.svm, &w.creator_ata), SEED);
    let admin = w.admin.insecure_clone();
    let r = admin_close_slab(&mut w, &admin);
    assert!(r.is_ok(), "{}", logs(&r));
    assert_eq!(terminal(&w.svm, &w.market), WrapperTerminal::Closed);
    let p2 = read_pool(&w.svm, &w.pool);
    assert_eq!(p2.terminal_unclaimed_atoms(), BUDGET - SEED, "still recorded after the close");
    assert_eq!(token_amount(&w.svm, &w.creator_ata), SEED);
}

/// Fund below the seed (FORGED record 8M > the 5M fund, i.e. losses ate 3M of the seed): the
/// creator gets what is left (5M), the stakers 0 of the fund (their principal untouched).
/// NEGATIVE CONTROL: on 3c715dc (S1-only) the 5M is booked to the stakers.
#[test]
fn closeout_fee_only_fund_below_seed_all_to_creator_stakers_zero() {
    let Some(mut w) = world("closeout_fee_only_fund_below_seed_all_to_creator_stakers_zero") else {
        return;
    };
    forge_seed(&mut w, Some(8_000_000));
    let p0 = read_pool(&w.svm, &w.pool);
    assert!(p0.has_real_lp_holders());
    admin_resolve(&mut w);
    let r = recover_terminal(&mut w, BUDGET, DEFAULT_OPTS);
    assert!(r.is_ok(), "{}", logs(&r));
    let p1 = read_pool(&w.svm, &w.pool);
    assert_eq!(token_amount(&w.svm, &w.creator_ata), BUDGET, "creator: what is left of the seed");
    assert_eq!(p1.total_pool_value(), p0.total_pool_value(), "stakers: 0 of the fund");
    assert_eq!(p1.creator_seed_remaining(), 3_000_000, "the lost part is simply not there");
    assert_eq!(p1.terminal_unclaimed_atoms(), 0);
    assert_eq!(token_amount(&w.svm, &w.vault), p1.total_pool_value().unwrap(), "vault == books");
}

/// AdminCloseSlab (tag 30) reservation path: a third party pushes the whole budget into
/// pool.vault with wrapper tag 41 directly; the admin then closes the slab. Tag 30 books only the
/// part that is not the creator's (BUDGET - seed, growth to the stakers) and leaves the seed
/// unbooked; the next tag 29 (amount 0, closed market) forwards exactly the seed. FORGED seed 3M.
#[test]
fn closeout_fee_only_admin_close_slab_reserves_only_the_seed() {
    let Some(mut w) = world("closeout_fee_only_admin_close_slab_reserves_only_the_seed") else {
        return;
    };
    const SEED: u64 = 3_000_000;
    forge_seed(&mut w, Some(SEED));
    let p0 = read_pool(&w.svm, &w.pool);
    admin_resolve(&mut w);
    let vault = w.vault;
    let r = third_party_tag41(&mut w, BUDGET, vault);
    assert!(r.is_ok(), "{}", logs(&r));
    let admin = w.admin.insecure_clone();
    let r = admin_close_slab(&mut w, &admin);
    assert!(r.is_ok(), "{}", logs(&r));
    let p1 = read_pool(&w.svm, &w.pool);
    assert_eq!(
        p1.total_pool_value().unwrap() - p0.total_pool_value().unwrap(),
        BUDGET - SEED,
        "tag 30 books the growth to the stakers, not the seed"
    );
    assert_eq!(token_amount(&w.svm, &w.creator_ata), 0);
    let r = recover_terminal(&mut w, 0, DEFAULT_OPTS);
    assert!(r.is_ok(), "{}", logs(&r));
    let p2 = read_pool(&w.svm, &w.pool);
    assert_eq!(token_amount(&w.svm, &w.creator_ata), SEED);
    assert_eq!(p2.total_pool_value(), p1.total_pool_value());
    assert_eq!(token_amount(&w.svm, &w.vault), p2.total_pool_value().unwrap(), "vault == books");
}

// ── Security review 2026-10-14: M-1 (seed = creator's own money) and M-2 (custody) ──────────

/// M-1: the seed recorded at bind is the creator's OWN money only. FORGED: 2M of another
/// party's claim (an accrued staker-reserve fee leg) sits in the engine insurance at bind. The
/// record is the budgeted slice (BUDGET), not the raw insurance (BUDGET + 2M), so at close the
/// creator cannot take that 2M out of the stakers' share. Also pins the real wrapper offsets of
/// the budget total (1101) and reserved credit (1085).
/// NEGATIVE CONTROL: on 8291e92 the record is the raw engine insurance, BUDGET + 2M.
#[test]
fn closeout_m1_seed_excludes_other_claims_in_insurance_forged_fee_leg() {
    const CLAIM: u64 = 2_000_000;
    PRE_BIND_CLAIM.with(|c| c.set(CLAIM));
    let w = world("closeout_m1_seed_excludes_other_claims_in_insurance_forged_fee_leg");
    PRE_BIND_CLAIM.with(|c| c.set(0));
    let Some(w) = w else { return };
    let m = w.svm.get_account(&w.market).unwrap();
    let rd = |o: usize| u128::from_le_bytes(m.data[o..o + 16].try_into().unwrap());
    assert_eq!(rd(MARKET_INSURANCE_OFF), (BUDGET + CLAIM) as u128, "PRE: claim inside insurance");
    assert_eq!(
        rd(percolator_stake::wrapper_layout::MARKET_INS_BUDGET_TOTAL_OFF),
        BUDGET as u128,
        "PIN: real wrapper budget total at 1101 == the creator's top-up"
    );
    assert_eq!(rd(percolator_stake::wrapper_layout::MARKET_INS_CREDIT_RESERVED_OFF), 0, "PIN 1085");
    let b = percolator_stake::state::read_wrapper_bind_insurance(&m.data).expect("pinned");
    assert_eq!(b.max_market_slots, 1, "PIN: max_market_slots @626 on the real wrapper");
    assert_eq!(b.asset0_budget_remaining, BUDGET as u128, "PIN: asset-0 slot budget/spent @3049..3113");
    assert_eq!((b.asset0_stale_long, b.asset0_stale_short), (0, 0), "PIN: stale counts @2759/2767");
    assert_eq!(b.vault, rd(percolator_stake::wrapper_layout::MARKET_INSURANCE_OFF - 16), "PIN vault @925");
    let p = read_pool(&w.svm, &w.pool);
    assert!(p.creator_seed_recorded());
    assert_eq!(p.creator_seed_atoms(), BUDGET, "seed = the creator's own (budgeted) money");
}

fn rotate(w: &mut World, tag: u8, pool_writable: bool) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let (admin_k, payer_k) = (w.admin.insecure_clone(), w.payer.insecure_clone());
    let pool_meta = if pool_writable {
        AccountMeta::new(w.pool, false)
    } else {
        AccountMeta::new_readonly(w.pool, false)
    };
    send(
        &mut w.svm,
        &payer_k,
        &[&admin_k],
        Instruction {
            program_id: w.stake_id,
            accounts: vec![
                AccountMeta::new(w.admin.pubkey(), true),
                pool_meta,
                AccountMeta::new_readonly(w.vault_auth, false),
                AccountMeta::new_readonly(w.admin.pubkey(), true), // new target = the creator
                AccountMeta::new(w.market, false),
                AccountMeta::new_readonly(w.wrapper_id, false),
            ],
            data: vec![tag],
        },
    )
}

fn burn(w: &mut World) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let (admin_k, payer_k) = (w.admin.insecure_clone(), w.payer.insecure_clone());
    send(
        &mut w.svm,
        &payer_k,
        &[&admin_k],
        Instruction {
            program_id: w.stake_id,
            accounts: vec![
                AccountMeta::new(w.admin.pubkey(), true),
                AccountMeta::new(w.pool, false),
                AccountMeta::new_readonly(w.vault_auth, false),
                AccountMeta::new(w.market, false),
                AccountMeta::new_readonly(w.wrapper_id, false),
            ],
            data: vec![21u8],
        },
    )
}

fn custody(w: &World) -> ([u8; 32], [u8; 32]) {
    percolator_stake::state::read_wrapper_asset0_insurance_keys(&w.svm.get_account(&w.market).unwrap().data)
        .expect("pinned market")
}

/// M-2 on the real wrapper (FEE_ONLY, Live, not burned):
///   * PIN: after the bind, asset 0's insurance authority (1422) and operator (1454) are vault_auth.
///   * Tag 22 (operator back to the creator) with a read-only pool: 16, nothing moves.
///   * Tag 22 writable: the operator is the creator's again AND the seed record is cleared.
///   * BurnAssetAdmin now refuses with 47 (custody not bound); nothing burned.
///   * Tag 20 (authority back) also clears; a re-bind (tag 19) records a fresh seed and restores
///     custody; then the burn succeeds.
///
/// NEGATIVE CONTROL: on 8291e92 the record survives tag 22 (stale seed) and the burn succeeds
/// with the operator on the creator.
#[test]
fn closeout_m2_rotate_back_clears_seed_and_burn_requires_custody() {
    let Some(mut w) = world("closeout_m2_rotate_back_clears_seed_and_burn_requires_custody") else {
        return;
    };
    let va = w.vault_auth.to_bytes();
    let me = w.admin.pubkey().to_bytes();
    assert_eq!(custody(&w), (va, va), "PIN: authority @1422 and operator @1454 = vault_auth");
    assert_eq!(read_pool(&w.svm, &w.pool).creator_seed_atoms(), BUDGET);
    let r = rotate(&mut w, 22, false);
    assert_eq!(custom(&r), Some(E_INVALID_ACCOUNT), "read-only v5 pool: {}", logs(&r));
    assert_eq!(custody(&w), (va, va));
    let r = rotate(&mut w, 22, true);
    assert!(r.is_ok(), "tag 22: {}", logs(&r));
    assert_eq!(custody(&w), (va, me), "operator back with the creator");
    let p = read_pool(&w.svm, &w.pool);
    assert!(!p.creator_seed_recorded(), "seed record cleared");
    assert_eq!(p.creator_seed_atoms(), 0);
    let r = burn(&mut w);
    assert_eq!(custom(&r), Some(E_INSURANCE_CUSTODY_NOT_BOUND), "{}", logs(&r));
    assert!(!read_pool(&w.svm, &w.pool).asset_admin_burned());
    let r = rotate(&mut w, 20, true);
    assert!(r.is_ok(), "tag 20: {}", logs(&r));
    assert_eq!(custody(&w), (me, me));
    let r = burn(&mut w);
    assert_eq!(custom(&r), Some(E_INSURANCE_CUSTODY_NOT_BOUND), "{}", logs(&r));
    let r = bind_again(&mut w, true);
    assert!(r.is_ok(), "re-bind: {}", logs(&r));
    assert_eq!(custody(&w), (va, va));
    let p = read_pool(&w.svm, &w.pool);
    assert!(p.creator_seed_recorded());
    assert_eq!(p.creator_seed_atoms(), BUDGET, "fresh seed at the re-bind");
    let r = burn(&mut w);
    assert!(r.is_ok(), "burn with custody bound: {}", logs(&r));
    assert!(read_pool(&w.svm, &w.pool).asset_admin_burned());
}

// ── Delta review 22c6de5: M-1b (asset 0 only, single-asset markets, no hidden K/F reservation) ──

/// M-1b: another asset's insurance budget is NOT the creator's asset-0 seed. FORGED (the harness
/// cannot activate a second asset): 3M of budget that is not asset 0's is added to the engine's
/// GROUP-WIDE budget total (1101), the insurance (941) and the vault (925), exactly what an
/// activated asset 1 with a 3M top-up adds to those header aggregates; asset 0's own slot
/// budget is untouched. The seed is asset 0's budget (BUDGET), not BUDGET + 3M.
/// NEGATIVE CONTROL: on 22c6de5 the seed reads the group-wide total, BUDGET + 3M.
#[test]
fn closeout_m1b_seed_is_asset0_budget_not_group_total_forged() {
    fn forge(w: &mut World) {
        use percolator_stake::wrapper_layout as wl;
        const X: u128 = 3_000_000;
        for off in [wl::MARKET_INS_BUDGET_TOTAL_OFF, wl::MARKET_INSURANCE_OFF, wl::MARKET_VAULT_OFF] {
            let v = market_rd128(w, off) + X;
            market_wr(w, off, &v.to_le_bytes());
        }
        let bal = token_amount(&w.svm, &w.wrapper_vault);
        let (wv, mint, wva) = (w.wrapper_vault, w.mint, w.wrapper_vault_auth);
        set_token_account(&mut w.svm, wv, &mint, &wva, bal + X as u64);
    }
    PRE_BIND.with(|c| c.set(Some(forge)));
    let w = world("closeout_m1b_seed_is_asset0_budget_not_group_total_forged");
    PRE_BIND.with(|c| c.set(None));
    let Some(w) = w else { return };
    assert_eq!(
        market_rd128(&w, percolator_stake::wrapper_layout::MARKET_INS_BUDGET_TOTAL_OFF),
        (BUDGET + 3_000_000) as u128,
        "PRE: group-wide total includes the other asset's budget"
    );
    let p = read_pool(&w.svm, &w.pool);
    assert!(p.creator_seed_recorded());
    assert_eq!(p.creator_seed_atoms(), BUDGET, "seed = asset 0's own budget only");
}

/// M-1b belt and braces: a v5 bind refuses a multi-asset market (48) before any CPI; custody does
/// not move. FORGED: `max_market_slots` (626) = 2 on the real market just before the bind (the
/// byte the wrapper's own units ledger refuses on, W-10). Restoring 1 lets the same bind succeed.
/// NEGATIVE CONTROL: on 22c6de5 the stake program never reads the byte (the bind is not refused
/// with 48).
#[test]
fn closeout_m1b_multi_asset_bind_refused_forged() {
    SKIP_BIND.with(|c| c.set(true));
    let w = world("closeout_m1b_multi_asset_bind_refused_forged");
    SKIP_BIND.with(|c| c.set(false));
    let Some(mut w) = w else { return };
    let off = percolator_stake::wrapper_layout::MARKET_MAX_MARKET_SLOTS_OFF;
    let d = w.svm.get_account(&w.market).unwrap().data;
    assert_eq!(u32::from_le_bytes(d[off..off + 4].try_into().unwrap()), 1, "PIN @626");
    let me = w.admin.pubkey().to_bytes();
    market_wr(&mut w, off, &2u32.to_le_bytes());
    let r = bind_again(&mut w, true);
    assert_eq!(custom(&r), Some(E_MULTI_ASSET_NOT_SUPPORTED), "{}", logs(&r));
    assert_eq!(custody(&w), (me, me), "custody unchanged");
    assert!(!read_pool(&w.svm, &w.pool).creator_seed_recorded());
    market_wr(&mut w, off, &1u32.to_le_bytes());
    let r = bind_again(&mut w, true);
    assert!(r.is_ok(), "control: single-asset bind works: {}", logs(&r));
    assert_eq!(read_pool(&w.svm, &w.pool).creator_seed_atoms(), BUDGET);
}

/// M-1b LOW: a stale K/F cohort on asset 0 (hidden loss reservation the wrapper keeps out of
/// withdrawals) makes the v5 bind wait (44) rather than count it as seed. FORGED stale count
/// (2759 / 2767). Clearing it lets the bind succeed.
/// NEGATIVE CONTROL: on 22c6de5 the bind succeeds with the stale cohort present.
#[test]
fn closeout_m1b_stale_kf_cohort_bind_waits_forged() {
    SKIP_BIND.with(|c| c.set(true));
    let w = world("closeout_m1b_stale_kf_cohort_bind_waits_forged");
    SKIP_BIND.with(|c| c.set(false));
    let Some(mut w) = w else { return };
    use percolator_stake::wrapper_layout as wl;
    for off in [wl::ASSET0_STALE_COUNT_LONG_OFF, wl::ASSET0_STALE_COUNT_SHORT_OFF] {
        let d = w.svm.get_account(&w.market).unwrap().data;
        assert_eq!(u64::from_le_bytes(d[off..off + 8].try_into().unwrap()), 0, "PIN");
        market_wr(&mut w, off, &1u64.to_le_bytes());
        let r = bind_again(&mut w, true);
        assert_eq!(custom(&r), Some(E_INSURANCE_READINGS_DIVERGED), "{}", logs(&r));
        assert!(!read_pool(&w.svm, &w.pool).creator_seed_recorded());
        market_wr(&mut w, off, &0u64.to_le_bytes());
    }
    let r = bind_again(&mut w, true);
    assert!(r.is_ok(), "control: {}", logs(&r));
    assert_eq!(read_pool(&w.svm, &w.pool).creator_seed_atoms(), BUDGET);
}

/// Withdraw with the v5 FIRST_LOSS account tail (market, units ledger, wrapper program,
/// system program). `withdraw` above only appends the market, which is the non-v5 shape.
fn withdraw_v5(
    w: &mut World,
    s: &Staker,
    lp: u64,
    pass_tail: bool,
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
    if pass_tail {
        accounts.push(AccountMeta::new(w.market, false));
        accounts.push(AccountMeta::new(
            percolator_stake::state::derive_wrapper_ins_units(&w.wrapper_id, &w.market).0,
            false,
        ));
        accounts.push(AccountMeta::new_readonly(w.wrapper_id, false));
        accounts.push(AccountMeta::new_readonly(system_program::id(), false));
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

/// GH#309 regression: a FIRST_LOSS staker must still be able to withdraw after the bound
/// market has been retired with `AdminCloseSlab` (tag 30).
///
/// Before the fix the v5 branch required a LIVE wrapper market on both of its reads, so
/// every post-close withdrawal reverted — `InvalidAccount` with the slab tail (the
/// tombstone is not a live market) and `NotEnoughAccountKeys` without it, because the v5
/// branch makes the slab mandatory. The staker's whole balance stayed in `pool.vault`
/// with no instruction able to release it. `f9_v5_first_loss_terminal_returns_creator_seed_s1`
/// computes the claim off-chain and never calls Withdraw, so it did not cover this.
///
/// Post-close the deployed leg is already liquid: the wrapper only closes a TERMINAL
/// market, and tag 29 books the recovered insurance into `total_returned`, so
/// `total_pool_value()` is the whole pool value here.
#[test]
fn f9_v5_first_loss_withdraw_succeeds_after_close_slab() {
    RISK_MODE.with(|c| c.set(1));
    let Some(mut w) = world("f9_v5_first_loss_withdraw_succeeds_after_close_slab") else {
        return;
    };
    RISK_MODE.with(|c| c.set(2));
    assert!(read_pool(&w.svm, &w.pool).is_first_loss());

    admin_resolve(&mut w);

    // tag 29, v5 shape (same call as the S1 test above): the creator seed goes back to the
    // creator and the pool's terminal surplus is booked to stakers.
    let units = percolator_stake::state::derive_wrapper_ins_units(&w.wrapper_id, &w.market).0;
    let creator_ata = Pubkey::new_unique();
    let (mint, admin_key) = (w.mint, w.admin.pubkey());
    set_token_account(&mut w.svm, creator_ata, &mint, &admin_key, 0);
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

    // tag 30: retire the market to a tombstone.
    let admin = w.admin.insecure_clone();
    let r = admin_close_slab(&mut w, &admin);
    assert!(r.is_ok(), "AdminCloseSlab: {}", logs(&r));
    if terminal(&w.svm, &w.market) != WrapperTerminal::Closed {
        // the P1 fee-rebook step can need a second call
        let r = admin_close_slab(&mut w, &admin);
        assert!(r.is_ok(), "AdminCloseSlab#2: {}", logs(&r));
    }
    assert_eq!(
        terminal(&w.svm, &w.market),
        WrapperTerminal::Closed,
        "the market is a tombstone"
    );

    let slot = w.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    w.svm.warp_to_slot(slot + 100);

    let alice = w.alice.take().unwrap();
    let lp = token_amount(&w.svm, &alice.lp_ata);
    assert!(lp > 0, "the staker holds LP");
    let before = token_amount(&w.svm, &alice.ata);
    let vault_before = token_amount(&w.svm, &w.vault);

    let r = withdraw_v5(&mut w, &alice, lp, true);
    assert!(
        r.is_ok(),
        "first-loss withdraw after CloseSlab must succeed: {}",
        logs(&r)
    );
    let paid = token_amount(&w.svm, &alice.ata) - before;
    assert!(paid > 0, "the staker was paid");
    assert_eq!(
        token_amount(&w.svm, &w.vault),
        vault_before - paid,
        "the payout came out of pool.vault"
    );
}
