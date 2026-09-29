//! INDEPENDENT SUITE (2026-09-30) — stake F3 dead-share fee booking + first-depositor /
//! donation capture. Written from the fee-flow audit (F3, F5) and the P1 design doc §F3
//! ("Stake AccrueFees refuses when only the 1,000 dead shares exist", error 29
//! NoRealLpHolders), NOT from the fix. Harness plumbing copied from
//! tests/mode0_accrue_fees_e2e.rs at the base e0ace2c.
//!
//! Stake .so under test: env INDEP_STAKE_SO (default target/deploy/percolator_stake.so).
//! Wrapper .so: env INDEP_WRAPPER_SO (default ~/wt-indep/baseline-so/wrapper-v18.2.so,
//! the deployed v18.2 bytes). Negative control = run with the stake .so built from BASE.
#![allow(dead_code, clippy::too_many_arguments)]
use litesvm::LiteSVM;
use percolator_stake::state::{
    derive_deposit_pda, derive_pool_pda, derive_vault_authority, StakePool, MINIMUM_LIQUIDITY,
    STAKE_POOL_SIZE,
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

// ---- Program IDs (mirrors n6_marketauth_rotation_e2e.rs / v16_stake_insurance_e2e.rs) ----
const WRAPPER_MAINNET: &str = "ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv";
const STAKE_ID: &str = "9tbLt8fs1C7cJRXAyiGY7Ub88AT7MLWpxLqFNVCkqzA6";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const MARKET_LEN_V17_CAP1: usize = 3675; // v18.2: 592 + 758 + 1*2325
// 3147 = MARKET_GROUP_OFF(592 = HEADER_LEN 16 + WRAPPER_CONFIG_LEN 576)
//       + MARKET_GROUP_LEN(758) + 1 * MARKET_ASSET_SLOT_LEN(1797).
// Was 3067 when WRAPPER_CONFIG_LEN was 496; the 2026-07-19 fee-split fields grew
// WrapperConfigV16 496 -> 576, so every market fixture in this repo was 80 bytes
// short and EVERY InitMarket here failed with InvalidAccountData. Recompute via
// percolator_prog::state::market_account_len_for_capacity(1) when the wrapper
// config changes again.
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;

// ---- Artifact paths ----

fn stake_so() -> PathBuf {
    if let Some(p) = std::env::var_os("INDEP_STAKE_SO") { return PathBuf::from(p); }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_stake.so");
    p
}

fn wrapper_so() -> PathBuf {
    if let Some(p) = std::env::var_os("INDEP_WRAPPER_SO") { return PathBuf::from(p); }
    let home = std::env::var("HOME").unwrap();
    let b = PathBuf::from(format!("{home}/wt-indep/baseline-so/wrapper-v18.2.so"));
    if b.exists() { return b; }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("percolator-prog/target/deploy/percolator_prog.so");
    p
}

// ---- Wrapper InitMarket (v17) — minimal live market, copied from
// n6_marketauth_rotation_e2e.rs so InitPool's marketauth-rotation CPI has a
// real target. ----

fn mint_data() -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[44] = 0; // decimals
    d[45] = 1; // is_initialized
    d
}

fn encode_init_market_v17() -> Vec<u8> {
    let mut out = Vec::with_capacity(219);
    out.push(0u8); // tag InitMarket
    out.extend_from_slice(&1u16.to_le_bytes()); // max_portfolio_assets
    out.extend_from_slice(&0u64.to_le_bytes()); // h_min
    out.extend_from_slice(&10u64.to_le_bytes()); // h_max
    out.extend_from_slice(&100u64.to_le_bytes()); // initial_price
    out.extend_from_slice(&1u128.to_le_bytes()); // min_nonzero_mm_req
    out.extend_from_slice(&2u128.to_le_bytes()); // min_nonzero_im_req
    out.extend_from_slice(&10_000u64.to_le_bytes()); // maintenance_margin_bps
    out.extend_from_slice(&10_000u64.to_le_bytes()); // initial_margin_bps
    out.extend_from_slice(&10_000u64.to_le_bytes()); // max_trading_fee_bps
    out.extend_from_slice(&0u64.to_le_bytes()); // trade_fee_base_bps
    out.extend_from_slice(&0u64.to_le_bytes()); // liquidation_fee_bps
    out.extend_from_slice(&0u128.to_le_bytes()); // liquidation_fee_cap
    out.extend_from_slice(&0u128.to_le_bytes()); // min_liquidation_abs
    out.extend_from_slice(&10_000u64.to_le_bytes()); // max_price_move_bps_per_slot
    out.extend_from_slice(&1u64.to_le_bytes()); // max_accrual_dt_slots
    out.extend_from_slice(&0u64.to_le_bytes()); // max_abs_funding_e9_per_slot
    out.extend_from_slice(&1u64.to_le_bytes()); // min_funding_lifetime_slots
    out.extend_from_slice(&1u64.to_le_bytes()); // max_account_b_settlement_chunks
    out.extend_from_slice(&1u64.to_le_bytes()); // max_bankrupt_close_chunks
    out.extend_from_slice(&100u64.to_le_bytes()); // max_bankrupt_close_lifetime_slots
    out.extend_from_slice(&MAX_VAULT_TVL.to_le_bytes()); // public_b_chunk_atoms
    out.extend_from_slice(&0u128.to_le_bytes()); // maintenance_fee_per_slot
    debug_assert_eq!(out.len(), 219, "InitMarket wire must be 219 bytes");
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
    let cb_heap =
        solana_sdk::compute_budget::ComputeBudgetInstruction::request_heap_frame(128 * 1024);
    let cb_cu =
        solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let tx = Transaction::new_signed_with_payer(
        &[cb_heap, cb_cu, ix],
        Some(&payer.pubkey()),
        &all,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).map(|_| ())
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

// ---- Stake InitPool (tag 0) — real instruction, mirrors
// n6_marketauth_rotation_e2e.rs's init_pool_ix/setup exactly. ----

fn encode_init_pool(cooldown_slots: u64, deposit_cap: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(17);
    out.push(0u8); // tag InitPool
    out.extend_from_slice(&cooldown_slots.to_le_bytes());
    out.extend_from_slice(&deposit_cap.to_le_bytes());
    out
}

struct InitPoolAccounts {
    admin: Pubkey,
    slab: Pubkey,
    pool_pda: Pubkey,
    lp_mint: Pubkey,
    vault: Pubkey,
    vault_auth: Pubkey,
    collateral_mint: Pubkey,
    percolator_program: Pubkey,
    token_program: Pubkey,
}

fn init_pool_ix(
    stake_id: Pubkey,
    a: &InitPoolAccounts,
    cooldown_slots: u64,
    deposit_cap: u64,
) -> Instruction {
    Instruction {
        program_id: stake_id,
        accounts: vec![
            AccountMeta::new(a.admin, true),
            AccountMeta::new(a.slab, false), // MUST be writable: the marketauth CPI needs it
            AccountMeta::new(a.pool_pda, false),
            AccountMeta::new(a.lp_mint, false),
            AccountMeta::new(a.vault, false),
            AccountMeta::new_readonly(a.vault_auth, false),
            AccountMeta::new_readonly(a.collateral_mint, false),
            AccountMeta::new_readonly(a.percolator_program, false),
            AccountMeta::new_readonly(a.token_program, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
        ],
        data: encode_init_pool(cooldown_slots, deposit_cap),
    }
}

/// Live market + pre-allocated (not yet InitPool'd) lp_mint/vault, ready for InitPool.
/// `InitPool` does NOT set the LP mint's authority; the client's prior CreateAccount +
/// InitializeMint must already have vault_auth as mint authority (mirrors
/// n6_marketauth_rotation_e2e.rs::setup — that file's InitPool test never touches LP
/// mint authority either, because process_init_pool's initialize_mint CPI does it).
fn setup(
    svm: &mut LiteSVM,
    wrapper_id: Pubkey,
    stake_id: Pubkey,
    token_program: Pubkey,
    admin: &Keypair,
    payer: &Keypair,
) -> (Pubkey, InitPoolAccounts) {
    let (market, mint) = build_live_market_v17(svm, wrapper_id, token_program, admin, payer);

    let (pool_pda, _) = derive_pool_pda(&stake_id, &market);
    let (vault_auth, _) = derive_vault_authority(&stake_id, &pool_pda);
    let lp_mint = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    preallocate_empty_spl_account(svm, lp_mint, token_program, 82);
    preallocate_empty_spl_account(svm, vault, token_program, 165);

    let accts = InitPoolAccounts {
        admin: admin.pubkey(),
        slab: market,
        pool_pda,
        lp_mint,
        vault,
        vault_auth,
        collateral_mint: mint,
        percolator_program: wrapper_id,
        token_program,
    };
    (market, accts)
}

// ---- Stake Deposit (tag 1) — real instruction, mirrors
// regression_166_pda_squat.rs::deposit_ix exactly (processor.rs:687-703 account order). ----

fn token_data(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1; // state = Initialized
    d
}

fn set_token_account(svm: &mut LiteSVM, key: Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) {
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    svm.set_account(
        key,
        Account {
            lamports: 2_039_280, // rent-exempt for 165 bytes
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

fn deposit_ix(
    stake_id: Pubkey,
    user: &Pubkey,
    pool_pda: Pubkey,
    user_ata: Pubkey,
    vault: Pubkey,
    lp_mint: Pubkey,
    user_lp_ata: Pubkey,
    vault_auth: Pubkey,
    deposit_pda: Pubkey,
    amount: u64,
    slab: Pubkey,
) -> Instruction {
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    let mut data = vec![1u8]; // tag = Deposit
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: stake_id,
        accounts: vec![
            AccountMeta::new(*user, true),
            AccountMeta::new(pool_pda, false),
            AccountMeta::new(user_ata, false),
            AccountMeta::new(vault, false),
            AccountMeta::new(lp_mint, false),
            AccountMeta::new(user_lp_ata, false),
            AccountMeta::new_readonly(vault_auth, false),
            AccountMeta::new(deposit_pda, false),
            AccountMeta::new_readonly(token_program, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(slab, false), // 11. wrapper market (#290)
        ],
        data,
    }
}

// ---- Stake AccrueFees (tag 12) — real instruction. Accounts per
// instruction.rs:299-306 / processor.rs:2543-2551. ----

fn accrue_fees_ix(
    stake_id: Pubkey,
    caller: &Pubkey,
    pool_pda: Pubkey,
    vault: Pubkey,
    slab: Pubkey,
) -> Instruction {
    Instruction {
        program_id: stake_id,
        accounts: vec![
            AccountMeta::new_readonly(*caller, true), // 0. caller [signer, permissionless]
            AccountMeta::new(pool_pda, false),        // 1. pool PDA [writable]
            AccountMeta::new_readonly(vault, false),  // 2. vault [readonly, balance only]
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false), // 3. clock
            AccountMeta::new_readonly(slab, false),   // 4. wrapper market (#290)
        ],
        data: vec![12u8], // tag = AccrueFees
    }
}

/// #290: simulate the wrapper's tag-87 `WithdrawInsuranceReserveToStake` bookkeeping
/// on the REAL wrapper-initialized market account: advance
/// `insurance_reserve_withdrawn_atoms` (account bytes [560..576), u128 LE) by
/// `amount`, exactly as the wrapper does at the transfer site. Callers move the
/// matching tokens into the vault themselves.
fn advance_wrapper_fee_counter(svm: &mut LiteSVM, market: &Pubkey, amount: u64) {
    let mut acct = svm.get_account(market).expect("market exists");
    let off = percolator_stake::state::WRAPPER_OFF_INSURANCE_RESERVE_WITHDRAWN;
    let cur = u128::from_le_bytes(acct.data[off..off + 16].try_into().unwrap());
    acct.data[off..off + 16].copy_from_slice(&(cur + amount as u128).to_le_bytes());
    svm.set_account(*market, acct).unwrap();
}

fn read_pool(svm: &LiteSVM, pool_pda: &Pubkey) -> StakePool {
    let data = svm.get_account(pool_pda).unwrap().data;
    *bytemuck::from_bytes::<StakePool>(&data[..STAKE_POOL_SIZE])
}


fn withdraw_ix(
    stake_id: Pubkey,
    user: &Pubkey,
    a: &InitPoolAccounts,
    user_lp_ata: Pubkey,
    user_ata: Pubkey,
    deposit_pda: Pubkey,
    lp_amount: u64,
) -> Instruction {
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    let mut data = vec![2u8];
    data.extend_from_slice(&lp_amount.to_le_bytes());
    Instruction {
        program_id: stake_id,
        accounts: vec![
            AccountMeta::new(*user, true),
            AccountMeta::new(a.pool_pda, false),
            AccountMeta::new(user_lp_ata, false),
            AccountMeta::new(a.lp_mint, false),
            AccountMeta::new(a.vault, false),
            AccountMeta::new(user_ata, false),
            AccountMeta::new_readonly(a.vault_auth, false),
            AccountMeta::new(deposit_pda, false),
            AccountMeta::new_readonly(token_program, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
            AccountMeta::new_readonly(a.slab, false),
        ],
        data,
    }
}

struct World {
    svm: LiteSVM,
    stake_id: Pubkey,
    payer: Keypair,
    a: InitPoolAccounts,
}

struct Staker {
    kp: Keypair,
    ata: Pubkey,
    lp_ata: Pubkey,
    dep_pda: Pubkey,
}

fn custom(e: &litesvm::types::FailedTransactionMetadata) -> Option<u32> {
    match &e.err {
        solana_sdk::transaction::TransactionError::InstructionError(
            _,
            solana_sdk::instruction::InstructionError::Custom(c),
        ) => Some(*c),
        _ => None,
    }
}

impl World {
    fn new() -> Self {
        let (so, wso) = (stake_so(), wrapper_so());
        assert!(so.exists() && wso.exists(), "missing .so: stake={} wrapper={}", so.display(), wso.display());
        let mut svm = LiteSVM::new().with_spl_programs();
        let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
        let wrapper_id = Pubkey::from_str(WRAPPER_MAINNET).unwrap();
        let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        svm.add_program_from_file(stake_id, so).unwrap();
        svm.add_program_from_file(wrapper_id, wso).unwrap();
        let admin = Keypair::new();
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
        svm.airdrop(&admin.pubkey(), 20_000_000_000).unwrap();
        let (_m, a) = setup(&mut svm, wrapper_id, stake_id, token_program, &admin, &payer);
        // cooldown 0 so withdrawals are immediate (cooldown is orthogonal to F3)
        send(&mut svm, &payer, &[&admin], init_pool_ix(stake_id, &a, 1, 0))
            .unwrap_or_else(|e| panic!("InitPool: {}", e.meta.logs.join("\n")));
        World { svm, stake_id, payer, a }
    }
    fn staker(&mut self, funds: u64) -> Staker {
        let kp = Keypair::new();
        self.svm.airdrop(&kp.pubkey(), 10_000_000_000).unwrap();
        let ata = Pubkey::new_unique();
        set_token_account(&mut self.svm, ata, &self.a.collateral_mint, &kp.pubkey(), funds);
        let lp_ata = Pubkey::new_unique();
        set_token_account(&mut self.svm, lp_ata, &self.a.lp_mint, &kp.pubkey(), 0);
        let (dep_pda, _) = derive_deposit_pda(&self.stake_id, &self.a.pool_pda, &kp.pubkey());
        Staker { kp, ata, lp_ata, dep_pda }
    }
    fn deposit(&mut self, s: &Staker, amt: u64) -> Result<(), litesvm::types::FailedTransactionMetadata> {
        self.svm.expire_blockhash();
        let ix = deposit_ix(self.stake_id, &s.kp.pubkey(), self.a.pool_pda, s.ata, self.a.vault, self.a.lp_mint, s.lp_ata, self.a.vault_auth, s.dep_pda, amt, self.a.slab);
        let p = self.payer.insecure_clone();
        send(&mut self.svm, &p, &[&s.kp], ix)
    }
    fn withdraw(&mut self, s: &Staker, lp: u64) -> Result<(), litesvm::types::FailedTransactionMetadata> {
        let mut clk = self.svm.get_sysvar::<solana_sdk::clock::Clock>();
        clk.slot += 10;
        self.svm.set_sysvar(&clk);
        self.svm.expire_blockhash();
        let ix = withdraw_ix(self.stake_id, &s.kp.pubkey(), &self.a, s.lp_ata, s.ata, s.dep_pda, lp);
        let p = self.payer.insecure_clone();
        send(&mut self.svm, &p, &[&s.kp], ix)
    }
    fn accrue(&mut self) -> Result<(), litesvm::types::FailedTransactionMetadata> {
        self.svm.expire_blockhash();
        let c = Keypair::new();
        self.svm.airdrop(&c.pubkey(), 1_000_000_000).unwrap();
        let ix = accrue_fees_ix(self.stake_id, &c.pubkey(), self.a.pool_pda, self.a.vault, self.a.slab);
        let p = self.payer.insecure_clone();
        send(&mut self.svm, &p, &[&c], ix)
    }
    /// Model a real tag-87 push: tokens land in the pool vault AND the wrapper's
    /// insurance_reserve_withdrawn counter advances by the same amount.
    fn push87(&mut self, amt: u64) {
        let v = token_amount(&self.svm, &self.a.vault);
        set_token_account(&mut self.svm, self.a.vault, &self.a.collateral_mint, &self.a.vault_auth, v + amt);
        advance_wrapper_fee_counter(&mut self.svm, &self.a.slab, amt);
    }
    /// A raw donation: tokens only, no wrapper counter movement.
    fn donate(&mut self, amt: u64) {
        let v = token_amount(&self.svm, &self.a.vault);
        set_token_account(&mut self.svm, self.a.vault, &self.a.collateral_mint, &self.a.vault_auth, v + amt);
    }
    fn pool(&self) -> StakePool { read_pool(&self.svm, &self.a.pool_pda) }
    fn tok(&self, k: &Pubkey) -> u64 { token_amount(&self.svm, k) }
    /// Genesis staker deposits then fully exits, leaving ONLY the 1,000 dead shares.
    fn drain_to_dead_shares(&mut self) {
        let g = self.staker(10_000);
        self.deposit(&g, 5_000).unwrap_or_else(|e| panic!("genesis deposit: {}", e.meta.logs.join("\n")));
        let lp = self.tok(&g.lp_ata);
        assert_eq!(lp, 5_000 - MINIMUM_LIQUIDITY, "genesis mints amount - MINIMUM_LIQUIDITY");
        self.withdraw(&g, lp).unwrap_or_else(|e| panic!("genesis full exit: {}", e.meta.logs.join("\n")));
        assert_eq!(self.pool().total_lp_supply, MINIMUM_LIQUIDITY, "vacuity: pool must hold exactly the dead shares");
    }
}

/// F3 (1): only dead shares exist -> AccrueFees must refuse with 29 and book nothing.
#[test]
fn indep_f3_accrue_with_only_dead_shares_refuses_29_and_books_nothing() {
    let mut w = World::new();
    w.drain_to_dead_shares();
    let before = w.pool();
    w.push87(1_224_232); // PENGU's stranded leg from the fee-flow audit
    let r = w.accrue();
    let after = w.pool();
    assert_eq!(after.total_fees_earned, before.total_fees_earned,
        "F3: fees must NOT be booked to the 1,000 dead shares (booked {})",
        after.total_fees_earned - before.total_fees_earned);
    match r {
        Err(e) => assert_eq!(custom(&e), Some(29), "refusal must be NoRealLpHolders(29); logs:\n{}", e.meta.logs.join("\n")),
        Ok(()) => panic!("F3: AccrueFees succeeded on a dead-shares-only pool (design: refuse with 29)"),
    }
}

/// F3 (2): boundary — 1,000 dead + 1 real share books; the booked fees are reachable.
#[test]
fn indep_f3_one_real_share_above_floor_books_fees() {
    let mut w = World::new();
    w.drain_to_dead_shares();
    let s = w.staker(10_000);
    // at supply 1000 / value >= 1000 a 1-atom deposit may round to 0 shares; find the
    // smallest deposit that mints >= 1 share.
    let mut minted = 0;
    for amt in 1..=10u64 {
        if w.deposit(&s, amt).is_ok() { minted = w.tok(&s.lp_ata); if minted > 0 { break; } }
    }
    assert!(minted >= 1, "could not mint a single real share");
    assert_eq!(w.pool().total_lp_supply, MINIMUM_LIQUIDITY + minted);
    let before = w.pool().total_fees_earned;
    w.push87(10_000);
    w.accrue().unwrap_or_else(|e| panic!("AccrueFees with a real share must succeed: {}", e.meta.logs.join("\n")));
    assert_eq!(w.pool().total_fees_earned - before, 10_000, "real staker present -> push books in full");
}

/// F3 (3): fees pushed while only dead shares exist are NOT stranded on the dead shares,
/// and the donation/backlog capture by the NEXT depositor is measured.
/// Design (fee-flow F3): "Those atoms are permanently unredeemable" is the bug. We assert
/// the pushed atoms remain claimable by *someone* (not locked forever) and record who.
#[test]
fn indep_f3_backlog_not_stranded_and_next_depositor_capture_is_measured() {
    let mut w = World::new();
    w.drain_to_dead_shares();
    const F: u64 = 1_000_000;
    w.push87(F);
    let _ = w.accrue(); // base: books to dead shares; fix: refuses
    // Next real depositor arrives, then the keeper accrues.
    let s = w.staker(10_000_000);
    const D: u64 = 1_000_000;
    w.deposit(&s, D).unwrap_or_else(|e| panic!("deposit: {}", e.meta.logs.join("\n")));
    let _ = w.accrue();
    let lp = w.tok(&s.lp_ata);
    let before = w.tok(&s.ata);
    w.withdraw(&s, lp).unwrap_or_else(|e| panic!("withdraw: {}", e.meta.logs.join("\n")));
    let got = w.tok(&s.ata) - before;
    let gain = got as i128 - D as i128;
    eprintln!("F3-capture: pushed {F} while dead-only; depositor D={D} redeemed {got} (gain {gain}); vault left {}", w.tok(&w.a.vault));
    // Not stranded: the next staker must be able to realise (nearly) all of F — on the
    // buggy base the dead shares own it and the depositor gains ~0 (bought in at the
    // inflated price).
    assert!(gain >= (F as i128) * 9 / 10,
        "F3: backlog fees stranded on dead shares — depositor gained {gain} of {F}");
}

/// Donation (no wrapper counter) before the first deposit must not be booked as fees and
/// must not dilute or brick the first/second depositor (#290 attribution; N7 inflation).
#[test]
fn indep_stake_donation_before_first_deposit_is_not_capturable() {
    let mut w = World::new();
    w.donate(5_000_000);
    let a = w.staker(10_000_000);
    w.deposit(&a, 2_000_000).unwrap_or_else(|e| panic!("first deposit after donation must work: {}", e.meta.logs.join("\n")));
    let _ = w.accrue();
    assert_eq!(w.pool().total_fees_earned, 0, "a raw donation is not attributable fee revenue");
    let b = w.staker(10_000_000);
    w.deposit(&b, 2_000_000).unwrap();
    let lpa = w.tok(&a.lp_ata);
    let lpb = w.tok(&b.lp_ata);
    // b must receive ~ the same shares per atom as a (not diluted by the donation)
    assert!(lpb + MINIMUM_LIQUIDITY >= lpa, "second depositor diluted: a={lpa} b={lpb}");
    let b0 = w.tok(&b.ata);
    w.withdraw(&b, lpb).unwrap();
    let out = w.tok(&b.ata) - b0;
    assert!(out <= 2_000_000 && out + 2 >= 2_000_000, "b must redeem ~its deposit, got {out}");
}
