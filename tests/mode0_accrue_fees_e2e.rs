//! Task 11 — mode-0 insurance pools accrue fees.
//!
//! Before this change, `AccrueFees` (tag 12) was gated to `pool_mode == 1`
//! (`processor.rs::process_accrue_fees`) and `total_pool_value()` only folded
//! `total_fees_earned` in for mode 1 (`state.rs::total_pool_value`). Every real
//! client calls `InitPool`, which hardcodes `pool_mode = 0` — so fee accrual was
//! reachable in the source but UNREACHABLE by any real pool. Mode-0 stakers had
//! a downside leg (`FlushToInsurance`) and no upside leg at all.
//!
//! This test loads the REAL stake .so + REAL v17 wrapper .so into one LiteSVM
//! instance (mirroring `n6_marketauth_rotation_e2e.rs`) and drives the actual
//! instruction dispatcher for the full lifecycle: InitMarket (wrapper) ->
//! InitPool (stake, mode 0 by construction, CPIs the wrapper to rotate
//! marketauth) -> Deposit (real, genesis deposit) -> [inject a vault surplus,
//! the one explicitly-authorized forgery — see task-11-brief.md step 3] ->
//! AccrueFees (real). We assert on the REAL post-instruction pool state read
//! back out of LiteSVM, not on anything we set by hand.
//!
//! Because this exercises `target/deploy/percolator_stake.so`, rebuild the SBF
//! artifact with `cargo build-sbf --no-default-features` after changing source
//! code; otherwise a stale artifact silently tests old behavior.

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
const MARKET_LEN_V17_CAP1: usize = 3067; // dump_sizes MARKET_ACCOUNT_LEN as of percolator-prog HEAD (1d4594a5)
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;

// ---- Artifact paths ----

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

fn preallocate_empty_spl_account(svm: &mut LiteSVM, key: Pubkey, token_program: Pubkey, size: usize) {
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

fn init_pool_ix(stake_id: Pubkey, a: &InitPoolAccounts, cooldown_slots: u64, deposit_cap: u64) -> Instruction {
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
        ],
        data,
    }
}

// ---- Stake AccrueFees (tag 12) — real instruction. Accounts per
// instruction.rs:299-306 / processor.rs:2543-2551. ----

fn accrue_fees_ix(stake_id: Pubkey, caller: &Pubkey, pool_pda: Pubkey, vault: Pubkey) -> Instruction {
    Instruction {
        program_id: stake_id,
        accounts: vec![
            AccountMeta::new_readonly(*caller, true), // 0. caller [signer, permissionless]
            AccountMeta::new(pool_pda, false),         // 1. pool PDA [writable]
            AccountMeta::new_readonly(vault, false),   // 2. vault [readonly, balance only]
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false), // 3. clock
        ],
        data: vec![12u8], // tag = AccrueFees
    }
}

fn read_pool(svm: &LiteSVM, pool_pda: &Pubkey) -> StakePool {
    let data = svm.get_account(pool_pda).unwrap().data;
    *bytemuck::from_bytes::<StakePool>(&data[..STAKE_POOL_SIZE])
}

/// End-to-end: InitPool (mode 0 by construction) -> Deposit (genesis) -> a vault
/// surplus lands in the vault (the ONLY forged state in this test, per
/// task-11-brief.md step 3 / the task's explicit permission) -> the REAL,
/// permissionless AccrueFees instruction. Asserts on real post-instruction state:
/// `total_fees_earned` grows by EXACTLY the surplus, and `total_pool_value()`
/// (computed by the crate's own method on the state read back from LiteSVM) grows
/// by the same amount.
#[test]
fn mode0_pool_accrues_fees_via_real_accrue_fees_instruction() {
    let so = stake_so();
    let wso = wrapper_so();
    if !so.exists() || !wso.exists() {
        eprintln!(
            "SKIP mode0_pool_accrues_fees_via_real_accrue_fees_instruction: .so missing \
             (stake={} wrapper={}) -- run `cargo build-sbf --no-default-features` in \
             percolator-stake and percolator-prog first",
            so.display(),
            wso.display()
        );
        return;
    }

    let mut svm = LiteSVM::new().with_spl_programs();
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
    let wrapper_id = Pubkey::from_str(WRAPPER_MAINNET).unwrap();
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    svm.add_program_from_file(stake_id, so).unwrap();
    svm.add_program_from_file(wrapper_id, wso).unwrap();

    let admin = Keypair::new();
    let user = Keypair::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.airdrop(&admin.pubkey(), 20_000_000_000).unwrap();
    svm.airdrop(&user.pubkey(), 20_000_000_000).unwrap();

    // ---- InitPool (real instruction; pool_mode = 0 is InitPool's hardcoded
    // default -- see processor.rs:672. This is the path EVERY real client uses. ----
    let (_market, accts) = setup(&mut svm, wrapper_id, stake_id, token_program, &admin, &payer);
    send(&mut svm, &payer, &[&admin], init_pool_ix(stake_id, &accts, 5, 0))
        .unwrap_or_else(|e| panic!("InitPool must succeed.\nLogs:\n{}", e.meta.logs.join("\n")));

    let pool_before_deposit = read_pool(&svm, &accts.pool_pda);
    assert_eq!(pool_before_deposit.pool_mode, 0, "InitPool must produce a mode-0 pool");
    assert_eq!(pool_before_deposit.total_fees_earned, 0, "genesis pool has no fees yet");

    // ---- Deposit (real instruction; genesis deposit, so LP = amount - MINIMUM_LIQUIDITY). ----
    let user_ata = Pubkey::new_unique();
    set_token_account(&mut svm, user_ata, &accts.collateral_mint, &user.pubkey(), 10_000);
    let user_lp_ata = Pubkey::new_unique();
    set_token_account(&mut svm, user_lp_ata, &accts.lp_mint, &user.pubkey(), 0);
    let (deposit_pda, _) = derive_deposit_pda(&stake_id, &accts.pool_pda, &user.pubkey());

    let deposit_amount: u64 = 2_000;
    assert!(deposit_amount > MINIMUM_LIQUIDITY, "must clear the N7 dead-share floor");
    let dep_ix = deposit_ix(
        stake_id,
        &user.pubkey(),
        accts.pool_pda,
        user_ata,
        accts.vault,
        accts.lp_mint,
        user_lp_ata,
        accts.vault_auth,
        deposit_pda,
        deposit_amount,
    );
    send(&mut svm, &payer, &[&user], dep_ix)
        .unwrap_or_else(|e| panic!("Deposit must succeed.\nLogs:\n{}", e.meta.logs.join("\n")));

    let pool_before_accrue = read_pool(&svm, &accts.pool_pda);
    assert_eq!(pool_before_accrue.pool_mode, 0, "pool_mode is immutable after InitPool");
    assert_eq!(
        token_amount(&svm, &accts.vault),
        deposit_amount,
        "vault must hold exactly the real deposit before any surplus is added"
    );
    let pool_value_before = pool_before_accrue
        .total_pool_value()
        .expect("pool value must be computable pre-accrual");
    assert_eq!(pool_value_before, deposit_amount, "pre-accrual: tpv == the real deposit, no fees yet");

    // ---- The ONE authorized forgery (task-11-brief.md step 3 / task instructions'
    // "Explicit permission" section): set the vault's token balance directly to
    // simulate the wrapper pushing the insurance leg of the trade-fee split into
    // this mode-0 pool's vault. Everything else in this test is real instruction
    // execution; nothing about pool state, deposits, or total_fees_earned is forged. ----
    let surplus: u64 = 4_242;
    set_token_account(
        &mut svm,
        accts.vault,
        &accts.collateral_mint,
        &accts.vault_auth,
        deposit_amount + surplus,
    );

    // ---- AccrueFees (real, permissionless instruction; caller is an unrelated
    // third party to prove permissionlessness). Pre-fix this reverted with
    // InvalidPoolMode for a mode-0 pool; post-fix it must succeed. ----
    let cranker = Keypair::new();
    svm.airdrop(&cranker.pubkey(), 10_000_000_000).unwrap();
    let acc_ix = accrue_fees_ix(stake_id, &cranker.pubkey(), accts.pool_pda, accts.vault);
    send(&mut svm, &payer, &[&cranker], acc_ix).unwrap_or_else(|e| {
        panic!(
            "AccrueFees must succeed on a mode-0 pool after Task 11's mode-gate relax.\nLogs:\n{}",
            e.meta.logs.join("\n")
        )
    });

    // ---- Assertions on the REAL post-instruction state. ----
    let pool_after = read_pool(&svm, &accts.pool_pda);
    assert_eq!(pool_after.pool_mode, 0, "AccrueFees must not mutate pool_mode");
    assert_eq!(
        pool_after.total_fees_earned, surplus,
        "total_fees_earned must grow by EXACTLY the vault surplus"
    );
    let pool_value_after = pool_after
        .total_pool_value()
        .expect("pool value must be computable post-accrual");
    assert_eq!(
        pool_value_after,
        pool_value_before + surplus,
        "total_pool_value() must grow by EXACTLY the surplus for a mode-0 pool"
    );
    assert_eq!(
        pool_after.total_deposited, deposit_amount,
        "sanity: total_deposited untouched by AccrueFees (fees are a separate field)"
    );
}
