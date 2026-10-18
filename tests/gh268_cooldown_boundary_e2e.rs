//! GH#268 (PSTAKE-COOLDOWN-BOUNDARY-001): the Withdraw cooldown is EXCLUSIVE at the boundary.
//!
//! The documented and unit-tested rule (`tests/integration.rs::test_cooldown_boundary_is_exclusive`)
//! is `current_slot > last_deposit_slot + cooldown_slots`. `process_withdraw` used `<`, so a
//! withdrawal at exactly `last_deposit_slot + cooldown_slots` passed and every configured
//! cooldown was one slot short at the edge.
//!
//! Real stake .so + real wrapper .so under LiteSVM, same harness as
//! `f3_dead_share_accrue_guard_e2e.rs` (FIRST_LOSS pool, real InitPool / Deposit / Withdraw).
//! Rebuild `target/deploy/percolator_stake.so` after changing source, or these tests exercise
//! stale bytes.

#![allow(clippy::result_large_err, clippy::too_many_arguments)]

use litesvm::LiteSVM;
use percolator_stake::state::{
    derive_deposit_pda, derive_pool_pda, derive_vault_authority, StakeDeposit, StakePool,
    MINIMUM_LIQUIDITY, STAKE_DEPOSIT_SIZE, STAKE_POOL_SIZE,
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
// v18 wrapper market account length for capacity 1. The deployed v18.2 wrapper
// (deploy/v18.2-wrapper@6377376a, sha256 4472b383...) rejects the older v17 length
// 3147 at InitMarket with InvalidAccountData; 3675 is what it accepts. The #290
// counter (`insurance_reserve_withdrawn_atoms`, bytes [560..576)) is unchanged.
// Run these suites against a v18 wrapper .so: the v17-era CI pin (15eb8b0c) rejects
// the v18 InitPool marketauth CPI wire with InvalidInstructionData.
// v2.2 (wrapper VERSION 19): 592 + 806 + 2437 = 3835 (3675 on v2.1).
const MARKET_LEN_V18_CAP1: usize = 4059;
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
            data: vec![0u8; MARKET_LEN_V18_CAP1],
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
    let wrapper_id = Pubkey::from_str(WRAPPER_MAINNET).unwrap();
    let mut data = vec![1u8]; // tag = Deposit
    data.extend_from_slice(&amount.to_le_bytes());
    // v5: the 16-byte InitPool creates a FIRST_LOSS pool -> signed consent byte + the
    // wrapper's InsuranceUnitsV20 (refreshed by CPI) + the wrapper program.
    data.extend_from_slice(&percolator_stake::state::deposit_consent_bytes(
        percolator_stake::state::DEPLOY_TARGET_DEFAULT_BPS,
        percolator_stake::state::LIQUID_BUFFER_DEFAULT_BPS,
        percolator_stake::state::HYSTERESIS_DEFAULT_BPS,
    ));
    let units = percolator_stake::state::derive_wrapper_ins_units(&wrapper_id, &slab).0;
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
            AccountMeta::new(slab, false), // 11. wrapper market (#290; v5: writable)
            AccountMeta::new(units, false), // 12. v5 InsuranceUnitsV20
            AccountMeta::new_readonly(wrapper_id, false), // 13. v5 wrapper program
        ],
        data,
    }
}

fn read_pool(svm: &LiteSVM, pool_pda: &Pubkey) -> StakePool {
    let data = svm.get_account(pool_pda).unwrap().data;
    *bytemuck::from_bytes::<StakePool>(&data[..STAKE_POOL_SIZE])
}

// ---- Withdraw (tag 2) ----

fn withdraw_ix(
    stake_id: Pubkey,
    user: &Pubkey,
    a: &InitPoolAccounts,
    user_ata: Pubkey,
    user_lp_ata: Pubkey,
    lp_amount: u64,
) -> Instruction {
    let (deposit_pda, _) = derive_deposit_pda(&stake_id, &a.pool_pda, user);
    let mut data = vec![2u8]; // tag = Withdraw
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
            AccountMeta::new_readonly(a.token_program, false),
            AccountMeta::new_readonly(solana_sdk::sysvar::clock::id(), false),
            AccountMeta::new(a.slab, false), // 10. wrapper market (#290; v5: required, writable)
            AccountMeta::new(
                percolator_stake::state::derive_wrapper_ins_units(
                    &Pubkey::from_str(WRAPPER_MAINNET).unwrap(),
                    &a.slab,
                )
                .0,
                false,
            ), // 11. v5 InsuranceUnitsV20
            AccountMeta::new_readonly(Pubkey::from_str(WRAPPER_MAINNET).unwrap(), false), // 12.
            AccountMeta::new_readonly(system_program::id(), false), // 13.
        ],
        data,
    }
}

struct World {
    svm: LiteSVM,
    stake_id: Pubkey,
    payer: Keypair,
    accts: InitPoolAccounts,
}


/// Real InitPool (16-byte wire: a FIRST_LOSS pool) with `cooldown_slots`, ready for deposits.
/// Panics if either .so is missing (a hard failure, never a skip: GH#311 S-3).
fn world(test_name: &str, cooldown_slots: u64) -> World {
    let so = stake_so();
    let wso = wrapper_so();
    if !so.exists() || !wso.exists() {
        panic!(
            "MISSING ARTIFACT (a hard failure, never a skip: GH#311 S-3) {test_name}: .so missing (stake={} wrapper={})",
            so.display(),
            wso.display()
        );
    }
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
    let (_market, accts) = setup(
        &mut svm,
        wrapper_id,
        stake_id,
        token_program,
        &admin,
        &payer,
    );
    send(
        &mut svm,
        &payer,
        &[&admin],
        init_pool_ix(stake_id, &accts, cooldown_slots, 0),
    )
    .unwrap_or_else(|e| panic!("InitPool.\nLogs:\n{}", e.meta.logs.join("\n")));
    assert_eq!(
        read_pool(&svm, &accts.pool_pda).cooldown_slots,
        cooldown_slots
    );
    World {
        svm,
        stake_id,
        payer,
        accts,
    }
}

struct Staker {
    kp: Keypair,
    ata: Pubkey,
    lp_ata: Pubkey,
}

fn deposit(w: &mut World, amount: u64) -> Staker {
    let kp = Keypair::new();
    w.svm.airdrop(&kp.pubkey(), 10_000_000_000).unwrap();
    let ata = Pubkey::new_unique();
    set_token_account(
        &mut w.svm,
        ata,
        &w.accts.collateral_mint,
        &kp.pubkey(),
        amount,
    );
    let lp_ata = Pubkey::new_unique();
    set_token_account(&mut w.svm, lp_ata, &w.accts.lp_mint, &kp.pubkey(), 0);
    let (deposit_pda, _) = derive_deposit_pda(&w.stake_id, &w.accts.pool_pda, &kp.pubkey());
    let ix = deposit_ix(
        w.stake_id,
        &kp.pubkey(),
        w.accts.pool_pda,
        ata,
        w.accts.vault,
        w.accts.lp_mint,
        lp_ata,
        w.accts.vault_auth,
        deposit_pda,
        amount,
        w.accts.slab,
    );
    send(&mut w.svm, &w.payer, &[&kp], ix)
        .unwrap_or_else(|e| panic!("Deposit.\nLogs:\n{}", e.meta.logs.join("\n")));
    Staker { kp, ata, lp_ata }
}

/// `last_deposit_slot` from the staker's real deposit PDA.
fn last_deposit_slot(w: &World, s: &Staker) -> u64 {
    let (deposit_pda, _) = derive_deposit_pda(&w.stake_id, &w.accts.pool_pda, &s.kp.pubkey());
    let data = w.svm.get_account(&deposit_pda).unwrap().data;
    bytemuck::from_bytes::<StakeDeposit>(&data[..STAKE_DEPOSIT_SIZE]).last_deposit_slot
}

fn try_withdraw(
    w: &mut World,
    s: &Staker,
    lp: u64,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let ix = withdraw_ix(w.stake_id, &s.kp.pubkey(), &w.accts, s.ata, s.lp_ata, lp);
    // A fresh blockhash so a retried identical Withdraw is not deduped.
    w.svm.expire_blockhash();
    send(&mut w.svm, &w.payer, &[&s.kp], ix)
}

fn warp_to(w: &mut World, slot: u64) {
    w.svm.warp_to_slot(slot);
    assert_eq!(w.svm.get_sysvar::<solana_sdk::clock::Clock>().slot, slot);
}

const COOLDOWN_NOT_ELAPSED: u32 = 3;

fn assert_cooldown_refusal(r: Result<(), litesvm::types::FailedTransactionMetadata>, what: &str) {
    let err = r.expect_err(what);
    match err.err {
        solana_sdk::transaction::TransactionError::InstructionError(
            _,
            solana_sdk::instruction::InstructionError::Custom(code),
        ) => assert_eq!(code, COOLDOWN_NOT_ELAPSED, "{what}: must be CooldownNotElapsed (3)"),
        other => panic!("{what}: expected Custom(3) CooldownNotElapsed, got {other:?}"),
    }
}

/// GH#268: at exactly `last_deposit_slot + cooldown_slots` the Withdraw is REFUSED with
/// CooldownNotElapsed and nothing moves; one slot later the same Withdraw pays out.
///
/// Pre-fix (`clock.slot < boundary`): the boundary-slot Withdraw succeeds.
#[test]
fn gh268_withdraw_at_the_exact_cooldown_boundary_is_refused() {
    assert_eq!(
        percolator_stake::error::StakeError::CooldownNotElapsed as u32,
        COOLDOWN_NOT_ELAPSED
    );
    for cooldown in [1u64, 5, 100] {
        let mut w = world(
            "gh268_withdraw_at_the_exact_cooldown_boundary_is_refused",
            cooldown,
        );
        let s = deposit(&mut w, 2_000);
        let lp = token_amount(&w.svm, &s.lp_ata);
        assert_eq!(lp, 2_000 - MINIMUM_LIQUIDITY);
        let boundary = last_deposit_slot(&w, &s) + cooldown;

        // Inside the cooldown and AT the boundary: refused, nothing moves.
        for slot in [boundary - 1, boundary] {
            warp_to(&mut w, slot);
            let vault_before = token_amount(&w.svm, &w.accts.vault);
            assert_cooldown_refusal(
                try_withdraw(&mut w, &s, lp),
                &format!("cooldown {cooldown}: Withdraw at slot {slot} (boundary {boundary})"),
            );
            assert_eq!(token_amount(&w.svm, &s.lp_ata), lp, "no LP burned");
            assert_eq!(token_amount(&w.svm, &w.accts.vault), vault_before);
            assert_eq!(token_amount(&w.svm, &s.ata), 0, "nothing paid");
        }

        // First slot strictly past the boundary: the same Withdraw pays out.
        warp_to(&mut w, boundary + 1);
        try_withdraw(&mut w, &s, lp).unwrap_or_else(|e| {
            panic!(
                "cooldown {cooldown}: Withdraw at boundary + 1 must succeed.\nLogs:\n{}",
                e.meta.logs.join("\n")
            )
        });
        assert_eq!(token_amount(&w.svm, &s.lp_ata), 0);
        assert!(token_amount(&w.svm, &s.ata) > 0, "paid out after the cooldown");
    }
}

/// A re-deposit restarts the cooldown for ALL of the staker's LP (processor.rs, "restarting
/// the cooldown clock"), and the restarted window is exclusive at its boundary too.
#[test]
fn gh268_redeposit_restarts_an_exclusive_cooldown() {
    let cooldown = 10u64;
    let mut w = world("gh268_redeposit_restarts_an_exclusive_cooldown", cooldown);
    let s = deposit(&mut w, 2_000);
    let first = last_deposit_slot(&w, &s);
    warp_to(&mut w, first + 7);
    // Top up from the same staker: fund the ATA and deposit again.
    let collateral_mint = w.accts.collateral_mint;
    let owner = s.kp.pubkey();
    set_token_account(&mut w.svm, s.ata, &collateral_mint, &owner, 500);
    let (deposit_pda, _) = derive_deposit_pda(&w.stake_id, &w.accts.pool_pda, &owner);
    let ix = deposit_ix(
        w.stake_id,
        &owner,
        w.accts.pool_pda,
        s.ata,
        w.accts.vault,
        w.accts.lp_mint,
        s.lp_ata,
        w.accts.vault_auth,
        deposit_pda,
        500,
        w.accts.slab,
    );
    w.svm.expire_blockhash();
    send(&mut w.svm, &w.payer, &[&s.kp], ix)
        .unwrap_or_else(|e| panic!("re-Deposit.\nLogs:\n{}", e.meta.logs.join("\n")));
    let second = last_deposit_slot(&w, &s);
    assert_eq!(second, first + 7, "the re-deposit restarts the clock");
    let lp = token_amount(&w.svm, &s.lp_ata);

    // The ORIGINAL boundary has passed but the restarted one has not.
    warp_to(&mut w, first + cooldown + 1);
    assert_cooldown_refusal(try_withdraw(&mut w, &s, lp), "inside the restarted cooldown");
    warp_to(&mut w, second + cooldown);
    assert_cooldown_refusal(try_withdraw(&mut w, &s, lp), "at the restarted boundary");
    warp_to(&mut w, second + cooldown + 1);
    try_withdraw(&mut w, &s, lp).unwrap_or_else(|e| {
        panic!(
            "past the restarted boundary.\nLogs:\n{}",
            e.meta.logs.join("\n")
        )
    });
    assert_eq!(token_amount(&w.svm, &s.lp_ata), 0);
}
