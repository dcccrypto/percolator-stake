//! F3 (fee-flow audit 2026-09-29): AccrueFees must not book fees to the N7
//! dead shares.
//!
//! `pool.total_lp_supply` counts the `MINIMUM_LIQUIDITY` (1,000) dead shares
//! that the genesis deposit locks and that nobody can ever redeem. The old gate
//! in `accrue_fees_inner` was `total_lp_supply > 0`, so once every real staker
//! had exited (supply == 1,000, the live state of six devnet pools on
//! 2026-09-29) a wrapper tag-87 push + the permissionless AccrueFees booked the
//! whole payout to the dead shares: unredeemable, and charged to the next
//! depositor as an inflated share price.
//!
//! The fix mirrors the wrapper LP vault guard
//! (`total_lp_shares_outstanding <= LP_VAULT_MINIMUM_LIQUIDITY` -> refuse):
//! AccrueFees refuses with `NoRealLpHolders` (Custom 29) and writes nothing,
//! and the shared accrual helper skips (without refusing) on the deposit and
//! withdraw pre-accrue path, so the pushed tokens stay in the vault un-booked
//! until a real staker exists.
//!
//! Real stake .so + real wrapper .so under LiteSVM, same harness as
//! `mode0_accrue_fees_e2e.rs`. The only forged state is the tag-87 push itself
//! (vault balance + the wrapper's `insurance_reserve_withdrawn_atoms` counter),
//! exactly as in that file. Rebuild `target/deploy/percolator_stake.so` after
//! changing source, or these tests exercise stale bytes.

#![allow(clippy::result_large_err, clippy::too_many_arguments)]

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
// v18 wrapper market account length for capacity 1. The deployed v18.2 wrapper
// (deploy/v18.2-wrapper@6377376a, sha256 4472b383...) rejects the older v17 length
// 3147 at InitMarket with InvalidAccountData; 3675 is what it accepts. The #290
// counter (`insurance_reserve_withdrawn_atoms`, bytes [560..576)) is unchanged.
// Run these suites against a v18 wrapper .so: the v17-era CI pin (15eb8b0c) rejects
// the v18 InitPool marketauth CPI wire with InvalidInstructionData.
// v2.2 (wrapper VERSION 19): 592 + 806 + 2437 = 3835 (3675 on v2.1).
const MARKET_LEN_V18_CAP1: usize = 3995;
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

// ---- F3-specific helpers ----

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

/// Real InitPool (mode 0), ready for deposits. None if either .so is missing.
fn world(test_name: &str) -> Option<World> {
    let so = stake_so();
    let wso = wrapper_so();
    if !so.exists() || !wso.exists() {
        eprintln!(
            "SKIP {test_name}: .so missing (stake={} wrapper={})",
            so.display(),
            wso.display()
        );
        return None;
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
        init_pool_ix(stake_id, &accts, 5, 0),
    )
    .unwrap_or_else(|e| panic!("InitPool.\nLogs:\n{}", e.meta.logs.join("\n")));
    assert_eq!(read_pool(&svm, &accts.pool_pda).pool_mode, 0);
    Some(World {
        svm,
        stake_id,
        payer,
        accts,
    })
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

/// The wrapper's tag-87 push: `amount` atoms land in the vault AND the wrapper's
/// cumulative payout counter advances by the same amount (that is what makes the
/// surplus attributable fee revenue under #290).
fn push_fees(w: &mut World, amount: u64) {
    let bal = token_amount(&w.svm, &w.accts.vault);
    let (mint, auth, vault) = (w.accts.collateral_mint, w.accts.vault_auth, w.accts.vault);
    set_token_account(&mut w.svm, vault, &mint, &auth, bal + amount);
    advance_wrapper_fee_counter(&mut w.svm, &w.accts.slab, amount);
}

fn accrue(w: &mut World) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let cranker = Keypair::new();
    w.svm.airdrop(&cranker.pubkey(), 10_000_000_000).unwrap();
    let ix = accrue_fees_ix(
        w.stake_id,
        &cranker.pubkey(),
        w.accts.pool_pda,
        w.accts.vault,
        w.accts.slab,
    );
    // A fresh blockhash so repeated identical AccrueFees txs are not deduped.
    w.svm.expire_blockhash();
    send(&mut w.svm, &w.payer, &[&cranker], ix)
}

fn pool_bytes(w: &World) -> Vec<u8> {
    w.svm.get_account(&w.accts.pool_pda).unwrap().data
}

const NO_REAL_LP_HOLDERS: u32 = 29;

/// (a) A pool whose only LP supply is the 1,000 dead shares (every real staker has
/// exited through the real Withdraw instruction) receives a tag-87 push. AccrueFees
/// is REFUSED with NoRealLpHolders (Custom 29), the pool account is byte-for-byte
/// unchanged (share price, total_fees_earned, the #290 cursor, last_fee_accrual_slot),
/// and the pushed tokens stay in the vault.
///
/// Pre-fix: AccrueFees succeeds and books the whole push to the dead shares.
#[test]
fn f3_accrue_fees_refused_when_only_dead_shares_exist() {
    let Some(mut w) = world("f3_accrue_fees_refused_when_only_dead_shares_exist") else {
        return;
    };
    assert_eq!(
        percolator_stake::error::StakeError::NoRealLpHolders as u32,
        NO_REAL_LP_HOLDERS
    );

    // Genesis 2,000 -> the staker holds 1,000 LP, 1,000 are dead.
    let alice = deposit(&mut w, 2_000);
    assert_eq!(
        token_amount(&w.svm, &alice.lp_ata),
        2_000 - MINIMUM_LIQUIDITY
    );
    assert_eq!(read_pool(&w.svm, &w.accts.pool_pda).total_lp_supply, 2_000);

    // Every real staker exits (real Withdraw, after the 5-slot cooldown).
    let slot = w.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    w.svm.warp_to_slot(slot + 100);
    let ix = withdraw_ix(
        w.stake_id,
        &alice.kp.pubkey(),
        &w.accts,
        alice.ata,
        alice.lp_ata,
        2_000 - MINIMUM_LIQUIDITY,
    );
    send(&mut w.svm, &w.payer, &[&alice.kp], ix)
        .unwrap_or_else(|e| panic!("Withdraw.\nLogs:\n{}", e.meta.logs.join("\n")));
    let pool = read_pool(&w.svm, &w.accts.pool_pda);
    assert_eq!(
        pool.total_lp_supply, MINIMUM_LIQUIDITY,
        "only the dead shares remain"
    );
    assert_eq!(token_amount(&w.svm, &alice.lp_ata), 0);
    assert_eq!(pool.total_fees_earned, 0);

    // The wrapper pushes the insurance leg (tag 87) into the dead-share-only pool.
    let fees: u64 = 1_224_232; // the PENGU figure from the audit
    let vault_before_push = token_amount(&w.svm, &w.accts.vault);
    push_fees(&mut w, fees);
    let pool_value_before = read_pool(&w.svm, &w.accts.pool_pda)
        .total_pool_value()
        .unwrap();
    let before = pool_bytes(&w);

    let err = accrue(&mut w)
        .expect_err("F3: AccrueFees must be REFUSED when total_lp_supply <= MINIMUM_LIQUIDITY");
    match err.err {
        solana_sdk::transaction::TransactionError::InstructionError(
            _,
            solana_sdk::instruction::InstructionError::Custom(code),
        ) => assert_eq!(code, NO_REAL_LP_HOLDERS, "must be NoRealLpHolders (29)"),
        other => panic!("expected Custom(29), got {other:?}"),
    }
    assert!(
        err.meta
            .logs
            .iter()
            .any(|l| l.contains("no real LP holders")),
        "refusal log line missing:\n{}",
        err.meta.logs.join("\n")
    );

    // Nothing was written: the pool account (share price inputs, fee ledger, #290
    // cursor, last_fee_accrual_slot) is byte-identical.
    assert_eq!(
        pool_bytes(&w),
        before,
        "a refused AccrueFees must write nothing"
    );
    let pool = read_pool(&w.svm, &w.accts.pool_pda);
    assert_eq!(
        pool.total_fees_earned, 0,
        "nothing booked to the dead shares"
    );
    assert_eq!(pool.total_pool_value().unwrap(), pool_value_before);
    // The pushed tokens stay in the vault, un-booked.
    assert_eq!(
        token_amount(&w.svm, &w.accts.vault),
        vault_before_push + fees
    );
}

/// (a, continued) S2 (Phase 4 v5, FIRST_LOSS pools): a push paid while ONLY the dead shares
/// exist belongs to no staker. The first real depositor's Deposit pre-accrue consumes it from
/// the #290 attribution cursor UNBOOKED, so it is never booked to that first staker (the F5
/// windfall this test used to measure is closed). The tokens stay in the vault as unbooked
/// surplus (terminal recovery books them to whoever then holds LP).
#[test]
fn f3_s2_pending_push_is_never_booked_to_the_first_staker() {
    let Some(mut w) = world("f3_s2_pending_push_is_never_booked_to_the_first_staker") else {
        return;
    };
    let alice = deposit(&mut w, 2_000);
    let slot = w.svm.get_sysvar::<solana_sdk::clock::Clock>().slot;
    w.svm.warp_to_slot(slot + 100);
    let ix = withdraw_ix(
        w.stake_id,
        &alice.kp.pubkey(),
        &w.accts,
        alice.ata,
        alice.lp_ata,
        2_000 - MINIMUM_LIQUIDITY,
    );
    send(&mut w.svm, &w.payer, &[&alice.kp], ix).unwrap();
    assert_eq!(
        read_pool(&w.svm, &w.accts.pool_pda).total_lp_supply,
        MINIMUM_LIQUIDITY
    );

    let fees: u64 = 1_224_232;
    push_fees(&mut w, fees);
    assert!(
        accrue(&mut w).is_err(),
        "refused while only dead shares exist"
    );
    let cursor_before = read_pool(&w.svm, &w.accts.pool_pda).mode0_fees_attributed;

    let pv_before = read_pool(&w.svm, &w.accts.pool_pda)
        .total_pool_value()
        .unwrap();
    let dep: u64 = 10_000;
    let bob = deposit(&mut w, dep);
    let pool = read_pool(&w.svm, &w.accts.pool_pda);
    assert_eq!(pool.total_fees_earned, 0, "nothing booked at the deposit");
    assert_eq!(
        pool.mode0_fees_attributed,
        cursor_before + fees,
        "S2: the pre-stake backlog is consumed from the cursor"
    );
    let bob_lp = token_amount(&w.svm, &bob.lp_ata);
    let expected_lp =
        percolator_stake::math::calc_lp_for_deposit(MINIMUM_LIQUIDITY, pv_before, dep).unwrap();
    assert_eq!(bob_lp, expected_lp, "minted at the un-accrued price");

    // A later AccrueFees has nothing attributable: the backlog is never Bob's.
    let _ = accrue(&mut w);
    let pool = read_pool(&w.svm, &w.accts.pool_pda);
    assert_eq!(pool.total_fees_earned, 0, "S2: the backlog is never booked");
    let bob_claim = percolator_stake::math::calc_collateral_for_withdraw(
        pool.total_lp_supply,
        pool.total_pool_value().unwrap(),
        bob_lp,
    )
    .unwrap();
    assert!(bob_claim <= dep, "S2: no first-staker windfall ({bob_claim} vs {dep})");
    // The tokens are still in the vault (unbooked surplus).
    assert!(token_amount(&w.svm, &w.accts.vault) >= pv_before + dep + fees);
}

/// (b) A pool with real stakers still accrues. Includes the exact boundary: a
/// genesis deposit of MINIMUM_LIQUIDITY + 1 leaves ONE real share
/// (total_lp_supply == 1,001), and AccrueFees books.
#[test]
fn f3_accrue_fees_still_books_with_real_stakers() {
    for genesis in [MINIMUM_LIQUIDITY + 1, 2_000, 1_000_000] {
        let Some(mut w) = world("f3_accrue_fees_still_books_with_real_stakers") else {
            return;
        };
        let _s = deposit(&mut w, genesis);
        let pool = read_pool(&w.svm, &w.accts.pool_pda);
        assert_eq!(pool.total_lp_supply, genesis);
        let pv = pool.total_pool_value().unwrap();
        let fees: u64 = 4_242;
        push_fees(&mut w, fees);
        accrue(&mut w).unwrap_or_else(|e| {
            panic!(
                "AccrueFees must succeed with real stakers (genesis {genesis}).\nLogs:\n{}",
                e.meta.logs.join("\n")
            )
        });
        let pool = read_pool(&w.svm, &w.accts.pool_pda);
        assert_eq!(pool.total_fees_earned, fees, "genesis {genesis}");
        assert_eq!(
            pool.total_pool_value().unwrap(),
            pv + fees,
            "genesis {genesis}"
        );
    }
}
