//! #290 — mode-0 fee attribution: a raw vault donation must never be booked as fees.
//!
//! Before #290, `accrue_fees_inner` booked ANY vault balance above
//! `total_pool_value()` as fee revenue, and mode-0 pools (every pool `InitPool`
//! creates) fold `total_fees_earned` into their share price. A dominant LP could
//! donate X straight into the vault with a plain SPL Transfer and crank the
//! permissionless `AccrueFees`. That inflated the share price at a cost of only
//! `(MINIMUM_LIQUIDITY + 1) x price`, whatever the pool size: every deposit below the
//! price reverted `ZeroSharesMinted`, rounding dust accrued to the attacker, and
//! `total_fees_earned` on the insurance backstop was corrupted.
//!
//! Post-fix, a mode-0 pool books surplus only up to the wrapper's not-yet-booked
//! tag-87 payouts (`insurance_reserve_withdrawn_atoms`, read from `pool.slab`).
//!
//! REAL binaries: `target/deploy/percolator_stake.so` plus the sibling
//! `percolator-prog/target/deploy/percolator_prog.so`, under LiteSVM. The donation
//! is a REAL SPL Token `Transfer`. The two stand-ins for a real tag-87 payout (the
//! vault balance bump and the wrapper counter bump) are applied TOGETHER, exactly
//! as the wrapper's handler does. Rebuild the stake .so
//! (`cargo build-sbf -- --features devnet`) after changing source.
//!
//! Negative control: with `src/processor.rs` reverted to the pre-#290 accrual,
//! `donation_is_not_booked_as_fees_and_does_not_block_deposits` and
//! `legacy_pool_is_armed_once_then_strictly_attributed` FAIL.

use litesvm::LiteSVM;
use percolator_stake::state::{
    derive_deposit_pda, derive_pool_pda, derive_vault_authority, StakePool, STAKE_POOL_SIZE,
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
const MARKET_LEN_V17_CAP1: usize = 3835; // v2.2 cap-1 market (592 + 806 + 2437); was 3147 (v17), 3675 (v2.1)
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

fn write_pool(svm: &mut LiteSVM, pool_pda: &Pubkey, pool: &StakePool) {
    let mut acct = svm.get_account(pool_pda).unwrap();
    acct.data[..STAKE_POOL_SIZE].copy_from_slice(bytemuck::bytes_of(pool));
    svm.set_account(*pool_pda, acct).unwrap();
}

/// A REAL SPL Token `Transfer` (tag 3): the raw-donation primitive. No vault
/// signature is needed to send tokens INTO a token account.
fn spl_transfer_ix(source: Pubkey, dest: Pubkey, owner: &Pubkey, amount: u64) -> Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: Pubkey::from_str(TOKEN_PROGRAM).unwrap(),
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new(dest, false),
            AccountMeta::new_readonly(*owner, true),
        ],
        data,
    }
}

/// Which account to pass in the trailing #290 slab slot.
enum S {
    Real,
    Missing,
    Other(Pubkey),
}

struct World {
    svm: LiteSVM,
    stake_id: Pubkey,
    wrapper_id: Pubkey,
    accts: InitPoolAccounts,
    payer: Keypair,
    admin: Keypair,
}

/// Real InitMarket (wrapper) -> real InitPool (stake, mode 0). `None` if the .so
/// artifacts are missing (the suite's SKIP convention).
fn world() -> Option<World> {
    let so = stake_so();
    let wso = wrapper_so();
    if !so.exists() || !wso.exists() {
        eprintln!(
            "SKIP mode0_fee_attribution_e2e: .so missing (stake={} wrapper={})",
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
        wrapper_id,
        accts,
        payer,
        admin,
    })
}

struct User {
    kp: Keypair,
    ata: Pubkey,
    lp_ata: Pubkey,
}

fn user(w: &mut World, balance: u64) -> User {
    let kp = Keypair::new();
    w.svm.airdrop(&kp.pubkey(), 10_000_000_000).unwrap();
    let ata = Pubkey::new_unique();
    let lp_ata = Pubkey::new_unique();
    set_token_account(
        &mut w.svm,
        ata,
        &w.accts.collateral_mint,
        &kp.pubkey(),
        balance,
    );
    set_token_account(&mut w.svm, lp_ata, &w.accts.lp_mint, &kp.pubkey(), 0);
    User { kp, ata, lp_ata }
}

fn deposit(
    w: &mut World,
    u: &User,
    amount: u64,
    slab: S,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let (deposit_pda, _) = derive_deposit_pda(&w.stake_id, &w.accts.pool_pda, &u.kp.pubkey());
    let mut ix = deposit_ix(
        w.stake_id,
        &u.kp.pubkey(),
        w.accts.pool_pda,
        u.ata,
        w.accts.vault,
        w.accts.lp_mint,
        u.lp_ata,
        w.accts.vault_auth,
        deposit_pda,
        amount,
        w.accts.slab,
    );
    match slab {
        S::Real => {}
        S::Other(k) => ix.accounts.last_mut().unwrap().pubkey = k,
        S::Missing => {
            ix.accounts.pop();
        }
    }
    let payer = w.payer.insecure_clone();
    send(&mut w.svm, &payer, &[&u.kp], ix)
}

fn accrue(w: &mut World, slab: S) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let cranker = Keypair::new(); // unrelated third party: AccrueFees is permissionless
    w.svm.airdrop(&cranker.pubkey(), 1_000_000_000).unwrap();
    let mut ix = accrue_fees_ix(
        w.stake_id,
        &cranker.pubkey(),
        w.accts.pool_pda,
        w.accts.vault,
        w.accts.slab,
    );
    match slab {
        S::Real => {}
        S::Other(k) => ix.accounts.last_mut().unwrap().pubkey = k,
        S::Missing => {
            ix.accounts.pop();
        }
    }
    let payer = w.payer.insecure_clone();
    send(&mut w.svm, &payer, &[&cranker], ix)
}

/// Stand-in for one real tag-87 payout: tokens land in the vault AND the wrapper's
/// counter advances by the same amount, as `handle_withdraw_insurance_reserve_to_stake`
/// does in one instruction.
fn wrapper_pays_fees(w: &mut World, amount: u64) {
    let bal = token_amount(&w.svm, &w.accts.vault);
    set_token_account(
        &mut w.svm,
        w.accts.vault,
        &w.accts.collateral_mint,
        &w.accts.vault_auth,
        bal + amount,
    );
    let slab = w.accts.slab;
    advance_wrapper_fee_counter(&mut w.svm, &slab, amount);
}

fn logs(e: &litesvm::types::FailedTransactionMetadata) -> String {
    format!("{:?}\n{}", e.err, e.meta.logs.join("\n"))
}

/// Layout canary: the offset this program reads (`[560..576)`) must be the
/// wrapper's `insurance_reserve_withdrawn_atoms` in the REAL wrapper binary. The
/// neighbouring fee-share defaults InitMarket writes (creator/lp/insurance =
/// 1600/4800/1600 bps at `[576..582)`) pin the end of the four u128 counters, and
/// a fresh market's counter must read 0.
#[test]
fn wrapper_counter_offset_matches_real_wrapper_layout() {
    let Some(w) = world() else { return };
    let data = w.svm.get_account(&w.accts.slab).unwrap().data;
    let u16_at = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]);
    assert_eq!(
        (u16_at(576), u16_at(578), u16_at(580)),
        (1600, 4800, 1600),
        "WrapperConfigV16 fee shares moved: the four u128 counters no longer end at \
         account byte 576, so WRAPPER_OFF_INSURANCE_RESERVE_WITHDRAWN is stale"
    );
    assert_eq!(
        percolator_stake::state::read_wrapper_insurance_reserve_withdrawn(&data),
        Some(0),
        "fresh market: magic/kind must parse and the tag-87 counter must be 0"
    );
    let _ = (&w.wrapper_id, &w.admin);
}

/// The #290 PoC shape (genesis 2,000,000; donation 100,000,000 via a REAL SPL
/// Transfer; third-party AccrueFees; 50-token victim deposit), then a real-shaped
/// fee payout that MUST still be booked in full.
#[test]
fn donation_is_not_booked_as_fees_and_does_not_block_deposits() {
    let Some(mut w) = world() else { return };
    const GENESIS: u64 = 2_000_000;
    const DONATION: u64 = 100_000_000;

    let attacker = user(&mut w, GENESIS + DONATION);
    deposit(&mut w, &attacker, GENESIS, S::Real)
        .unwrap_or_else(|e| panic!("genesis deposit: {}", logs(&e)));
    let tpv_before = read_pool(&w.svm, &w.accts.pool_pda)
        .total_pool_value()
        .unwrap();
    assert_eq!(tpv_before, GENESIS);

    // Raw donation: a real SPL Transfer into the vault.
    let payer = w.payer.insecure_clone();
    let akp = attacker.kp.insecure_clone();
    send(
        &mut w.svm,
        &payer,
        &[&akp],
        spl_transfer_ix(attacker.ata, w.accts.vault, &akp.pubkey(), DONATION),
    )
    .unwrap_or_else(|e| panic!("SPL donation transfer: {}", logs(&e)));
    assert_eq!(token_amount(&w.svm, &w.accts.vault), GENESIS + DONATION);

    // Permissionless crank. Pre-#290 this booked all 100,000,000 as fees.
    accrue(&mut w, S::Real).unwrap_or_else(|e| panic!("AccrueFees: {}", logs(&e)));
    let pool = read_pool(&w.svm, &w.accts.pool_pda);
    assert_eq!(
        pool.total_fees_earned, 0,
        "#290: a raw donation must NOT be booked as fee revenue"
    );
    assert_eq!(
        pool.total_pool_value().unwrap(),
        tpv_before,
        "#290: a raw donation must not move the share price"
    );

    // The DoS the donation used to cause: a 50-token deposit reverted
    // ZeroSharesMinted at the pumped price (51 per LP). It must now mint.
    let victim = user(&mut w, 1_000);
    deposit(&mut w, &victim, 50, S::Real)
        .unwrap_or_else(|e| panic!("#290: small deposit must not be priced out: {}", logs(&e)));
    assert!(
        token_amount(&w.svm, &victim.lp_ata) > 0,
        "victim must receive LP at the un-inflated price"
    );

    // A real-shaped wrapper payout IS still fee revenue, booked in full and no more.
    const FEES: u64 = 7_777;
    wrapper_pays_fees(&mut w, FEES);
    accrue(&mut w, S::Real).unwrap_or_else(|e| panic!("AccrueFees: {}", logs(&e)));
    let pool = read_pool(&w.svm, &w.accts.pool_pda);
    assert_eq!(
        pool.total_fees_earned, FEES,
        "wrapper-paid fees must be booked exactly, the donation still excluded"
    );
    assert_eq!(
        pool.mode0_fees_attributed, FEES,
        "cursor tracks booked payouts"
    );
    assert!(pool.fee_attribution_armed());

    // Idempotent: a second crank books nothing more.
    accrue(&mut w, S::Real).unwrap_or_else(|e| panic!("AccrueFees: {}", logs(&e)));
    assert_eq!(read_pool(&w.svm, &w.accts.pool_pda).total_fees_earned, FEES);
}

/// A pool created before #290 has `fee_attribution_armed == false` and a stale
/// vault snapshot in the cursor bytes. The first accrual books what the legacy
/// code would have booked, capped at the wrapper's lifetime payouts. From then on,
/// accrual is strictly attributed.
#[test]
fn legacy_pool_is_armed_once_then_strictly_attributed() {
    let Some(mut w) = world() else { return };
    let lp = user(&mut w, 1_000_000);
    deposit(&mut w, &lp, 1_000_000, S::Real)
        .unwrap_or_else(|e| panic!("genesis deposit: {}", logs(&e)));

    // Rewind the pool to its pre-#290 shape: un-armed, stale snapshot bytes.
    let mut pool = read_pool(&w.svm, &w.accts.pool_pda);
    pool.set_fee_attribution_armed(false);
    pool.mode0_fees_attributed = 987_654_321; // a stale vault-balance snapshot
    write_pool(&mut w.svm, &w.accts.pool_pda, &pool);

    // Pending, un-accrued wrapper payout of 5,000 at upgrade time.
    wrapper_pays_fees(&mut w, 5_000);
    accrue(&mut w, S::Real).unwrap_or_else(|e| panic!("AccrueFees: {}", logs(&e)));
    let pool = read_pool(&w.svm, &w.accts.pool_pda);
    assert!(
        pool.fee_attribution_armed(),
        "first attributed accrual arms the cursor"
    );
    assert_eq!(
        pool.total_fees_earned, 5_000,
        "pending payout at upgrade is booked"
    );
    assert_eq!(
        pool.mode0_fees_attributed, 5_000,
        "stale snapshot replaced by the counter"
    );

    // After arming, a donation is ignored.
    let d = user(&mut w, 3_000_000);
    let payer = w.payer.insecure_clone();
    let dkp = d.kp.insecure_clone();
    send(
        &mut w.svm,
        &payer,
        &[&dkp],
        spl_transfer_ix(d.ata, w.accts.vault, &dkp.pubkey(), 3_000_000),
    )
    .unwrap();
    accrue(&mut w, S::Real).unwrap_or_else(|e| panic!("AccrueFees: {}", logs(&e)));
    assert_eq!(
        read_pool(&w.svm, &w.accts.pool_pda).total_fees_earned,
        5_000
    );
}

/// The slab is load-bearing, so it must be required where it matters and
/// unforgeable where supplied.
#[test]
fn slab_account_is_required_and_validated() {
    let Some(mut w) = world() else { return };
    let lp = user(&mut w, 10_000_000);
    deposit(&mut w, &lp, 1_000_000, S::Real)
        .unwrap_or_else(|e| panic!("genesis deposit: {}", logs(&e)));

    // Missing: mode-0 AccrueFees and Deposit refuse (a Deposit without it could mint
    // at a price that has not absorbed pending wrapper fees: the #136 JIT capture).
    let e = accrue(&mut w, S::Missing).expect_err("mode-0 AccrueFees without slab must fail");
    assert!(logs(&e).contains("NotEnoughAccountKeys"), "{}", logs(&e));
    let e =
        deposit(&mut w, &lp, 1_000, S::Missing).expect_err("mode-0 Deposit without slab must fail");
    assert!(logs(&e).contains("NotEnoughAccountKeys"), "{}", logs(&e));

    // Forged: an account owned by some other program, claiming a huge counter.
    let forged = Pubkey::new_unique();
    let mut data = w.svm.get_account(&w.accts.slab).unwrap().data;
    let off = percolator_stake::state::WRAPPER_OFF_INSURANCE_RESERVE_WITHDRAWN;
    data[off..off + 16].copy_from_slice(&(u64::MAX as u128).to_le_bytes());
    w.svm
        .set_account(
            forged,
            Account {
                lamports: 1_000_000_000,
                data: data.clone(),
                owner: Pubkey::new_unique(),
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    accrue(&mut w, S::Other(forged)).expect_err("slab != pool.slab must fail");

    // Owner gate: the real slab key, re-owned by a foreign program and carrying
    // the forged counter, must be refused with IllegalOwner.
    let real = w.svm.get_account(&w.accts.slab).unwrap();
    let mut reowned = real.clone();
    reowned.owner = Pubkey::new_unique();
    reowned.data = data;
    w.svm.set_account(w.accts.slab, reowned).unwrap();
    let e = accrue(&mut w, S::Real).expect_err("slab owner != pool.percolator_program must fail");
    assert!(logs(&e).contains("IllegalOwner"), "{}", logs(&e));
    w.svm.set_account(w.accts.slab, real).unwrap();

    // Nothing was booked through any refused path.
    assert_eq!(read_pool(&w.svm, &w.accts.pool_pda).total_fees_earned, 0);
}
