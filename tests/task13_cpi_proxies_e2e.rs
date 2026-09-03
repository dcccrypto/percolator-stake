//! Task 13 — CPI proxies for wrapper setters stranded by staking, e2e.
//!
//! `InitPool` irreversibly rotates `cfg.marketauth` to the stake-pool PDA, and
//! `BindInsuranceAuthority` hands asset 0's `insurance_authority` to the
//! `vault_auth` PDA. A PDA cannot sign a top-level transaction, so every wrapper
//! instruction gated on either field becomes reachable ONLY through a CPI proxy
//! issued by this program. Before this file, exactly one such proxy existed
//! (`AdminResolveMarket` -> wrapper tag 19).
//!
//! WHY A PROXY TEST IN ISOLATION PROVES NOTHING. A test that just calls the new
//! proxy and sees `Ok` would pass even if the proxy were a no-op, and would pass
//! even if the authority had never actually moved. So every reachability test
//! here follows the same five-step shape against the REAL wrapper `.so`:
//!
//!   1. create a real v17 market (admin == marketauth == insurance_authority);
//!   2. call the wrapper tag DIRECTLY as admin and prove it SUCCEEDS — this is
//!      the control that pins the wire encoding and the account layout as
//!      correct BEFORE any authority moves, so a later failure cannot be blamed
//!      on a malformed instruction;
//!   3. run the real `StakeInitPool` (and real `BindInsuranceAuthority` for the
//!      insurance_authority-gated tags) so the authority genuinely moves;
//!   4. call the wrapper tag DIRECTLY as admin again and prove it now FAILS —
//!      this is the step that distinguishes a real proxy from a decorative one;
//!   5. call the PROXY, prove it succeeds, and read the wrapper config back off
//!      the chain to assert the stored value actually changed.
//!
//! Steps 2 and 4 together are the load-bearing pair: the same bytes that worked
//! before the rotation stop working after it, and only the proxy recovers them.
//!
//! GROUP A (marketauth-gated, POOL PDA signs): stake 25 -> wrapper 86,
//! stake 26 -> wrapper 88, and — since GH#286 — stake 28 -> wrapper 55.
//! GROUP B (insurance_authority-gated, VAULT_AUTH PDA signs): stake 27 ->
//! wrapper 51.
//!
//! Tag 28 MOVED from Group B to Group A. Wrapper #455 re-gated tag 55 on
//! marketauth ("like every other market-wide setter"), and `InitPool` rotates
//! marketauth to the pool PDA — so the pool PDA is now the correct signer and
//! vault_auth is refused. See the note on `tag55_*` for why that test is
//! ignored until the wrapper carrying #455 is deployed.
//!
//! Wrapper tag 51 is the setter for `backing_trade_fee_bps`. On a staked market
//! nobody could set it, which is the mechanical root of the standing
//! "fee split is unachievable" finding. `tag51_*` below is the test that proves
//! that specific hole is closed.

use litesvm::LiteSVM;
use percolator_stake::state::{derive_pool_pda, derive_vault_authority};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
    transaction::{Transaction, TransactionError},
};
use std::path::PathBuf;
use std::str::FromStr;

const WRAPPER_MAINNET: &str = "ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv";
// The stake program's canonical declared id (`solana_program::declare_id!` in
// src/lib.rs). Loading the .so at its real id keeps every PDA derivation in this
// file identical to production.
const STAKE_ID: &str = "GCHhcgwPyrai8SWHEVWw3odedguFXEtJobNnWSfWBCU3";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

const MARKET_LEN_V17_CAP1: usize = 3147;
// 3147 = MARKET_GROUP_OFF(592 = HEADER_LEN 16 + WRAPPER_CONFIG_LEN 576)
//       + MARKET_GROUP_LEN(758) + 1 * MARKET_ASSET_SLOT_LEN(1797).
// Recompute via percolator_prog::state::market_account_len_for_capacity(1) if
// the wrapper config changes again.
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;

// ── WrapperConfigV16 field offsets, absolute in the market account ───────────
//
// The config sits immediately after the 16-byte account header, so every offset
// below is `16 + offset_within_WrapperConfigV16`. The struct derives
// bytemuck::Pod (no implicit padding), so the field order in v16_program.rs is
// the byte order here.
//
// THESE OFFSETS ARE SELF-VALIDATING. Every test that reads a share asserts the
// InitMarket defaults (1600/4800/1600) at these offsets BEFORE mutating
// anything. If an offset were wrong, that pre-state assertion fails loudly
// rather than silently reading an unrelated field and comparing it to garbage.
const CFG_OFF: usize = 16;
const OFF_MAINTENANCE_FEE_PER_SLOT: usize = CFG_OFF + 96; // u128
const OFF_TRADE_FEE_BASE_BPS: usize = CFG_OFF + 128; // u64
const OFF_BACKING_TRADE_FEE_BPS_LONG: usize = CFG_OFF + 182; // u16
const OFF_BACKING_INS_SHARE_BPS_LONG: usize = CFG_OFF + 426; // u16
const OFF_CREATOR_SHARE_BPS: usize = CFG_OFF + 560; // u16
const OFF_LP_SHARE_BPS: usize = CFG_OFF + 562; // u16
const OFF_INSURANCE_SHARE_BPS: usize = CFG_OFF + 564; // u16

// InitMarket fee-split defaults (v16_program.rs constants). Sum == 8000 ==
// FEE_SHARE_TOTAL_BPS (10_000 - PROTOCOL_FEE_BPS).
const DEFAULT_CREATOR_SHARE_BPS: u16 = 1600;
const DEFAULT_LP_SHARE_BPS: u16 = 4800;
const DEFAULT_INSURANCE_SHARE_BPS: u16 = 1600;

// Two distinct VALID splits (each sums to 8000 and satisfies creator <= 3600,
// lp >= 3200, insurance >= 1200). "PRE" is applied directly before staking;
// "POST" is applied through the proxy after staking, so the final assertion
// proves the proxy moved the value off a non-default state.
const PRE_SPLIT: (u16, u16, u16) = (1200, 5000, 1800);
const POST_SPLIT: (u16, u16, u16) = (3600, 3200, 1200);

// ── wrapper instruction tags ────────────────────────────────────────────────
const W_TAG_UPDATE_BACKING_FEE_POLICY: u8 = 51;
const W_TAG_UPDATE_TRADE_FEE_POLICY: u8 = 55;
const W_TAG_UPDATE_ASSET_AUTHORITY: u8 = 65;
const W_TAG_UPDATE_FEE_SPLIT: u8 = 86;
const W_TAG_UPDATE_MAINTENANCE_FEE_PER_SLOT: u8 = 88;

// ── stake instruction tags (this task) ──────────────────────────────────────
const S_TAG_ADMIN_UPDATE_FEE_SPLIT: u8 = 25;
const S_TAG_ADMIN_UPDATE_MAINTENANCE_FEE_PER_SLOT: u8 = 26;
const S_TAG_ADMIN_UPDATE_BACKING_FEE_POLICY: u8 = 27;
const S_TAG_ADMIN_UPDATE_TRADE_FEE_POLICY: u8 = 28;

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
) -> Result<(), TransactionError> {
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
    svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err)
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

/// Build a Live v17 market. `admin` becomes `cfg.marketauth` AND asset 0's
/// `asset_admin` / `insurance_authority` (InitMarket bootstraps all of them to
/// the init signer), which is exactly the pre-stake state both groups start from.
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

// ── config readers ──────────────────────────────────────────────────────────

// ── error-code discrimination ───────────────────────────────────────────────
//
// Both programs surface failures as `Custom(n)`, so a bare `expect_err` cannot
// tell "the stake program refused" from "the wrapper refused". Several tests
// below would otherwise pass for the wrong reason — e.g. a proxy aimed at a
// foreign slab is ALSO rejected by the wrapper (the mis-derived PDA is not that
// market's marketauth), so removing stake's own `pool.slab` check would leave a
// bare `expect_err` green. Asserting the exact code is what makes those tests
// sensitive to the check they are meant to cover.
//
// Wrapper `PercolatorError` (v16_program.rs): Unauthorized is index 8.
const WRAPPER_ERR_UNAUTHORIZED: u32 = 8;
// Stake `StakeError` (src/error.rs): Unauthorized = 2, InvalidPda = 10.
const STAKE_ERR_UNAUTHORIZED: u32 = 2;
const STAKE_ERR_INVALID_PDA: u32 = 10;

#[track_caller]
fn assert_custom_err(err: &TransactionError, expected: u32, ctx: &str) {
    match err {
        TransactionError::InstructionError(
            _,
            solana_sdk::instruction::InstructionError::Custom(code),
        ) => assert_eq!(
            *code, expected,
            "{ctx}: expected Custom({expected}), got Custom({code})"
        ),
        other => panic!("{ctx}: expected Custom({expected}), got {other:?}"),
    }
}

fn read_u16_at(svm: &LiteSVM, market: &Pubkey, off: usize) -> u16 {
    let d = svm.get_account(market).unwrap().data;
    u16::from_le_bytes(d[off..off + 2].try_into().unwrap())
}

fn read_u64_at(svm: &LiteSVM, market: &Pubkey, off: usize) -> u64 {
    let d = svm.get_account(market).unwrap().data;
    u64::from_le_bytes(d[off..off + 8].try_into().unwrap())
}

fn read_u128_at(svm: &LiteSVM, market: &Pubkey, off: usize) -> u128 {
    let d = svm.get_account(market).unwrap().data;
    u128::from_le_bytes(d[off..off + 16].try_into().unwrap())
}

fn read_split(svm: &LiteSVM, market: &Pubkey) -> (u16, u16, u16) {
    (
        read_u16_at(svm, market, OFF_CREATOR_SHARE_BPS),
        read_u16_at(svm, market, OFF_LP_SHARE_BPS),
        read_u16_at(svm, market, OFF_INSURANCE_SHARE_BPS),
    )
}

/// Assert the freshly-initialized market shows the InitMarket fee-split
/// defaults. This is the offset self-check described at the top: it fails if
/// `OFF_CREATOR_SHARE_BPS` and friends have drifted from the wrapper's layout.
fn assert_default_split(svm: &LiteSVM, market: &Pubkey) {
    assert_eq!(
        read_split(svm, market),
        (
            DEFAULT_CREATOR_SHARE_BPS,
            DEFAULT_LP_SHARE_BPS,
            DEFAULT_INSURANCE_SHARE_BPS
        ),
        "OFFSET SELF-CHECK: a fresh v17 market must read back the InitMarket \
         fee-split defaults at OFF_CREATOR/LP/INSURANCE_SHARE_BPS. A mismatch \
         means WrapperConfigV16's layout moved and these offsets are stale."
    );
}

// ── direct wrapper instruction builders ─────────────────────────────────────

fn direct_update_fee_split_ix(
    wrapper_id: Pubkey,
    authority: Pubkey,
    market: Pubkey,
    split: (u16, u16, u16),
) -> Instruction {
    let mut data = Vec::with_capacity(7);
    data.push(W_TAG_UPDATE_FEE_SPLIT);
    data.extend_from_slice(&split.0.to_le_bytes());
    data.extend_from_slice(&split.1.to_le_bytes());
    data.extend_from_slice(&split.2.to_le_bytes());
    Instruction {
        program_id: wrapper_id,
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(market, false),
        ],
        data,
    }
}

fn direct_update_maintenance_fee_ix(
    wrapper_id: Pubkey,
    authority: Pubkey,
    market: Pubkey,
    value: u128,
) -> Instruction {
    let mut data = Vec::with_capacity(17);
    data.push(W_TAG_UPDATE_MAINTENANCE_FEE_PER_SLOT);
    data.extend_from_slice(&value.to_le_bytes());
    Instruction {
        program_id: wrapper_id,
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(market, false),
        ],
        data,
    }
}

fn direct_update_backing_fee_ix(
    wrapper_id: Pubkey,
    authority: Pubkey,
    market: Pubkey,
    domain: u16,
    fee_bps: u16,
    insurance_share_bps: u16,
) -> Instruction {
    let mut data = Vec::with_capacity(7);
    data.push(W_TAG_UPDATE_BACKING_FEE_POLICY);
    data.extend_from_slice(&domain.to_le_bytes());
    data.extend_from_slice(&fee_bps.to_le_bytes());
    data.extend_from_slice(&insurance_share_bps.to_le_bytes());
    Instruction {
        program_id: wrapper_id,
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(market, false),
        ],
        data,
    }
}

fn direct_update_trade_fee_ix(
    wrapper_id: Pubkey,
    authority: Pubkey,
    market: Pubkey,
    trade_fee_base_bps: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(9);
    data.push(W_TAG_UPDATE_TRADE_FEE_POLICY);
    data.extend_from_slice(&trade_fee_base_bps.to_le_bytes());
    Instruction {
        program_id: wrapper_id,
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(market, false),
        ],
        data,
    }
}

/// Wrapper tag 65 `UpdateAssetAuthority`, used only by the tag-69 analysis test
/// to demonstrate that a burned (`[0;32]`) `asset_admin` rejects every signer.
///
/// A non-zero incoming key must itself co-sign and must equal `new_pubkey`
/// (v16_program.rs handle_update_asset_authority), so `new_authority` is marked
/// as a signer here and the caller passes the same key in both positions.
fn direct_update_asset_authority_ix(
    wrapper_id: Pubkey,
    current: Pubkey,
    new_authority: Pubkey,
    market: Pubkey,
    kind: u8,
) -> Instruction {
    let mut data = Vec::with_capacity(36);
    data.push(W_TAG_UPDATE_ASSET_AUTHORITY);
    data.extend_from_slice(&0u16.to_le_bytes()); // asset_index = 0
    data.push(kind);
    data.extend_from_slice(&new_authority.to_bytes()); // new_pubkey == the co-signer
    Instruction {
        program_id: wrapper_id,
        accounts: vec![
            AccountMeta::new_readonly(current, true),
            AccountMeta::new_readonly(new_authority, true),
            AccountMeta::new(market, false),
        ],
        data,
    }
}

// ── stake proxy instruction builders ────────────────────────────────────────

/// GROUP A account shape: [admin(signer), pool_pda, slab(w), percolator].
fn group_a_proxy_ix(
    stake_id: Pubkey,
    admin: Pubkey,
    pool_pda: Pubkey,
    slab: Pubkey,
    wrapper_id: Pubkey,
    data: Vec<u8>,
) -> Instruction {
    Instruction {
        program_id: stake_id,
        accounts: vec![
            AccountMeta::new_readonly(admin, true),
            AccountMeta::new_readonly(pool_pda, false),
            AccountMeta::new(slab, false),
            AccountMeta::new_readonly(wrapper_id, false),
        ],
        data,
    }
}

/// GROUP B account shape: [admin(signer), pool_pda, vault_auth, slab(w), percolator].
#[allow(clippy::too_many_arguments)]
fn group_b_proxy_ix(
    stake_id: Pubkey,
    admin: Pubkey,
    pool_pda: Pubkey,
    vault_auth: Pubkey,
    slab: Pubkey,
    wrapper_id: Pubkey,
    data: Vec<u8>,
) -> Instruction {
    Instruction {
        program_id: stake_id,
        accounts: vec![
            AccountMeta::new_readonly(admin, true),
            AccountMeta::new_readonly(pool_pda, false),
            AccountMeta::new_readonly(vault_auth, false),
            AccountMeta::new(slab, false),
            AccountMeta::new_readonly(wrapper_id, false),
        ],
        data,
    }
}

fn encode_proxy_fee_split(split: (u16, u16, u16)) -> Vec<u8> {
    let mut d = Vec::with_capacity(7);
    d.push(S_TAG_ADMIN_UPDATE_FEE_SPLIT);
    d.extend_from_slice(&split.0.to_le_bytes());
    d.extend_from_slice(&split.1.to_le_bytes());
    d.extend_from_slice(&split.2.to_le_bytes());
    d
}

fn encode_proxy_maintenance_fee(value: u128) -> Vec<u8> {
    let mut d = Vec::with_capacity(17);
    d.push(S_TAG_ADMIN_UPDATE_MAINTENANCE_FEE_PER_SLOT);
    d.extend_from_slice(&value.to_le_bytes());
    d
}

fn encode_proxy_backing_fee(domain: u16, fee_bps: u16, insurance_share_bps: u16) -> Vec<u8> {
    let mut d = Vec::with_capacity(7);
    d.push(S_TAG_ADMIN_UPDATE_BACKING_FEE_POLICY);
    d.extend_from_slice(&domain.to_le_bytes());
    d.extend_from_slice(&fee_bps.to_le_bytes());
    d.extend_from_slice(&insurance_share_bps.to_le_bytes());
    d
}

fn encode_proxy_trade_fee(trade_fee_base_bps: u64) -> Vec<u8> {
    let mut d = Vec::with_capacity(9);
    d.push(S_TAG_ADMIN_UPDATE_TRADE_FEE_POLICY);
    d.extend_from_slice(&trade_fee_base_bps.to_le_bytes());
    d
}

// ── stake InitPool / BindInsuranceAuthority ─────────────────────────────────

struct Staked {
    market: Pubkey,
    pool_pda: Pubkey,
    vault_auth: Pubkey,
}

fn encode_init_pool(cooldown_slots: u64, deposit_cap: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(17);
    out.push(0u8); // tag InitPool
    out.extend_from_slice(&cooldown_slots.to_le_bytes());
    out.extend_from_slice(&deposit_cap.to_le_bytes());
    out
}

/// Runs the REAL `StakeInitPool`, which is what actually rotates
/// `cfg.marketauth` to the pool PDA. Nothing here is injected or simulated.
#[allow(clippy::too_many_arguments)]
fn run_init_pool(
    svm: &mut LiteSVM,
    wrapper_id: Pubkey,
    stake_id: Pubkey,
    token_program: Pubkey,
    admin: &Keypair,
    payer: &Keypair,
    market: Pubkey,
    mint: Pubkey,
) -> Staked {
    let (pool_pda, _) = derive_pool_pda(&stake_id, &market);
    let (vault_auth, _) = derive_vault_authority(&stake_id, &pool_pda);
    let lp_mint = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    preallocate_empty_spl_account(svm, lp_mint, token_program, 82);
    preallocate_empty_spl_account(svm, vault, token_program, 165);

    let ix = Instruction {
        program_id: stake_id,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false), // writable: the marketauth CPI needs it
            AccountMeta::new(pool_pda, false),
            AccountMeta::new(lp_mint, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(vault_auth, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(wrapper_id, false),
            AccountMeta::new_readonly(token_program, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(solana_sdk::sysvar::rent::id(), false),
        ],
        // cooldown_slots MUST be non-zero: InitPool calls validate_cooldown_slots
        // (BUG-13), which rejects 0 so a pool can never exist without a cooldown.
        // deposit_cap 0 == uncapped, matching n6_marketauth_rotation_e2e.
        data: encode_init_pool(5, 0),
    };
    send(svm, payer, &[admin], ix).expect("StakeInitPool must succeed");

    Staked {
        market,
        pool_pda,
        vault_auth,
    }
}

/// Runs the REAL `BindInsuranceAuthority` (stake tag 19), which moves asset 0's
/// `insurance_authority` (and `insurance_operator`) to `vault_auth`.
fn run_bind_insurance_authority(
    svm: &mut LiteSVM,
    wrapper_id: Pubkey,
    stake_id: Pubkey,
    admin: &Keypair,
    payer: &Keypair,
    s: &Staked,
) {
    let ix = Instruction {
        program_id: stake_id,
        accounts: vec![
            AccountMeta::new_readonly(admin.pubkey(), true),
            AccountMeta::new_readonly(s.pool_pda, false),
            AccountMeta::new_readonly(s.vault_auth, false),
            AccountMeta::new(s.market, false),
            AccountMeta::new_readonly(wrapper_id, false),
        ],
        data: vec![19u8],
    };
    send(svm, payer, &[admin], ix).expect("BindInsuranceAuthority must succeed");
}

// ── harness ─────────────────────────────────────────────────────────────────

struct Env {
    svm: LiteSVM,
    wrapper_id: Pubkey,
    stake_id: Pubkey,
    token_program: Pubkey,
    admin: Keypair,
    payer: Keypair,
}

/// Returns None (and the caller skips) when the .so artifacts are absent, so
/// this file behaves like the other cross-program e2e suites in this repo.
fn env() -> Option<Env> {
    if !stake_so().exists() || !wrapper_so().exists() {
        eprintln!(
            "SKIP task13 proxies e2e: .so missing (stake={} wrapper={}) — \
             run `cargo build-sbf` here and `cargo build-sbf --features devnet` \
             in percolator-prog",
            stake_so().display(),
            wrapper_so().display()
        );
        return None;
    }
    let mut svm = LiteSVM::new();
    let wrapper_id = Pubkey::from_str(WRAPPER_MAINNET).unwrap();
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();

    svm.add_program_from_file(wrapper_id, wrapper_so()).unwrap();
    svm.add_program_from_file(stake_id, stake_so()).unwrap();

    let admin = Keypair::new();
    let payer = Keypair::new();
    svm.airdrop(&admin.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();

    Some(Env {
        svm,
        wrapper_id,
        stake_id,
        token_program,
        admin,
        payer,
    })
}

// ════════════════════════════════════════════════════════════════════════════
// GROUP A — wrapper tag 86 UpdateFeeSplit, via stake tag 25 (pool PDA signs)
// ════════════════════════════════════════════════════════════════════════════

/// The full five-step reachability proof for tag 86.
///
/// Step 4 (the direct call failing AFTER InitPool) is what makes this test
/// meaningful: it uses the exact same instruction bytes that succeeded in step
/// 2, so the failure can only come from the marketauth rotation.
#[test]
fn tag86_fee_split_direct_dies_after_initpool_and_proxy_restores_it() {
    let Some(mut e) = env() else { return };

    // 1. real market; admin == marketauth.
    let (market, mint) = build_live_market_v17(
        &mut e.svm,
        e.wrapper_id,
        e.token_program,
        &e.admin,
        &e.payer,
    );
    assert_default_split(&e.svm, &market);

    // 2. CONTROL: the direct wrapper call SUCCEEDS while admin is marketauth.
    //    This pins the tag-86 wire + account layout as correct.
    send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        direct_update_fee_split_ix(e.wrapper_id, e.admin.pubkey(), market, PRE_SPLIT),
    )
    .expect("PRE-STAKE CONTROL: direct UpdateFeeSplit must succeed while admin is marketauth");
    assert_eq!(
        read_split(&e.svm, &market),
        PRE_SPLIT,
        "control call must actually have written the pre-stake split"
    );

    // 3. real InitPool — marketauth genuinely moves to the pool PDA.
    let s = run_init_pool(
        &mut e.svm,
        e.wrapper_id,
        e.stake_id,
        e.token_program,
        &e.admin,
        &e.payer,
        market,
        mint,
    );

    // 4. THE LOAD-BEARING STEP: the identical direct call now FAILS.
    let err = send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        direct_update_fee_split_ix(e.wrapper_id, e.admin.pubkey(), market, POST_SPLIT),
    )
    .expect_err(
        "AFTER StakeInitPool the original admin MUST NOT be able to call wrapper \
         UpdateFeeSplit directly — marketauth is now the pool PDA. If this \
         succeeds, the rotation did not happen and this whole task is moot.",
    );
    eprintln!("tag86 direct-call-after-InitPool rejected with: {err:?}");
    assert_eq!(
        read_split(&e.svm, &market),
        PRE_SPLIT,
        "the rejected direct call must not have mutated the split"
    );

    // 5. the proxy succeeds, and the value actually changes on chain.
    send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        group_a_proxy_ix(
            e.stake_id,
            e.admin.pubkey(),
            s.pool_pda,
            market,
            e.wrapper_id,
            encode_proxy_fee_split(POST_SPLIT),
        ),
    )
    .expect("stake tag 25 proxy must reach wrapper tag 86 by signing as the pool PDA");

    assert_eq!(
        read_split(&e.svm, &market),
        POST_SPLIT,
        "PROXY EFFECT: the on-chain fee split must now equal the proxied value"
    );
    assert_ne!(
        read_split(&e.svm, &market),
        PRE_SPLIT,
        "PROXY EFFECT: the split must have actually moved off its pre-stake value"
    );
}

/// Tag 88 carries a `u128`. The value used here is deliberately larger than
/// `u64::MAX`, so this test fails if the wire is ever narrowed to 8 bytes —
/// either the wrapper rejects the short payload, or a truncated value is
/// stored and the read-back mismatches.
#[test]
fn tag88_maintenance_fee_direct_dies_after_initpool_and_proxy_writes_full_u128() {
    let Some(mut e) = env() else { return };

    let (market, mint) = build_live_market_v17(
        &mut e.svm,
        e.wrapper_id,
        e.token_program,
        &e.admin,
        &e.payer,
    );
    assert_eq!(
        read_u128_at(&e.svm, &market, OFF_MAINTENANCE_FEE_PER_SLOT),
        0,
        "OFFSET SELF-CHECK: InitMarket wrote maintenance_fee_per_slot = 0"
    );

    // A value that cannot survive a u64 round-trip.
    const BIG: u128 = (u64::MAX as u128) + 12_345;
    const PRE_VALUE: u128 = 7;

    // 2. CONTROL: direct call works pre-stake.
    send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        direct_update_maintenance_fee_ix(e.wrapper_id, e.admin.pubkey(), market, PRE_VALUE),
    )
    .expect("PRE-STAKE CONTROL: direct UpdateMaintenanceFeePerSlot must succeed");
    assert_eq!(
        read_u128_at(&e.svm, &market, OFF_MAINTENANCE_FEE_PER_SLOT),
        PRE_VALUE
    );

    // 3. real InitPool.
    let s = run_init_pool(
        &mut e.svm,
        e.wrapper_id,
        e.stake_id,
        e.token_program,
        &e.admin,
        &e.payer,
        market,
        mint,
    );

    // 4. direct call now fails.
    let err = send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        direct_update_maintenance_fee_ix(e.wrapper_id, e.admin.pubkey(), market, BIG),
    )
    .expect_err(
        "AFTER StakeInitPool the direct tag-88 call must fail (marketauth is the pool PDA)",
    );
    eprintln!("tag88 direct-call-after-InitPool rejected with: {err:?}");
    assert_eq!(
        read_u128_at(&e.svm, &market, OFF_MAINTENANCE_FEE_PER_SLOT),
        PRE_VALUE,
        "the rejected direct call must not have mutated the value"
    );

    // 5. proxy succeeds and stores the FULL u128.
    send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        group_a_proxy_ix(
            e.stake_id,
            e.admin.pubkey(),
            s.pool_pda,
            market,
            e.wrapper_id,
            encode_proxy_maintenance_fee(BIG),
        ),
    )
    .expect("stake tag 26 proxy must reach wrapper tag 88 by signing as the pool PDA");

    assert_eq!(
        read_u128_at(&e.svm, &market, OFF_MAINTENANCE_FEE_PER_SLOT),
        BIG,
        "U128 WIRE PROOF: a value above u64::MAX must round-trip exactly. A \
         truncating (u64) encoder cannot produce this."
    );
    assert!(
        read_u128_at(&e.svm, &market, OFF_MAINTENANCE_FEE_PER_SLOT) > u64::MAX as u128,
        "stored value must exceed u64::MAX"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// GROUP B — wrapper tag 51 UpdateBackingFeePolicy, via stake 27 (vault_auth)
// ════════════════════════════════════════════════════════════════════════════

/// THE FEE-SPLIT UNBLOCKER. Wrapper tag 51 sets `backing_trade_fee_bps`. Once
/// `BindInsuranceAuthority` moves asset 0's `insurance_authority` to
/// `vault_auth`, no key on earth can call tag 51 directly — which is precisely
/// why the protocol's fee split was unachievable on a staked market. This test
/// proves the hole exists and that stake tag 27 closes it.
#[test]
fn tag51_backing_fee_direct_dies_after_bind_and_proxy_restores_it() {
    let Some(mut e) = env() else { return };

    let (market, mint) = build_live_market_v17(
        &mut e.svm,
        e.wrapper_id,
        e.token_program,
        &e.admin,
        &e.payer,
    );
    assert_eq!(
        read_u16_at(&e.svm, &market, OFF_BACKING_TRADE_FEE_BPS_LONG),
        0,
        "OFFSET SELF-CHECK: InitMarket sets backing_trade_fee_bps_long = 0"
    );

    const DOMAIN_LONG: u16 = 0; // asset_index = domain / 2 = 0
    const PRE_FEE_BPS: u16 = 11;
    const PRE_INS_SHARE: u16 = 1_000;
    const POST_FEE_BPS: u16 = 25;
    const POST_INS_SHARE: u16 = 3_000;

    // 2. CONTROL: direct call works while admin still holds insurance_authority.
    send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        direct_update_backing_fee_ix(
            e.wrapper_id,
            e.admin.pubkey(),
            market,
            DOMAIN_LONG,
            PRE_FEE_BPS,
            PRE_INS_SHARE,
        ),
    )
    .expect(
        "PRE-BIND CONTROL: direct UpdateBackingFeePolicy must succeed while admin is \
         asset 0's insurance_authority",
    );
    assert_eq!(
        read_u16_at(&e.svm, &market, OFF_BACKING_TRADE_FEE_BPS_LONG),
        PRE_FEE_BPS,
        "control call must actually have written the backing fee"
    );

    // 3. real InitPool + real BindInsuranceAuthority — the authority genuinely moves.
    let s = run_init_pool(
        &mut e.svm,
        e.wrapper_id,
        e.stake_id,
        e.token_program,
        &e.admin,
        &e.payer,
        market,
        mint,
    );
    run_bind_insurance_authority(&mut e.svm, e.wrapper_id, e.stake_id, &e.admin, &e.payer, &s);

    // 4. THE LOAD-BEARING STEP: the identical direct call now FAILS. This is the
    //    state in which "nobody can set the backing fee" was true.
    let err = send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        direct_update_backing_fee_ix(
            e.wrapper_id,
            e.admin.pubkey(),
            market,
            DOMAIN_LONG,
            POST_FEE_BPS,
            POST_INS_SHARE,
        ),
    )
    .expect_err(
        "AFTER BindInsuranceAuthority the original admin MUST NOT be able to call \
         wrapper UpdateBackingFeePolicy directly — insurance_authority is now the \
         vault_auth PDA.",
    );
    eprintln!("tag51 direct-call-after-bind rejected with: {err:?}");
    assert_eq!(
        read_u16_at(&e.svm, &market, OFF_BACKING_TRADE_FEE_BPS_LONG),
        PRE_FEE_BPS,
        "the rejected direct call must not have mutated the backing fee"
    );

    // 5. the proxy succeeds by signing as vault_auth, and the value changes.
    send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        group_b_proxy_ix(
            e.stake_id,
            e.admin.pubkey(),
            s.pool_pda,
            s.vault_auth,
            market,
            e.wrapper_id,
            encode_proxy_backing_fee(DOMAIN_LONG, POST_FEE_BPS, POST_INS_SHARE),
        ),
    )
    .expect(
        "stake tag 27 proxy must reach wrapper tag 51 by signing as vault_auth — \
         this is the instruction that makes the fee split achievable on a staked market",
    );

    assert_eq!(
        read_u16_at(&e.svm, &market, OFF_BACKING_TRADE_FEE_BPS_LONG),
        POST_FEE_BPS,
        "PROXY EFFECT: backing_trade_fee_bps_long must now equal the proxied value"
    );
    assert_ne!(
        read_u16_at(&e.svm, &market, OFF_BACKING_TRADE_FEE_BPS_LONG),
        PRE_FEE_BPS,
        "PROXY EFFECT: the backing fee must have actually moved"
    );
    assert_eq!(
        read_u16_at(&e.svm, &market, OFF_BACKING_INS_SHARE_BPS_LONG),
        POST_INS_SHARE,
        "PROXY EFFECT: the backing insurance share must also be stored"
    );
}

/// Group A (was Group B), wrapper tag 55, via stake tag 28.
///
/// GH#286: IGNORED until percolator-prog is deployed at a commit containing #455.
///
/// This is not flakiness and not a weakened assertion — it is a genuine
/// coordinated-deploy window, and the two sides are mutually exclusive:
///
///   wrapper 15eb8b0c (DEPLOYED, pre-#455)  tag 55 gates on the per-asset
///                                          insurance authority -> vault_auth signs
///   wrapper main      (post-#455)           tag 55 gates on marketauth
///                                          -> the pool PDA signs
///
/// `cpi_update_trade_fee_policy` passes ONE authority account, so the proxy can
/// present exactly one signer. There is no value that satisfies both wrappers.
/// The proxy now signs as the pool PDA, which is correct for the wrapper we are
/// shipping and wrong for the one currently on chain.
///
/// MEASURED, both ways, with fresh `cargo build-sbf -- --features devnet` builds:
///   wrapper origin/main + engine main        8 passed, 0 failed
///   wrapper 15eb8b0c   + engine f53be74a     7 passed, 1 failed (this test)
///
/// stake CI pins the wrapper to WRAPPER_DEPLOYED, so leaving this active would
/// make the trunk red for a reason nobody can fix without a deploy — which is
/// exactly the "permanently red gate nobody reads" failure this repo hit twice
/// this week. Ignoring it with the removal condition stated in-source is the
/// honest form.
///
/// TO REMOVE: when `ci/deployed-refs.env` in percolator-prog advances
/// WRAPPER_DEPLOYED past #455 (0cc58c7c), the #287 drift guard fails and forces
/// this file's pin to be bumped. Delete this attribute in the same commit.
#[test]
#[ignore = "GH#286: needs a wrapper deployed at/after #455; the deployed wrapper \
            gates tag 55 on the per-asset authority, the new one on marketauth, \
            and the proxy can only present one signer"]
fn tag55_trade_fee_direct_dies_after_bind_and_proxy_restores_it() {
    let Some(mut e) = env() else { return };

    let (market, mint) = build_live_market_v17(
        &mut e.svm,
        e.wrapper_id,
        e.token_program,
        &e.admin,
        &e.payer,
    );
    assert_eq!(
        read_u64_at(&e.svm, &market, OFF_TRADE_FEE_BASE_BPS),
        0,
        "OFFSET SELF-CHECK: InitMarket wrote trade_fee_base_bps = 0"
    );

    const PRE_TRADE_FEE: u64 = 13;
    const POST_TRADE_FEE: u64 = 42;

    // 2. CONTROL.
    send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        direct_update_trade_fee_ix(e.wrapper_id, e.admin.pubkey(), market, PRE_TRADE_FEE),
    )
    .expect("PRE-BIND CONTROL: direct UpdateTradeFeePolicy must succeed");
    assert_eq!(
        read_u64_at(&e.svm, &market, OFF_TRADE_FEE_BASE_BPS),
        PRE_TRADE_FEE
    );

    // 3. real InitPool + bind.
    let s = run_init_pool(
        &mut e.svm,
        e.wrapper_id,
        e.stake_id,
        e.token_program,
        &e.admin,
        &e.payer,
        market,
        mint,
    );
    run_bind_insurance_authority(&mut e.svm, e.wrapper_id, e.stake_id, &e.admin, &e.payer, &s);

    // 4. direct call now fails.
    let err = send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        direct_update_trade_fee_ix(e.wrapper_id, e.admin.pubkey(), market, POST_TRADE_FEE),
    )
    .expect_err("AFTER BindInsuranceAuthority the direct tag-55 call must fail");
    eprintln!("tag55 direct-call-after-bind rejected with: {err:?}");
    assert_eq!(
        read_u64_at(&e.svm, &market, OFF_TRADE_FEE_BASE_BPS),
        PRE_TRADE_FEE,
        "the rejected direct call must not have mutated the trade fee"
    );

    // 5. proxy succeeds.
    send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        group_b_proxy_ix(
            e.stake_id,
            e.admin.pubkey(),
            s.pool_pda,
            s.vault_auth,
            market,
            e.wrapper_id,
            encode_proxy_trade_fee(POST_TRADE_FEE),
        ),
    )
    .expect("stake tag 28 proxy must reach wrapper tag 55 by signing as vault_auth");

    assert_eq!(
        read_u64_at(&e.svm, &market, OFF_TRADE_FEE_BASE_BPS),
        POST_TRADE_FEE,
        "PROXY EFFECT: trade_fee_base_bps must now equal the proxied value"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// ORDERING, AUTHORITY, AND BINDING NEGATIVES
// ════════════════════════════════════════════════════════════════════════════

/// The Group B proxies RESTORE a capability rather than transfer one: before
/// `BindInsuranceAuthority`, `vault_auth` is not yet `insurance_authority`, so
/// the proxy cannot work and the human admin does not need it. This pins that
/// ordering so nobody "fixes" the proxy to work pre-bind by weakening a check.
#[test]
fn group_b_proxy_fails_before_bind_because_vault_auth_is_not_yet_the_authority() {
    let Some(mut e) = env() else { return };

    let (market, mint) = build_live_market_v17(
        &mut e.svm,
        e.wrapper_id,
        e.token_program,
        &e.admin,
        &e.payer,
    );
    let s = run_init_pool(
        &mut e.svm,
        e.wrapper_id,
        e.stake_id,
        e.token_program,
        &e.admin,
        &e.payer,
        market,
        mint,
    );
    // NOTE: BindInsuranceAuthority deliberately NOT called.

    let err = send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        group_b_proxy_ix(
            e.stake_id,
            e.admin.pubkey(),
            s.pool_pda,
            s.vault_auth,
            market,
            e.wrapper_id,
            encode_proxy_backing_fee(0, 25, 3_000),
        ),
    )
    .expect_err(
        "before BindInsuranceAuthority, vault_auth is NOT asset 0's insurance_authority, \
         so the wrapper must reject the proxied CPI",
    );
    eprintln!("group-B proxy before bind rejected with: {err:?}");
    // The WRAPPER refuses (stake's own checks all pass — the pool and vault_auth
    // are genuine); this is what "restores rather than transfers" looks like.
    assert_custom_err(
        &err,
        WRAPPER_ERR_UNAUTHORIZED,
        "pre-bind group-B proxy must be refused by the WRAPPER's authority gate",
    );

    assert_eq!(
        read_u16_at(&e.svm, &market, OFF_BACKING_TRADE_FEE_BPS_LONG),
        0,
        "a rejected pre-bind proxy must leave the backing fee untouched"
    );
}

/// Authority model: all four proxies are gated on `pool.admin`, mirroring
/// `AdminResolveMarket`. A stranger holding no role must not be able to rewrite
/// a market's fee policy through them.
#[test]
fn proxies_reject_a_non_admin_signer() {
    let Some(mut e) = env() else { return };

    let (market, mint) = build_live_market_v17(
        &mut e.svm,
        e.wrapper_id,
        e.token_program,
        &e.admin,
        &e.payer,
    );
    let s = run_init_pool(
        &mut e.svm,
        e.wrapper_id,
        e.stake_id,
        e.token_program,
        &e.admin,
        &e.payer,
        market,
        mint,
    );
    run_bind_insurance_authority(&mut e.svm, e.wrapper_id, e.stake_id, &e.admin, &e.payer, &s);

    let stranger = Keypair::new();
    e.svm.airdrop(&stranger.pubkey(), 100_000_000_000).unwrap();

    // Group A (tag 25).
    let e25 = send(
        &mut e.svm,
        &e.payer,
        &[&stranger],
        group_a_proxy_ix(
            e.stake_id,
            stranger.pubkey(),
            s.pool_pda,
            market,
            e.wrapper_id,
            encode_proxy_fee_split(POST_SPLIT),
        ),
    )
    .expect_err("tag 25 must reject a signer that is not pool.admin");
    assert_custom_err(&e25, STAKE_ERR_UNAUTHORIZED, "tag 25 non-admin");

    // Group A (tag 26).
    let e26 = send(
        &mut e.svm,
        &e.payer,
        &[&stranger],
        group_a_proxy_ix(
            e.stake_id,
            stranger.pubkey(),
            s.pool_pda,
            market,
            e.wrapper_id,
            encode_proxy_maintenance_fee(999),
        ),
    )
    .expect_err("tag 26 must reject a signer that is not pool.admin");
    assert_custom_err(&e26, STAKE_ERR_UNAUTHORIZED, "tag 26 non-admin");

    // Group B (tag 27) — the fee-split-critical one.
    let e27 = send(
        &mut e.svm,
        &e.payer,
        &[&stranger],
        group_b_proxy_ix(
            e.stake_id,
            stranger.pubkey(),
            s.pool_pda,
            s.vault_auth,
            market,
            e.wrapper_id,
            encode_proxy_backing_fee(0, 25, 3_000),
        ),
    )
    .expect_err("tag 27 must reject a signer that is not pool.admin");
    assert_custom_err(&e27, STAKE_ERR_UNAUTHORIZED, "tag 27 non-admin");

    // Group B (tag 28).
    let e28 = send(
        &mut e.svm,
        &e.payer,
        &[&stranger],
        group_b_proxy_ix(
            e.stake_id,
            stranger.pubkey(),
            s.pool_pda,
            s.vault_auth,
            market,
            e.wrapper_id,
            encode_proxy_trade_fee(42),
        ),
    )
    .expect_err("tag 28 must reject a signer that is not pool.admin");
    assert_custom_err(&e28, STAKE_ERR_UNAUTHORIZED, "tag 28 non-admin");

    // Nothing moved.
    assert_eq!(
        read_split(&e.svm, &market),
        (
            DEFAULT_CREATOR_SHARE_BPS,
            DEFAULT_LP_SHARE_BPS,
            DEFAULT_INSURANCE_SHARE_BPS
        ),
        "no rejected proxy may mutate the fee split"
    );
    assert_eq!(
        read_u16_at(&e.svm, &market, OFF_BACKING_TRADE_FEE_BPS_LONG),
        0,
        "no rejected proxy may mutate the backing fee"
    );
    assert_eq!(
        read_u64_at(&e.svm, &market, OFF_TRADE_FEE_BASE_BPS),
        0,
        "no rejected proxy may mutate the trade fee"
    );
    assert_eq!(
        read_u128_at(&e.svm, &market, OFF_MAINTENANCE_FEE_PER_SLOT),
        0,
        "no rejected proxy may mutate the maintenance fee"
    );
}

/// The proxies bind their CPI to `pool.slab`, so a validly-signed proxy cannot
/// be aimed at a different market. Mirrors `AdminResolveMarket`'s slab check.
#[test]
fn proxy_rejects_a_slab_that_is_not_the_pools_own_market() {
    let Some(mut e) = env() else { return };

    let (market_a, mint_a) = build_live_market_v17(
        &mut e.svm,
        e.wrapper_id,
        e.token_program,
        &e.admin,
        &e.payer,
    );
    let s = run_init_pool(
        &mut e.svm,
        e.wrapper_id,
        e.stake_id,
        e.token_program,
        &e.admin,
        &e.payer,
        market_a,
        mint_a,
    );

    // A second, unrelated market the same admin also controls.
    let (market_b, _mint_b) = build_live_market_v17(
        &mut e.svm,
        e.wrapper_id,
        e.token_program,
        &e.admin,
        &e.payer,
    );
    assert_default_split(&e.svm, &market_b);
    let err = send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        group_a_proxy_ix(
            e.stake_id,
            e.admin.pubkey(),
            s.pool_pda, // pool for market_a
            market_b,   // but aimed at market_b
            e.wrapper_id,
            encode_proxy_fee_split(POST_SPLIT),
        ),
    )
    .expect_err("the proxy must reject a slab that is not pool.slab");

    // MUST be STAKE's InvalidPda, not the wrapper's Unauthorized. If stake's own
    // `pool.slab` check were removed, this call would still fail — the wrapper
    // would reject the mis-derived PDA — and a bare expect_err would stay green
    // while the guard was gone. Pinning the code makes this test actually test
    // the guard. (The wrapper's rejection is only incidental here because
    // market_b's pool bump happens to differ; it is not a guarantee.)
    assert_custom_err(
        &err,
        STAKE_ERR_INVALID_PDA,
        "foreign slab must be refused by the STAKE program's pool.slab binding, \
         before any CPI is attempted",
    );

    assert_default_split(&e.svm, &market_b);
}

// ════════════════════════════════════════════════════════════════════════════
// WRAPPER TAG 69 — deliberately NOT proxied; this pins the reasoning
// ════════════════════════════════════════════════════════════════════════════

/// Wrapper tag 69 `RestartAssetOracle` is gated on the per-asset `asset_admin`.
/// This program moves `asset_admin` to exactly one place — `[0u8; 32]`, via
/// `BurnAssetAdmin` (tag 21). It never rotates it to `vault_auth` or the pool
/// PDA. The wrapper gates with `expect_live_authority`, whose
/// `live_authority_matches` requires `expected != [0u8; 32]`, so a burned
/// `asset_admin` matches NO signer at all.
///
/// Consequently a tag-69 proxy would be dead code in both reachable states:
///   * pre-burn, `asset_admin == pool.admin` — a real keypair that calls tag 69
///     directly and needs no proxy (and a vault_auth-signed proxy would be
///     rejected, since vault_auth != asset_admin);
///   * post-burn, `asset_admin == [0;32]` — nothing can satisfy the gate.
///
/// This test demonstrates BOTH halves behaviourally, after the real
/// InitPool + Bind + Burn sequence, using tag 65 — which shares exactly the same
/// `expect_live_authority(asset_admin, ...)` gate as tag 69.
///
/// UPDATED for wrapper #416/#417 + #437/#439, both of which are in the DEPLOYED
/// wrapper. `handle_update_asset_authority` used to let a live `asset_admin`
/// rotate ANY of the asset's authorities, and this test's pre-burn step was a
/// CONTROL that relied on exactly that bypass succeeding. The guard is now an
/// allow-list of STATES rather than of kinds:
///
///     admin_bypass_permitted = admin_signed
///         && (current_value == [0u8; 32] || <unsignable LP-registry PDA>)
///
/// so the bypass survives only where there is no holder to defend. The old
/// control therefore asserts behaviour the wrapper deliberately removed, and it
/// broke percolator-stake CI when that change reached `main`.
///
/// Rather than delete the control — which would leave both rejections
/// indistinguishable from a malformed instruction — the test now:
///   1. keeps a POSITIVE CONTROL, the current holder self-rotating, so the call
///      path is proven live;
///   2. asserts the pre-burn rejection EXPLICITLY, pinning the inversion; and
///   3. keeps the post-burn rejection, which since #437/#439 is a second
///      independent reason rather than the cause.
///
/// Net effect: this pins strictly more behaviour than before, and no longer
/// depends on a bypass that no longer exists.
///
/// Restoring tag 69 after a burn requires a WRAPPER change, which is out of
/// scope for this task. If that ever lands, add the proxy and delete this test.
#[test]
fn tag69_restart_asset_oracle_is_not_proxyable_after_asset_admin_burn() {
    let Some(mut e) = env() else { return };

    let (market, mint) = build_live_market_v17(
        &mut e.svm,
        e.wrapper_id,
        e.token_program,
        &e.admin,
        &e.payer,
    );
    let s = run_init_pool(
        &mut e.svm,
        e.wrapper_id,
        e.stake_id,
        e.token_program,
        &e.admin,
        &e.payer,
        market,
        mint,
    );
    run_bind_insurance_authority(&mut e.svm, e.wrapper_id, e.stake_id, &e.admin, &e.payer, &s);

    // POSITIVE CONTROL: prove this instruction, these accounts and this signer
    // actually work, by having the CURRENT HOLDER self-rotate. `oracle_authority`
    // is still admin's after InitPool + bind, so this goes through
    // `expect_live_authority` on the ordinary holder-consent path and never
    // touches the asset_admin bypass.
    //
    // Without this the two rejections below would be indistinguishable from a
    // malformed instruction that could never have succeeded — which is precisely
    // how the old PRE-BURN CONTROL earned its keep, and why replacing it with
    // nothing was not an option.
    send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        direct_update_asset_authority_ix(
            e.wrapper_id,
            e.admin.pubkey(),
            e.admin.pubkey(), // self-rotate oracle_authority: holder consents
            market,
            4, // kind = oracle_authority, still held by admin
        ),
    )
    .expect(
        "POSITIVE CONTROL: the current holder must be able to self-rotate — if this \
         fails the rejections below prove nothing about asset_admin",
    );

    // PRE-BURN: asset_admin is LIVE and equals admin, and it still cannot rotate an
    // authority someone else holds.
    //
    // This assertion is the inverse of what this test asserted before wrapper
    // #416/#417 and #437/#439. `handle_update_asset_authority` used to let
    // asset_admin rotate ANY of the asset's authorities; the guard is now an
    // allow-list of STATES rather than of kinds —
    //
    //     admin_bypass_permitted = admin_signed
    //         && (current_value == [0u8; 32] || <unsignable LP-registry PDA>)
    //
    // — so the bypass survives only where there is NO HOLDER TO DEFEND. The
    // wrapper's own note: "The insurance legs have already paid that price since
    // #416/#417; this makes it uniform across all five kinds."
    //
    // `BindInsuranceAuthority` has moved insurance_operator to vault_auth, so it IS
    // held, and admin is refused despite being asset_admin.
    send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        direct_update_asset_authority_ix(
            e.wrapper_id,
            e.admin.pubkey(),
            e.admin.pubkey(),
            market,
            2, // kind = insurance_operator, held by vault_auth
        ),
    )
    .expect_err(
        "PRE-BURN: asset_admin must NOT be able to seize a HELD authority — this is \
         the #416/#417 + #437/#439 inversion, and it is in the DEPLOYED wrapper",
    );

    // `insurance_authority` (kind 1) is also still vault_auth and admin does not
    // hold it, so the post-burn attempt below targets THAT.

    // Burn asset_admin to [0;32] via the real stake instruction (tag 21).
    let burn_ix = Instruction {
        program_id: e.stake_id,
        accounts: vec![
            AccountMeta::new(e.admin.pubkey(), true),
            AccountMeta::new(s.pool_pda, false),
            AccountMeta::new_readonly(s.vault_auth, false),
            AccountMeta::new(market, false),
            AccountMeta::new_readonly(e.wrapper_id, false),
        ],
        data: vec![21u8],
    };
    send(&mut e.svm, &e.payer, &[&e.admin], burn_ix).expect("BurnAssetAdmin must succeed");

    // POST-BURN: still rejected, now for a SECOND independent reason. asset_admin
    // is [0;32], so `admin_signed` is false outright, and `live_authority_matches`
    // refuses a zero authority for every signer — a vault_auth-signed CPI included.
    //
    // Note honestly what this does and does not show. Since #437/#439 the burn is
    // no longer what makes this call fail: the PRE-BURN assertion above proves it
    // already failed while asset_admin was live. The burn removes the remaining
    // path rather than the only one. That is why the pre-burn case is now asserted
    // explicitly instead of being left as a control — otherwise this rejection
    // would look like it was caused by the burn, and it is not.
    //
    // The conclusion the test exists for is unchanged and is now established by
    // both halves together: there is no signer a tag-69 proxy could present that
    // would pass, which is why none is shipped.
    let err = send(
        &mut e.svm,
        &e.payer,
        &[&e.admin],
        direct_update_asset_authority_ix(
            e.wrapper_id,
            e.admin.pubkey(),
            e.admin.pubkey(),
            market,
            1, // kind = insurance_authority, still held by vault_auth
        ),
    )
    .expect_err(
        "AFTER BurnAssetAdmin, asset_admin == [0;32], so the admin_signed bypass is \
         gone and expect_live_authority(insurance_authority=vault_auth, admin) \
         rejects. The same zero-authority rule is what gates wrapper tag 69 on \
         asset_admin — a tag-69 proxy signing as vault_auth would fail here too, \
         which is why none is shipped.",
    );
    eprintln!("post-burn asset_admin-gated call rejected with: {err:?}");

    // And pin that this program exposes no tag-69 proxy: 29 is unallocated.
    // If someone adds one, this assertion is the prompt to revisit the analysis
    // in instruction.rs's module doc.
    let bogus = Instruction {
        program_id: e.stake_id,
        accounts: vec![
            AccountMeta::new_readonly(e.admin.pubkey(), true),
            AccountMeta::new_readonly(s.pool_pda, false),
            AccountMeta::new(market, false),
            AccountMeta::new_readonly(e.wrapper_id, false),
        ],
        data: vec![29u8],
    };
    send(&mut e.svm, &e.payer, &[&e.admin], bogus)
        .expect_err("stake tag 29 must be unallocated — no tag-69 proxy exists");
}
