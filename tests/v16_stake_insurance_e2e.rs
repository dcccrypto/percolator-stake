//! Assembled LiteSVM end-to-end test for the v16 insurance-flush re-bind.
//!
//! Loads BOTH on-chain programs into one LiteSVM instance:
//! the percolator-stake .so (this crate, solana-program 2.2.1) at STAKE_ID, and
//! the v16 wrapper .so (percolator-prog, solana-program 1.18) at WRAPPER_MAINNET.
//! Drives the real cross-program path: InitMarket (wrapper) then
//! BindInsuranceAuthority (stake CPIs wrapper UpdateAuthority) then
//! FlushToInsurance (stake CPIs wrapper TopUpInsurance).
//!
//! This is the test the stake crate's pure-struct suite CANNOT provide: it
//! exercises the actual u128 wire, the authority binding, and Live-mode gate
//! across the program boundary, and would have caught the pre-v16 8-byte break.
//!
//! Decoding note: we deliberately do not dev-depend on percolator-prog to decode
//! the wrapper's market state (its solana 1.18 curve25519-dalek/zeroize tree is
//! unresolvable against our solana 2.2 graph). The "flush applied" proof is the
//! REAL SPL token movement (stake vault -> wrapper vault): the v16 handler
//! transfers tokens only AFTER it credits group.header.insurance and runs
//! validate_shape (v16_program.rs:7602/7640/7647), so an observed token transfer
//! into the wrapper vault proves the insurance credit succeeded atomically.
//!
//! AUD-T2-3 (2026-10-18): the three flush / re-bind tests on the v16 3107 B market layout were
//! permanently `#[ignore]`d (v5 answers tags 3 and 23 with DeprecatedV5 = 34) and have been
//! deleted. First-loss behaviour is covered by tests/v5_first_loss.rs and the wrapper
//! p4_wave_d cross-program tests.

use bytemuck::Zeroable;
use litesvm::LiteSVM;
use percolator_stake::state::{
    derive_pool_pda, StakePool, STAKE_POOL_SIZE,
};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
    transaction::{Transaction, TransactionError},
};
use std::path::PathBuf;
use std::str::FromStr;

// v16 wrapper mainnet program id (stake's InitPool allowlist requires this id;
// we load the wrapper here so the stake pool's percolator_program check passes).
const WRAPPER_MAINNET: &str = "ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv";
// stake program id (target/deploy/percolator_stake-keypair.json).
const STAKE_ID: &str = "9tbLt8fs1C7cJRXAyiGY7Ub88AT7MLWpxLqFNVCkqzA6";
// classic SPL Token program id (loaded by with_spl_programs; wrapper's
// verify_token_program requires exactly this key).

// Pinned against the LOCKED wrapper baseline (v16-wrapper-sync-phase2b-tier3-complete
// @5260d1b): market_account_len_for_capacity(1) measured = 3107.
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;

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

// ── SPL Token data, hand-packed (stable layouts) ───────────────────────────

// ── Wrapper InitMarket (tag 0) — hand-encoded to match ix::Instruction::encode
//    (v16_program.rs:2826-2874). Default V16CuMarketParams (v16_cu.rs:229-255). ─

fn encode_init_market_default() -> Vec<u8> {
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
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &all,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn smoke_both_programs_load() {
    let stake_path = stake_so();
    let wrapper_path = wrapper_so();
    assert!(
        stake_path.exists(),
        "stake .so missing — run cargo build-sbf"
    );
    assert!(
        wrapper_path.exists(),
        "wrapper .so missing — build ../percolator-prog"
    );
    let mut svm = LiteSVM::new().with_spl_programs();
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
    let wrapper_id = Pubkey::from_str(WRAPPER_MAINNET).unwrap();
    svm.add_program_from_file(stake_id, stake_path).unwrap();
    svm.add_program_from_file(wrapper_id, wrapper_path).unwrap();
    assert!(svm.get_account(&stake_id).unwrap().executable);
    assert!(svm.get_account(&wrapper_id).unwrap().executable);
}

#[test]
fn init_market_wire_is_219_bytes() {
    // Self-check: our hand-encoded InitMarket matches the wrapper's encoder length.
    assert_eq!(encode_init_market_default().len(), 219);
}

// ── Two-step admin rotation (finding #4) — runtime, through the real program ──
// Rotation only touches the pool PDA (no market/CPI), so we use a minimal pool.

/// Load the stake program and craft a version-2 StakePool owned by it with the
/// given admin. Returns (svm, stake_id, pool_pda).
fn setup_pool_only(admin: &Pubkey) -> (LiteSVM, Pubkey, Pubkey) {
    let mut svm = LiteSVM::new();
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
    svm.add_program_from_file(stake_id, stake_so()).unwrap();
    let slab = Pubkey::new_unique();
    let (pool_pda, _) = derive_pool_pda(&stake_id, &slab);
    let mut pool = StakePool::zeroed();
    pool.is_initialized = 1;
    pool.bump = 255;
    pool.slab = slab.to_bytes();
    pool.admin = admin.to_bytes();
    pool.set_discriminator(); // discriminator + CURRENT_VERSION (2)
    let mut bytes = vec![0u8; STAKE_POOL_SIZE];
    bytes.copy_from_slice(bytemuck::bytes_of(&pool));
    svm.set_account(
        pool_pda,
        Account {
            lamports: 1_000_000_000,
            data: bytes,
            owner: stake_id,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    (svm, stake_id, pool_pda)
}

fn pool_admin(svm: &LiteSVM, pool_pda: &Pubkey) -> [u8; 32] {
    let data = svm.get_account(pool_pda).unwrap().data;
    let pool: &StakePool = bytemuck::from_bytes(&data[..STAKE_POOL_SIZE]);
    pool.admin
}

fn propose_ix(
    stake_id: Pubkey,
    pool_pda: Pubkey,
    admin: &Pubkey,
    new_admin: [u8; 32],
) -> Instruction {
    let mut data = vec![5u8];
    data.extend_from_slice(&new_admin);
    Instruction {
        program_id: stake_id,
        accounts: vec![
            AccountMeta::new_readonly(*admin, true),
            AccountMeta::new(pool_pda, false),
        ],
        data,
    }
}

fn accept_ix(stake_id: Pubkey, pool_pda: Pubkey, new_admin: &Pubkey) -> Instruction {
    Instruction {
        program_id: stake_id,
        accounts: vec![
            AccountMeta::new_readonly(*new_admin, true),
            AccountMeta::new(pool_pda, false),
        ],
        data: vec![6u8],
    }
}

#[test]
fn two_step_admin_rotation_happy_path() {
    let admin = Keypair::new();
    let new_admin = Keypair::new();
    let payer = Keypair::new();
    let (mut svm, stake_id, pool_pda) = setup_pool_only(&admin.pubkey());
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    // propose (current admin signs)
    send(
        &mut svm,
        &payer,
        &[&admin],
        propose_ix(
            stake_id,
            pool_pda,
            &admin.pubkey(),
            new_admin.pubkey().to_bytes(),
        ),
    )
    .expect("ProposeAdmin");
    assert_eq!(
        pool_admin(&svm, &pool_pda),
        admin.pubkey().to_bytes(),
        "admin unchanged until accept"
    );

    // accept (pending admin signs) -> rotation
    send(
        &mut svm,
        &payer,
        &[&new_admin],
        accept_ix(stake_id, pool_pda, &new_admin.pubkey()),
    )
    .expect("AcceptAdmin");
    assert_eq!(
        pool_admin(&svm, &pool_pda),
        new_admin.pubkey().to_bytes(),
        "admin rotated"
    );

    // old admin can no longer propose (Unauthorized=2)
    let err = send(
        &mut svm,
        &payer,
        &[&admin],
        propose_ix(
            stake_id,
            pool_pda,
            &admin.pubkey(),
            admin.pubkey().to_bytes(),
        ),
    )
    .expect_err("old admin must be rejected");
    assert!(matches!(
        err,
        TransactionError::InstructionError(_, InstructionError::Custom(2))
    ));
}

#[test]
fn accept_by_non_pending_signer_rejected() {
    let admin = Keypair::new();
    let new_admin = Keypair::new();
    let attacker = Keypair::new();
    let payer = Keypair::new();
    let (mut svm, stake_id, pool_pda) = setup_pool_only(&admin.pubkey());
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    send(
        &mut svm,
        &payer,
        &[&admin],
        propose_ix(
            stake_id,
            pool_pda,
            &admin.pubkey(),
            new_admin.pubkey().to_bytes(),
        ),
    )
    .expect("ProposeAdmin");

    // attacker (not the pending admin) tries to accept -> Unauthorized=2
    let err = send(
        &mut svm,
        &payer,
        &[&attacker],
        accept_ix(stake_id, pool_pda, &attacker.pubkey()),
    )
    .expect_err("non-pending signer must be rejected");
    assert!(matches!(
        err,
        TransactionError::InstructionError(_, InstructionError::Custom(2))
    ));
    assert_eq!(
        pool_admin(&svm, &pool_pda),
        admin.pubkey().to_bytes(),
        "admin unchanged"
    );
}

#[test]
fn accept_with_no_pending_rejected() {
    let admin = Keypair::new();
    let payer = Keypair::new();
    let (mut svm, stake_id, pool_pda) = setup_pool_only(&admin.pubkey());
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    // no proposal outstanding -> AcceptAdmin reverts NoPendingAdmin=23
    let err = send(
        &mut svm,
        &payer,
        &[&admin],
        accept_ix(stake_id, pool_pda, &admin.pubkey()),
    )
    .expect_err("accept with no pending must revert");
    assert!(matches!(
        err,
        TransactionError::InstructionError(_, InstructionError::Custom(23))
    ));
}

#[test]
fn propose_zero_cancels_pending() {
    let admin = Keypair::new();
    let new_admin = Keypair::new();
    let payer = Keypair::new();
    let (mut svm, stake_id, pool_pda) = setup_pool_only(&admin.pubkey());
    svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();

    send(
        &mut svm,
        &payer,
        &[&admin],
        propose_ix(
            stake_id,
            pool_pda,
            &admin.pubkey(),
            new_admin.pubkey().to_bytes(),
        ),
    )
    .expect("ProposeAdmin");
    // cancel by proposing the zero pubkey
    send(
        &mut svm,
        &payer,
        &[&admin],
        propose_ix(stake_id, pool_pda, &admin.pubkey(), [0u8; 32]),
    )
    .expect("ProposeAdmin(zero) cancels");

    // the previously-proposed admin can no longer accept -> NoPendingAdmin=23
    let err = send(
        &mut svm,
        &payer,
        &[&new_admin],
        accept_ix(stake_id, pool_pda, &new_admin.pubkey()),
    )
    .expect_err("accept after cancel must revert");
    assert!(matches!(
        err,
        TransactionError::InstructionError(_, InstructionError::Custom(23))
    ));
}

// ── No-lockout: rotate the insurance authority off the PDA + re-bind from a
//    "redeployed" stake program (new program id => new vault_auth PDA) ──────────
