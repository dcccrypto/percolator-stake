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

use bytemuck::Zeroable;
use litesvm::LiteSVM;
use percolator_stake::state::{
    derive_pool_pda, derive_vault_authority, StakePool, STAKE_POOL_SIZE,
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
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

// Pinned against the LOCKED wrapper baseline (v16-wrapper-sync-phase2b-tier3-complete
// @5260d1b): market_account_len_for_capacity(1) measured = 3107.
const MARKET_LEN_CAP1: usize = 3107;
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;

const FLUSH_AMOUNT: u64 = 250_000;

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

/// 82-byte SPL Mint: authority None, supply 0, decimals 0, initialized, no freeze.
fn mint_data() -> Vec<u8> {
    let mut d = vec![0u8; 82];
    // mint_authority COption<Pubkey> [0..36] = None (already zero)
    // supply u64 [36..44] = 0
    d[44] = 0; // decimals
    d[45] = 1; // is_initialized = true
               // freeze_authority COption<Pubkey> [46..82] = None (zero)
    d
}

/// 165-byte SPL token account: given mint, owner, amount; no delegate/native/close.
fn token_data(mint: &Pubkey, owner: &Pubkey, amount: u64) -> Vec<u8> {
    let mut d = vec![0u8; 165];
    d[0..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    // delegate COption [72..108] = None
    d[108] = 1; // state = Initialized
                // is_native COption<u64> [109..121] = None
                // delegated_amount u64 [121..129] = 0
                // close_authority COption [129..165] = None
    d
}

/// Read an SPL token account's `amount` (offset 64..72) from raw account data.
fn token_amount(svm: &LiteSVM, key: &Pubkey) -> u64 {
    let acct = svm.get_account(key).expect("token account exists");
    u64::from_le_bytes(acct.data[64..72].try_into().unwrap())
}

fn set_token_account(svm: &mut LiteSVM, key: Pubkey, mint: &Pubkey, owner: &Pubkey, amount: u64) {
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    svm.set_account(
        key,
        Account {
            lamports: 1_000_000_000,
            data: token_data(mint, owner, amount),
            owner: token_program,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

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

// ── Shared harness ──────────────────────────────────────────────────────────

struct Env {
    svm: LiteSVM,
    stake_id: Pubkey,
    wrapper_id: Pubkey,
    token_program: Pubkey,
    admin: Keypair,
    payer: Keypair,
    market: Pubkey,
    #[allow(dead_code)]
    mint: Pubkey,
    wrapper_vault: Pubkey,
    pool_pda: Pubkey,
    vault_auth: Pubkey,
    stake_vault: Pubkey,
}

impl Env {
    /// Build a Live v16 market + a crafted stake pool with a funded stake vault.
    /// Does NOT bind the insurance authority (callers choose to or not).
    fn setup() -> Self {
        let mut svm = LiteSVM::new().with_spl_programs();
        let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
        let wrapper_id = Pubkey::from_str(WRAPPER_MAINNET).unwrap();
        let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        svm.add_program_from_file(stake_id, stake_so()).unwrap();
        svm.add_program_from_file(wrapper_id, wrapper_so())
            .unwrap();

        let payer = Keypair::new();
        let admin = Keypair::new();
        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
        svm.airdrop(&admin.pubkey(), 10_000_000_000).unwrap();

        let market = Pubkey::new_unique();
        let mint = Pubkey::new_unique();

        // collateral mint
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

        // wrapper vault token account: owner = wrapper vault authority [b"vault", market]
        let wrapper_vault_auth =
            Pubkey::find_program_address(&[b"vault", market.as_ref()], &wrapper_id).0;
        let wrapper_vault = Pubkey::new_unique();
        set_token_account(&mut svm, wrapper_vault, &mint, &wrapper_vault_auth, 0);

        // preallocate the market account (wrapper-owned, exact length) and InitMarket.
        svm.set_account(
            market,
            Account {
                lamports: 1_000_000_000,
                data: vec![0u8; MARKET_LEN_CAP1],
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
            data: encode_init_market_default(),
        };
        send(&mut svm, &payer, &[&admin], init_ix).expect("InitMarket");

        // stake pool PDAs (under STAKE_ID) + funded stake vault
        let (pool_pda, _) = derive_pool_pda(&stake_id, &market);
        let (vault_auth, vault_auth_bump) = derive_vault_authority(&stake_id, &pool_pda);
        let stake_vault = Pubkey::new_unique();
        set_token_account(&mut svm, stake_vault, &mint, &vault_auth, FLUSH_AMOUNT);

        // craft the StakePool account (insurance LP mode, version 2)
        let mut pool = StakePool::zeroed();
        pool.is_initialized = 1;
        pool.bump = 255;
        pool.vault_authority_bump = vault_auth_bump;
        pool.slab = market.to_bytes();
        pool.admin = admin.pubkey().to_bytes();
        pool.collateral_mint = mint.to_bytes();
        pool.lp_mint = Pubkey::new_unique().to_bytes();
        pool.vault = stake_vault.to_bytes();
        pool.total_deposited = FLUSH_AMOUNT; // available for flush = FLUSH_AMOUNT
        pool.percolator_program = wrapper_id.to_bytes();
        pool.pool_mode = 0; // insurance LP (flush only valid here)
        pool.set_discriminator(); // writes discriminator + CURRENT_VERSION (2)
        let mut pool_bytes = vec![0u8; STAKE_POOL_SIZE];
        pool_bytes.copy_from_slice(bytemuck::bytes_of(&pool));
        svm.set_account(
            pool_pda,
            Account {
                lamports: 1_000_000_000,
                data: pool_bytes,
                owner: stake_id,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();

        Env {
            svm,
            stake_id,
            wrapper_id,
            token_program,
            admin,
            payer,
            market,
            mint,
            wrapper_vault,
            pool_pda,
            vault_auth,
            stake_vault,
        }
    }

    /// stake BindInsuranceAuthority (tag 19) — binds cfg.insurance_authority = vault_auth PDA.
    fn bind_ix(&self) -> Instruction {
        Instruction {
            program_id: self.stake_id,
            accounts: vec![
                AccountMeta::new(self.admin.pubkey(), true),
                AccountMeta::new_readonly(self.pool_pda, false),
                AccountMeta::new_readonly(self.vault_auth, false),
                AccountMeta::new(self.market, false),
                AccountMeta::new_readonly(self.wrapper_id, false),
            ],
            data: vec![19u8],
        }
    }

    /// stake FlushToInsurance (tag 3 + u64 amount).
    fn flush_ix(&self, amount: u64) -> Instruction {
        let mut data = vec![3u8];
        data.extend_from_slice(&amount.to_le_bytes());
        Instruction {
            program_id: self.stake_id,
            accounts: vec![
                AccountMeta::new(self.admin.pubkey(), true), // caller (admin-gated)
                AccountMeta::new(self.pool_pda, false),      // pool
                AccountMeta::new(self.stake_vault, false),   // vault (source)
                AccountMeta::new_readonly(self.vault_auth, false), // vault_auth (CPI signer)
                AccountMeta::new(self.market, false),        // slab/market
                AccountMeta::new(self.wrapper_vault, false), // wrapper vault (dest)
                AccountMeta::new_readonly(self.wrapper_id, false), // percolator program
                AccountMeta::new_readonly(self.token_program, false),
            ],
            data,
        }
    }
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
    svm.add_program_from_file(wrapper_id, wrapper_path)
        .unwrap();
    assert!(svm.get_account(&stake_id).unwrap().executable);
    assert!(svm.get_account(&wrapper_id).unwrap().executable);
}

#[test]
fn init_market_wire_is_219_bytes() {
    // Self-check: our hand-encoded InitMarket matches the wrapper's encoder length.
    assert_eq!(encode_init_market_default().len(), 219);
}

/// HAPPY PATH: bind the insurance authority, then flush. The flush moves real
/// SPL tokens stake_vault -> wrapper_vault, which (per the v16 handler ordering)
/// proves the insurance credit + validate_shape succeeded across the boundary.
#[test]
fn flush_applies_insurance_after_bind() {
    let mut env = Env::setup();

    // 1) bind cfg.insurance_authority = vault_auth PDA (stake CPIs UpdateAuthority).
    let bind = env.bind_ix();
    send(&mut env.svm, &env.payer, &[&env.admin], bind).expect("BindInsuranceAuthority");

    // pre-balances
    assert_eq!(token_amount(&env.svm, &env.stake_vault), FLUSH_AMOUNT);
    assert_eq!(token_amount(&env.svm, &env.wrapper_vault), 0);

    // 2) flush (stake CPIs TopUpInsurance with the 16-byte u128 wire).
    let flush = env.flush_ix(FLUSH_AMOUNT);
    send(&mut env.svm, &env.payer, &[&env.admin], flush).expect("FlushToInsurance");

    // 3) APPLIED proof: tokens actually moved into the wrapper insurance vault.
    assert_eq!(
        token_amount(&env.svm, &env.stake_vault),
        0,
        "stake vault drained by the flush"
    );
    assert_eq!(
        token_amount(&env.svm, &env.wrapper_vault),
        FLUSH_AMOUNT,
        "wrapper insurance vault received the full amount (credit + transfer are atomic)"
    );
}

/// NEGATIVE: WITHOUT the bind, cfg.insurance_authority is still `admin`, but the
/// CPI signer is the vault_auth PDA -> the wrapper rejects at the OPERATIVE
/// authority gate with Custom(8) Unauthorized. Must NOT be Custom(21)
/// EngineLockActive (market is Live) nor InvalidInstructionData (wire is 16-byte).
#[test]
fn flush_unbound_authority_rejected_with_unauthorized() {
    let mut env = Env::setup();
    // deliberately skip bind_ix
    let flush = env.flush_ix(FLUSH_AMOUNT);
    let err = send(&mut env.svm, &env.payer, &[&env.admin], flush)
        .expect_err("unbound flush must revert");

    match err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
            assert_eq!(
                code, 8,
                "must reject at the wrapper authority gate (Unauthorized=8)"
            );
            assert_ne!(code, 21, "must NOT be EngineLockActive (market IS Live)");
        }
        other => panic!("expected Custom(8) Unauthorized, got {other:?}"),
    }
    // nothing moved
    assert_eq!(token_amount(&env.svm, &env.stake_vault), FLUSH_AMOUNT);
    assert_eq!(token_amount(&env.svm, &env.wrapper_vault), 0);
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

struct PoolCtx {
    stake_id: Pubkey,
    pool_pda: Pubkey,
    vault_auth: Pubkey,
    stake_vault: Pubkey,
}

/// Create a Live v16 market (preallocate + InitMarket). Returns (market, mint, wrapper_vault).
fn build_live_market(
    svm: &mut LiteSVM,
    wrapper_id: Pubkey,
    token_program: Pubkey,
    admin: &Keypair,
    payer: &Keypair,
) -> (Pubkey, Pubkey, Pubkey) {
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
    let wrapper_vault = Pubkey::new_unique();
    set_token_account(svm, wrapper_vault, &mint, &wrapper_vault_auth, 0);
    svm.set_account(
        market,
        Account {
            lamports: 1_000_000_000,
            data: vec![0u8; MARKET_LEN_CAP1],
            owner: wrapper_id,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
    let init = Instruction {
        program_id: wrapper_id,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(market, false),
            AccountMeta::new_readonly(mint, false),
        ],
        data: encode_init_market_default(),
    };
    send(svm, payer, &[admin], init).expect("InitMarket");
    (market, mint, wrapper_vault)
}

/// Craft a funded insurance-LP stake pool for `market` under `stake_id` (the .so
/// must already be loaded at that id). vault_auth derives under `stake_id`.
fn add_stake_pool(
    svm: &mut LiteSVM,
    stake_id: Pubkey,
    wrapper_id: Pubkey,
    market: Pubkey,
    mint: Pubkey,
    admin: &Pubkey,
    amount: u64,
) -> PoolCtx {
    let (pool_pda, _) = derive_pool_pda(&stake_id, &market);
    let (vault_auth, bump) = derive_vault_authority(&stake_id, &pool_pda);
    let stake_vault = Pubkey::new_unique();
    set_token_account(svm, stake_vault, &mint, &vault_auth, amount);
    let mut pool = StakePool::zeroed();
    pool.is_initialized = 1;
    pool.bump = 255;
    pool.vault_authority_bump = bump;
    pool.slab = market.to_bytes();
    pool.admin = admin.to_bytes();
    pool.collateral_mint = mint.to_bytes();
    pool.lp_mint = Pubkey::new_unique().to_bytes();
    pool.vault = stake_vault.to_bytes();
    pool.total_deposited = amount;
    pool.percolator_program = wrapper_id.to_bytes();
    pool.pool_mode = 0;
    pool.set_discriminator();
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
    PoolCtx {
        stake_id,
        pool_pda,
        vault_auth,
        stake_vault,
    }
}

fn bind_ix(ctx: &PoolCtx, wrapper_id: Pubkey, market: Pubkey, admin: &Pubkey) -> Instruction {
    Instruction {
        program_id: ctx.stake_id,
        accounts: vec![
            AccountMeta::new(*admin, true),
            AccountMeta::new_readonly(ctx.pool_pda, false),
            AccountMeta::new_readonly(ctx.vault_auth, false),
            AccountMeta::new(market, false),
            AccountMeta::new_readonly(wrapper_id, false),
        ],
        data: vec![19u8],
    }
}

fn rotate_ix(
    ctx: &PoolCtx,
    wrapper_id: Pubkey,
    market: Pubkey,
    admin: &Pubkey,
    new_target: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: ctx.stake_id,
        accounts: vec![
            AccountMeta::new(*admin, true),
            AccountMeta::new_readonly(ctx.pool_pda, false),
            AccountMeta::new_readonly(ctx.vault_auth, false),
            AccountMeta::new_readonly(*new_target, true), // new authority co-signs
            AccountMeta::new(market, false),
            AccountMeta::new_readonly(wrapper_id, false),
        ],
        data: vec![20u8],
    }
}

fn flush_ix_ctx(
    ctx: &PoolCtx,
    wrapper_id: Pubkey,
    token_program: Pubkey,
    market: Pubkey,
    wrapper_vault: Pubkey,
    admin: &Pubkey,
    amount: u64,
) -> Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: ctx.stake_id,
        accounts: vec![
            AccountMeta::new(*admin, true),
            AccountMeta::new(ctx.pool_pda, false),
            AccountMeta::new(ctx.stake_vault, false),
            AccountMeta::new_readonly(ctx.vault_auth, false),
            AccountMeta::new(market, false),
            AccountMeta::new(wrapper_vault, false),
            AccountMeta::new_readonly(wrapper_id, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data,
    }
}

/// Locate the offset of a 32-byte pubkey within account data (used to find the
/// `insurance_authority` field by searching for the unique bound PDA bytes).
fn find_pubkey_offset(data: &[u8], needle: &[u8; 32]) -> Option<usize> {
    data.windows(32).position(|w| w == needle)
}

fn read_at(svm: &LiteSVM, market: &Pubkey, off: usize) -> [u8; 32] {
    let d = svm.get_account(market).unwrap().data;
    d[off..off + 32].try_into().unwrap()
}

/// THE no-lockout proof. Models a stake program redeploy (new program id => new
/// vault_auth PDA): bind under the OLD program, rotate the authority to the admin
/// wallet, confirm the OLD PDA can no longer flush, then re-bind from the NEW
/// program and flush again. The final flush is what proves the bind is NOT a
/// permanent weld.
#[test]
fn no_lockout_rotate_then_rebind_from_new_program() {
    let mut svm = LiteSVM::new().with_spl_programs();
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
    let stake_id_2 = Pubkey::new_unique(); // the "redeployed" stake program
    let wrapper_id = Pubkey::from_str(WRAPPER_MAINNET).unwrap();
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    svm.add_program_from_file(stake_id, stake_so()).unwrap();
    svm.add_program_from_file(stake_id_2, stake_so()).unwrap();
    svm.add_program_from_file(wrapper_id, wrapper_so())
        .unwrap();

    let admin = Keypair::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&admin.pubkey(), 10_000_000_000).unwrap();

    let (market, mint, wrapper_vault) =
        build_live_market(&mut svm, wrapper_id, token_program, &admin, &payer);

    // --- OLD program: bind -> flush works ---
    let pool_a = add_stake_pool(
        &mut svm,
        stake_id,
        wrapper_id,
        market,
        mint,
        &admin.pubkey(),
        100_000,
    );
    send(
        &mut svm,
        &payer,
        &[&admin],
        bind_ix(&pool_a, wrapper_id, market, &admin.pubkey()),
    )
    .expect("bind A");
    // locate insurance_authority by searching for the unique bound PDA bytes.
    let off = find_pubkey_offset(
        &svm.get_account(&market).unwrap().data,
        &pool_a.vault_auth.to_bytes(),
    )
    .expect("insurance_authority == vault_auth_A after bind");
    assert_eq!(read_at(&svm, &market, off), pool_a.vault_auth.to_bytes());
    send(
        &mut svm,
        &payer,
        &[&admin],
        flush_ix_ctx(
            &pool_a,
            wrapper_id,
            token_program,
            market,
            wrapper_vault,
            &admin.pubkey(),
            40_000,
        ),
    )
    .expect("flush A");
    assert_eq!(token_amount(&svm, &wrapper_vault), 40_000);

    // --- ROTATE the authority off the PDA to the admin wallet ---
    send(
        &mut svm,
        &payer,
        &[&admin],
        rotate_ix(
            &pool_a,
            wrapper_id,
            market,
            &admin.pubkey(),
            &admin.pubkey(),
        ),
    )
    .expect("rotate insurance_authority -> admin wallet");
    assert_eq!(
        read_at(&svm, &market, off),
        admin.pubkey().to_bytes(),
        "insurance_authority rotated to the admin wallet"
    );

    // --- OLD program flush now rejects at the operative authority gate ---
    let err = send(
        &mut svm,
        &payer,
        &[&admin],
        flush_ix_ctx(
            &pool_a,
            wrapper_id,
            token_program,
            market,
            wrapper_vault,
            &admin.pubkey(),
            10_000,
        ),
    )
    .expect_err("old-PDA flush must reject after rotate");
    match err {
        TransactionError::InstructionError(_, InstructionError::Custom(c)) => {
            assert_eq!(c, 8, "operative insurance_authority gate (Unauthorized=8)");
            assert_ne!(c, 21, "must NOT be an incidental EngineLockActive");
        }
        other => panic!("expected Custom(8) Unauthorized, got {other:?}"),
    }
    assert_eq!(
        token_amount(&svm, &wrapper_vault),
        40_000,
        "rejected flush moved nothing"
    );

    // --- NEW program: re-bind (admin is current authority now) + flush works ---
    let pool_b = add_stake_pool(
        &mut svm,
        stake_id_2,
        wrapper_id,
        market,
        mint,
        &admin.pubkey(),
        100_000,
    );
    assert_ne!(
        pool_b.vault_auth, pool_a.vault_auth,
        "redeployed program derives a NEW vault_auth PDA"
    );
    send(
        &mut svm,
        &payer,
        &[&admin],
        bind_ix(&pool_b, wrapper_id, market, &admin.pubkey()),
    )
    .expect("re-bind from the NEW program");
    assert_eq!(
        read_at(&svm, &market, off),
        pool_b.vault_auth.to_bytes(),
        "insurance_authority re-bound to the NEW PDA"
    );
    send(
        &mut svm,
        &payer,
        &[&admin],
        flush_ix_ctx(
            &pool_b,
            wrapper_id,
            token_program,
            market,
            wrapper_vault,
            &admin.pubkey(),
            25_000,
        ),
    )
    .expect("flush from the NEW program (NO LOCKOUT)");
    assert_eq!(
        token_amount(&svm, &wrapper_vault),
        40_000 + 25_000,
        "the redeployed program's flush applied — the bind was never a permanent weld"
    );
}
