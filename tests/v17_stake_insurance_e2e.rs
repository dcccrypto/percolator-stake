//! Phase 4 assembled LiteSVM e2e — stake Bind/Rotate re-targeted to tag 65.
//!
//! Loads the stake .so + the v17 wrapper .so into one LiteSVM instance and
//! exercises the critical security properties of the redesigned stake custody:
//!
//! 1. no-admin-drain: after bind, neither admin (marketauth) nor any attacker
//!    can drain insurance via the tag-57 WithdrawInsuranceAsset shutdown path.
//!    RED before bind (wrapper rejects, auth not set yet).
//!    GREEN after bind + wrapper D-STAKE-1 guard fires on the drain attempt.
//!
//! 2. no-lockout-before-burn: the full migration round-trip works before the
//!    final burn:
//!    bind (old program) -> flush -> rotate to admin -> re-bind (new program)
//!    -> burn -> flush. The bind can recover custody until BurnAssetAdmin seals it.
//!
//! Wire: [65u8][0x00 0x00][0x01][pubkey:32] = 36 bytes (tag 65, asset_index=0,
//! kind=ASSET_AUTH_INSURANCE=1). Verified at byte level by cpi_tags.rs tests.
//!
//! NOTE on v16 tests in v16_stake_insurance_e2e.rs: those tests use
//! encode_init_market_default() with MARKET_LEN_CAP1=3107 (v16 layout) and are
//! #[ignore]d against the v17 wrapper binary, where the correct market size is
//! 3003 bytes (MARKET_ACCOUNT_LEN, confirmed via `cargo run --example dump_sizes`
//! in percolator-prog). The tests below use 3003.
//!
//! NOTE on the heap frame: v17 market instructions exceed the default 32KB BPF
//! heap during init and abort with "Access violation in heap section" unless the
//! transaction prepends ComputeBudgetInstruction::request_heap_frame — see send()
//! and issue #176.
//!
//! AUD-T2-3 (2026-10-18): the seven bind -> flush, no-drain, no-lockout and RecoverFlushedInsurance tests were
//! permanently `#[ignore]`d (v5 answers tags 3 and 23 with DeprecatedV5 = 34) and have been
//! deleted. First-loss behaviour is covered by tests/v5_first_loss.rs and the wrapper
//! p4_wave_d cross-program tests.

use bytemuck::Zeroable;
use litesvm::LiteSVM;
use percolator_stake::error::StakeError;
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

// ── Program IDs ──────────────────────────────────────────────────────────────
const WRAPPER_MAINNET: &str = "ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv";
const STAKE_ID: &str = "9tbLt8fs1C7cJRXAyiGY7Ub88AT7MLWpxLqFNVCkqzA6";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
// Associated Token Program ID (used for canonical vault ATA computation).
// Source: v16_program.rs:13530-13531.
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

// v17 wrapper market size for capacity=1. MUST equal the wrapper's
// state::market_account_len_for_capacity(1) (== constants::MARKET_ACCOUNT_LEN);
// an undersized account makes market_slot_capacity() compute 0 slots < the
// configured 1 → InitMarket returns InvalidAccountData. History: v16=3107,
// earlier v17=2987, then 3003 (post source-domain convergence), then 3067; current=3147
// (post InitMatcherCtx port / protocol-fee tag renumbering, percolator-prog
// HEAD 1d4594a5 — confirmed via `cargo run --example dump_sizes`).
const MARKET_LEN_V17_CAP1: usize = 4059; // v2.2 variant -rem cap-1 market (592 + 806 + 2661 [#287 +32]: slot = 2325 + 112 band/rent + 160 funding drift tail + 32 R1 words); was 3147 (v17), 3675 (v2.1)
// 3147 = MARKET_GROUP_OFF(592 = HEADER_LEN 16 + WRAPPER_CONFIG_LEN 576)
//       + MARKET_GROUP_LEN(758) + 1 * MARKET_ASSET_SLOT_LEN(1797).
// Was 3067 when WRAPPER_CONFIG_LEN was 496; the 2026-07-19 fee-split fields grew
// WrapperConfigV16 496 -> 576, so every market fixture in this repo was 80 bytes
// short and EVERY InitMarket here failed with InvalidAccountData. Recompute via
// percolator_prog::state::market_account_len_for_capacity(1) when the wrapper
// config changes again.
const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000;
const FLUSH_AMOUNT: u64 = 250_000;

// ── .so paths ────────────────────────────────────────────────────────────────

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

// ── SPL token account helpers ─────────────────────────────────────────────────

/// Compute the canonical wrapper vault ATA: the Associated Token Account of
/// vault_authority for mint. Formula matches v16_program.rs:13538-13548
/// (canonical_vault_address). The v17 wrapper enforces ATA-canonicity via
/// verify_vault_token_account (line 13670: key != canonical_vault_address).
fn canonical_vault_ata(vault_authority: &Pubkey, mint: &Pubkey) -> Pubkey {
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    let ata_program = Pubkey::from_str(ATA_PROGRAM).unwrap();
    Pubkey::find_program_address(
        &[
            vault_authority.as_ref(),
            token_program.as_ref(),
            mint.as_ref(),
        ],
        &ata_program,
    )
    .0
}

fn mint_data() -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[44] = 0; // decimals
    d[45] = 1; // is_initialized
    d
}

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
            lamports: 1_000_000_000,
            data: token_data(mint, owner, amount),
            owner: token_program,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

// ── InitMarket wire (v17) ─────────────────────────────────────────────────────
// Fields: max_portfolio_assets(u16) h_min(u64) h_max(u64) initial_price(u64)
// min_nonzero_mm_req(u128) min_nonzero_im_req(u128) maintenance_margin_bps(u64)
// initial_margin_bps(u64) max_trading_fee_bps(u64) trade_fee_base_bps(u64)
// liquidation_fee_bps(u64) liquidation_fee_cap(u128) min_liquidation_abs(u128)
// max_price_move_bps_per_slot(u64) max_accrual_dt_slots(u64)
// max_abs_funding_e9_per_slot(u64) min_funding_lifetime_slots(u64)
// max_account_b_settlement_chunks(u64) max_bankrupt_close_chunks(u64)
// max_bankrupt_close_lifetime_slots(u64) public_b_chunk_atoms(u128)
// maintenance_fee_per_slot(u128)
// Total: 1 + 2 + 8*14 + 16*5 = 219 bytes (same encoding as v16).
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

// ── WithdrawInsuranceAsset (tag 57) wire — used for the no-admin-drain test ──
// Wire: [57u8][asset_index: u16 LE][amount: u128 LE] = 19 bytes
// Accounts: [operator(signer), market(w), dest_token(w), vault_token(w),
//            vault_authority, token_program]
// Used to attempt admin-drain (should be rejected by D-STAKE-1 guard).

// ── Transaction helpers ───────────────────────────────────────────────────────

/// v2.2 combined release: complete the stale direct wrapper wire (tag 57 lacked `market_id` and the
/// `authority_epoch` trailer, so the drain attempt decoded as InvalidInstructionData and the RED
/// control proved nothing). Values come from the live market bytes.
fn complete_wrapper_wire(svm: &LiteSVM, ix: &mut Instruction) {
    use percolator_stake::wrapper_layout::{ASSET0_AUTHORITY_EPOCH_OFF, ASSET0_MARKET_ID_OFF};
    let d = ix.data.clone();
    if d.first() != Some(&57u8) || d.len() != 19 {
        return;
    }
    let Some(m) = ix.accounts.get(1) else { return };
    let Some(acct) = svm.get_account(&m.pubkey) else { return };
    let rd = |off: usize| u64::from_le_bytes(acct.data[off..off + 8].try_into().unwrap());
    let mut n = vec![57u8];
    n.extend_from_slice(&d[1..3]);
    n.extend_from_slice(&rd(ASSET0_MARKET_ID_OFF).to_le_bytes());
    n.extend_from_slice(&d[3..19]);
    n.extend_from_slice(&rd(ASSET0_AUTHORITY_EPOCH_OFF).to_le_bytes());
    ix.data = n;
}

fn send(
    svm: &mut LiteSVM,
    payer: &Keypair,
    signers: &[&Keypair],
    mut ix: Instruction,
) -> Result<(), TransactionError> {
    complete_wrapper_wire(svm, &mut ix);
    let mut all: Vec<&Keypair> = vec![payer];
    all.extend_from_slice(signers);
    // The v17 wrapper installs a custom 128KB BumpAllocator (V16_HEAP_FRAME_BYTES,
    // v16_program.rs:14401) that bumps DOWN from heap_base+128KB. The entrypoint's
    // deserialize() makes the first allocation on EVERY instruction, so without a
    // matching heap frame the program aborts with "Access violation in heap section"
    // (~153 CU). Every transaction to the wrapper MUST request a 128KB heap frame; this
    // mirrors the production transaction shape. See issue #176 (v17 deploy blocker: no
    // TS client currently requests this frame).
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

// ── Market + stake pool setup ─────────────────────────────────────────────────

/// Build a Live v17 market (allocate + InitMarket). Returns (market, mint, wrapper_vault).
///
/// The wrapper_vault returned is the CANONICAL ATA of the vault_authority for mint
/// (v17 verify_vault_token_account enforces canonical ATA: line 13670 in v16_program.rs).
fn build_live_market_v17(
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
    // Use the canonical ATA (required by v17's verify_vault_token_account).
    let wrapper_vault = canonical_vault_ata(&wrapper_vault_auth, &mint);
    set_token_account(svm, wrapper_vault, &mint, &wrapper_vault_auth, 0);

    // Allocate market with v17 size (2987 bytes for capacity=1).
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
    (market, mint, wrapper_vault)
}

struct PoolCtx {
    stake_id: Pubkey,
    pool_pda: Pubkey,
    vault_auth: Pubkey,
    stake_vault: Pubkey,
}

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

// ── Instruction encoders ──────────────────────────────────────────────────────

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

/// RecoverFlushedInsurance (stake tag 23): PDA-signed recovery of wrapper insurance to pool vault.
///
/// Accounts:
///   0. `[]`          caller (permissionless)
///   1. `[writable]`  pool PDA
///   2. `[writable]`  pool vault token account (dest = pool.vault)
///   3. `[]`          vault_auth PDA (signs as insurance_operator)
///   4. `[writable]`  wrapper market account
///   5. `[writable]`  wrapper vault token account (insurance source)
///   6. `[]`          wrapper vault authority PDA
///   7. `[]`          token program
///   8. `[]`          percolator program
///
/// Wire: [23u8][amount: u64 LE] = 9 bytes
fn recover_flushed_insurance_ix(
    ctx: &PoolCtx,
    wrapper_id: Pubkey,
    token_program: Pubkey,
    market: Pubkey,
    wrapper_vault: Pubkey,
    wrapper_vault_auth: Pubkey,
    caller: &Pubkey,
    amount: u64,
) -> Instruction {
    let mut data = vec![23u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: ctx.stake_id,
        accounts: vec![
            AccountMeta::new_readonly(*caller, false), // 0: caller (permissionless)
            AccountMeta::new(ctx.pool_pda, false),     // 1: pool PDA (writable)
            AccountMeta::new(ctx.stake_vault, false),  // 2: pool vault (dest; writable)
            AccountMeta::new_readonly(ctx.vault_auth, false), // 3: vault_auth PDA
            AccountMeta::new(market, false),           // 4: wrapper market (writable)
            AccountMeta::new(wrapper_vault, false),    // 5: wrapper vault (source; writable)
            AccountMeta::new_readonly(wrapper_vault_auth, false), // 6: wrapper vault auth
            AccountMeta::new_readonly(token_program, false), // 7: token program
            AccountMeta::new_readonly(wrapper_id, false), // 8: percolator program
        ],
        data,
    }
}

/// Rotate insurance_operator (kind=2) directly via tag 65 on the wrapper.
/// Used in the RED control test (bypasses the stake program to exercise the direct
/// wrapper path, proving the auth gate is open before secure bind).
///
/// Account layout (handle_update_asset_authority): [current(signer), new_auth(signer), market(w)]
/// Wire: [65u8][0x00 0x00 (asset_index u16 LE)][0x02 (kind=ASSET_AUTH_INSURANCE_OPERATOR)][new_pubkey:32]
#[allow(dead_code)]
fn rotate_operator_wrapper_ix(
    wrapper_id: Pubkey,
    current: Pubkey,
    new_operator: Pubkey,
    market: Pubkey,
) -> Instruction {
    let mut data = Vec::with_capacity(36);
    data.push(65u8);
    data.extend_from_slice(&0u16.to_le_bytes());
    data.push(2u8);
    data.extend_from_slice(new_operator.as_ref());
    debug_assert_eq!(data.len(), 36);
    Instruction {
        program_id: wrapper_id,
        accounts: vec![
            AccountMeta::new(current, true),
            AccountMeta::new_readonly(new_operator, true),
            AccountMeta::new(market, false),
        ],
        data,
    }
}

// ── Helpers for reading insurance_authority from the market account ───────────

// ── SMOKE ─────────────────────────────────────────────────────────────────────

#[test]
fn smoke_v17_binaries_load() {
    assert!(
        stake_so().exists(),
        "stake .so missing — run cargo build-sbf in ~/v17/percolator-stake"
    );
    assert!(
        wrapper_so().exists(),
        "wrapper .so missing — run cargo build-sbf in ~/v17/percolator-prog"
    );
    let mut svm = LiteSVM::new().with_spl_programs();
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
    let wrapper_id = Pubkey::from_str(WRAPPER_MAINNET).unwrap();
    svm.add_program_from_file(stake_id, stake_so()).unwrap();
    svm.add_program_from_file(wrapper_id, wrapper_so()).unwrap();
    assert!(svm.get_account(&stake_id).unwrap().executable);
    assert!(svm.get_account(&wrapper_id).unwrap().executable);
}

#[test]
fn init_market_v17_wire_is_219_bytes() {
    assert_eq!(encode_init_market_v17().len(), 219);
}

// ── v4 FLUSH / RECOVER scenarios (removed) ────────────────────────────────────
//
// v5 removed FlushToInsurance / RecoverFlushedInsurance (tags 3 and 23 answer
// DeprecatedV5 = 34 for every caller). The bind -> flush, no-admin-drain, no-lockout and
// RecoverFlushedInsurance (#171) scenarios built on them were permanently ignored and have
// been deleted (AUD-T2-3). First-loss deployment, loss and withdrawal behaviour is covered
// by tests/v5_first_loss.rs and the wrapper p4_wave_d XP-1..3 cross-program tests.

/// NEGATIVE: nothing flushed → InsufficientVaultBalance.
#[test]
fn recover_flushed_insurance_nothing_flushed_rejected() {
    let mut svm = LiteSVM::new().with_spl_programs();
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
    let wrapper_id = Pubkey::from_str(WRAPPER_MAINNET).unwrap();
    let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
    svm.add_program_from_file(stake_id, stake_so()).unwrap();
    svm.add_program_from_file(wrapper_id, wrapper_so()).unwrap();

    let admin = Keypair::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.airdrop(&admin.pubkey(), 20_000_000_000).unwrap();

    let (market, mint, wrapper_vault) =
        build_live_market_v17(&mut svm, wrapper_id, token_program, &admin, &payer);

    let pool = add_stake_pool(
        &mut svm,
        stake_id,
        wrapper_id,
        market,
        mint,
        &admin.pubkey(),
        FLUSH_AMOUNT,
    );

    let wrapper_vault_auth =
        Pubkey::find_program_address(&[b"vault", market.as_ref()], &wrapper_id).0;

    // Bind so the PDA is set up, but do NOT flush.
    send(
        &mut svm,
        &payer,
        &[&admin],
        bind_ix(&pool, wrapper_id, market, &admin.pubkey()),
    )
    .expect("bind");

    // total_flushed == 0 == total_returned → outstanding == 0 → InsufficientVaultBalance.
    svm.expire_blockhash();
    let err = send(
        &mut svm,
        &payer,
        &[],
        recover_flushed_insurance_ix(
            &pool,
            wrapper_id,
            token_program,
            market,
            wrapper_vault,
            wrapper_vault_auth,
            &payer.pubkey(),
            1,
        ),
    )
    .expect_err("recover with nothing flushed must be rejected");

    match err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
            // v5: RecoverFlushedInsurance is deprecated (DeprecatedV5 = 34) before any balance check.
            assert_eq!(
                code,
                StakeError::DeprecatedV5 as u32,
                "v5: RecoverFlushedInsurance returns DeprecatedV5=34 (was InsufficientVaultBalance=13 pre-v5), got code={code}"
            );
        }
        other => panic!("expected Custom(InsufficientVaultBalance=13), got {other:?}"),
    }
}
