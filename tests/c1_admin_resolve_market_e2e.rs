//! C-1 (security review BLOCKER) — AdminResolveMarket CPI proxy e2e.
//!
//! `InitPool` rotates the wrapper's `cfg.marketauth` to this program's pool PDA
//! (see `n6_marketauth_rotation_e2e.rs`), but until this fix there was NO CPI
//! proxy for the wrapper's ResolveMarket (tag 19) — meaning once marketauth
//! rotated, no key could ever resolve the market again. `AdminResolveMarket`
//! (stake tag 24) closes that gap.
//!
//! Loads the REAL stake .so + the REAL v17 wrapper .so into one LiteSVM instance
//! (mirroring `v17_stake_insurance_e2e.rs` / `n6_marketauth_rotation_e2e.rs`) so
//! the CPI wire is validated against the ACTUAL deployed wrapper bytecode, not a
//! hand-rolled decoder — the strongest possible evidence the ported wire
//! byte-matches `handle_resolve_market` (percolator-prog@e26c97a4,
//! v16_program.rs:10278).
//!
//! Covers:
//! 1. `admin_resolve_market_succeeds_and_actually_flips_wrapper_mode` — GREEN:
//!    the CPI succeeds through the real wrapper, and a SECOND call afterward
//!    fails (the wrapper's own `if group.header.mode != 0` guard fires) — proof
//!    the first call genuinely transitioned the market out of Live mode, not
//!    just that the instruction returned Ok.
//! 2. `admin_resolve_market_rejects_non_admin_signer` — RED: a non-admin caller
//!    cannot trigger the CPI (admin-gated).
//! 3. `admin_resolve_market_h1_blocked_by_outstanding_flushed_insurance` and
//!    `admin_resolve_market_h1_unblocked_after_recovery` — H-1: resolution is
//!    refused while `total_flushed > total_recovered_from_wrapper`, and
//!    succeeds once the pool's bookkeeping shows full wrapper-side recovery.
//! 4. H-1 RE-REVIEW FIX regression tests (the reviewer's confirmed finding: the
//!    OLD `total_flushed - total_returned` gate could be satisfied via
//!    `ReturnInsurance` alone, which moves the ADMIN'S OWN wallet tokens into
//!    pool.vault with NO wrapper CPI, permanently stranding real flushed
//!    capital in the wrapper post-resolution):
//!    - `admin_resolve_market_h1_blocked_when_only_total_returned_satisfied` —
//!      direct-state regression proving `total_returned == total_flushed`
//!      alone no longer unlocks resolution.
//!    - `admin_resolve_market_h1_blocked_by_real_return_insurance_call` —
//!      exercises the REAL `ReturnInsurance` (tag 10) instruction (genuine SPL
//!      transfer from the admin's own ATA into pool.vault) and proves
//!      `AdminResolveMarket` still rejects afterward.
//!    - `admin_resolve_market_h1_unblocked_only_after_real_recover_flushed_insurance`
//!      — exercises the REAL `RecoverFlushedInsurance` (tag 23) instruction,
//!      which CPIs the actual wrapper's tag-57 `WithdrawInsuranceAsset`, and
//!      proves `AdminResolveMarket` only succeeds once that real recovery has
//!      run (not merely because `total_returned` looks satisfied).
//!
//! AUD-T2-3 (2026-10-18): the two H1 tests that drove a real FlushToInsurance / RecoverFlushedInsurance were
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

const WRAPPER_MAINNET: &str = "ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv";
const STAKE_ID: &str = "9tbLt8fs1C7cJRXAyiGY7Ub88AT7MLWpxLqFNVCkqzA6";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
// Associated Token Program ID (used for canonical wrapper-vault ATA computation).
// Source: v16_program.rs:13530-13531 (mirrors v17_stake_insurance_e2e.rs).
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const MARKET_LEN_V17_CAP1: usize = 4059; // v2.2 variant -rem cap-1 market (592 + 806 + 2661 [#287 +32]: slot = 2325 + 112 band/rent + 160 funding drift tail + 32 R1 words); was 3147 (v17), 3675 (v2.1)
// 3147 = MARKET_GROUP_OFF(592 = HEADER_LEN 16 + WRAPPER_CONFIG_LEN 576)
//       + MARKET_GROUP_LEN(758) + 1 * MARKET_ASSET_SLOT_LEN(1797).
// Was 3067 when WRAPPER_CONFIG_LEN was 496; the 2026-07-19 fee-split fields grew
// WrapperConfigV16 496 -> 576, so every market fixture in this repo was 80 bytes
// short and EVERY InitMarket here failed with InvalidAccountData. Recompute via
// percolator_prog::state::market_account_len_for_capacity(1) when the wrapper
// config changes again.
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

fn mint_data() -> Vec<u8> {
    let mut d = vec![0u8; 82];
    d[44] = 0; // decimals
    d[45] = 1; // is_initialized
    d
}

// ── SPL token account helpers (mirrors v17_stake_insurance_e2e.rs) ────────────

/// Compute the canonical wrapper vault ATA: the Associated Token Account of
/// vault_authority for mint. Needed by the real RecoverFlushedInsurance flow,
/// which CPIs the wrapper's tag-57 WithdrawInsuranceAsset against this account.
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

/// Build a Live v17 market (allocate + InitMarket). `admin` becomes the
/// market's `cfg.marketauth` (InitMarket bootstraps marketauth to the init
/// signer — v16_program.rs InitMarket handler). Returns (market, mint,
/// wrapper_vault) — wrapper_vault is the CANONICAL ATA of the wrapper's
/// vault_authority for mint (required by the real RecoverFlushedInsurance /
/// FlushToInsurance flows added for the H-1 re-review regression tests).
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
    let wrapper_vault = canonical_vault_ata(&wrapper_vault_auth, &mint);
    set_token_account(svm, wrapper_vault, &mint, &wrapper_vault_auth, 0);

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

fn find_pubkey_offset(data: &[u8], needle: &[u8; 32]) -> Option<usize> {
    data.windows(32).position(|w| w == needle)
}

fn read_32_at(svm: &LiteSVM, market: &Pubkey, off: usize) -> [u8; 32] {
    let d = svm.get_account(market).unwrap().data;
    d[off..off + 32].try_into().unwrap()
}

/// Overwrite the 32 bytes at `off` in `market`'s account data with `new_val`.
/// Used to simulate "InitPool already rotated marketauth to the pool PDA"
/// without paying for the full InitPool dance (LP mint/vault creation) in
/// every test — mirrors how `add_stake_pool` in `v17_stake_insurance_e2e.rs`
/// injects StakePool state directly rather than running the real InitPool.
/// The real InitPool -> marketauth-rotation wire itself is already covered
/// end-to-end by `n6_marketauth_rotation_e2e.rs`; this file's job is to prove
/// AdminResolveMarket (the NEW C-1 proxy) correctly drives the real wrapper
/// once that rotation has happened.
fn write_32_at(svm: &mut LiteSVM, market: &Pubkey, off: usize, new_val: &[u8; 32]) {
    let mut acct = svm.get_account(market).unwrap();
    acct.data[off..off + 32].copy_from_slice(new_val);
    svm.set_account(*market, acct).unwrap();
}

/// Inject a StakePool account with marketauth-correct bump (unlike
/// `v17_stake_insurance_e2e.rs::add_stake_pool`'s placeholder `bump = 255`,
/// AdminResolveMarket's CPI signs with the pool PDA's OWN seeds, so the bump
/// must be the REAL one or `invoke_signed` will not produce a valid signature).
///
/// Takes `total_recovered_from_wrapper` explicitly (rather than assuming it
/// tracks `total_returned`) so tests can directly construct the H-1 re-review
/// bypass shape: `total_returned == total_flushed` (satisfied via
/// ReturnInsurance-style bookkeeping) while `total_recovered_from_wrapper == 0`
/// (nothing actually pulled back from the wrapper).
#[allow(clippy::too_many_arguments)]
fn inject_pool(
    svm: &mut LiteSVM,
    stake_id: Pubkey,
    wrapper_id: Pubkey,
    market: Pubkey,
    admin: &Pubkey,
    total_flushed: u64,
    total_returned: u64,
    total_recovered_from_wrapper: u64,
) -> Pubkey {
    let (pool_pda, bump) = derive_pool_pda(&stake_id, &market);

    let mut pool = StakePool::zeroed();
    pool.is_initialized = 1;
    pool.bump = bump; // REAL bump — required for invoke_signed to sign as pool_pda
    pool.slab = market.to_bytes();
    pool.admin = admin.to_bytes();
    pool.percolator_program = wrapper_id.to_bytes();
    pool.total_flushed = total_flushed;
    pool.total_returned = total_returned;
    pool.total_recovered_from_wrapper = total_recovered_from_wrapper;
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
    pool_pda
}

/// AdminResolveMarket (stake tag 24) instruction encoder.
/// Accounts: [admin(signer), pool_pda(readonly), slab(writable), percolator_program(readonly)]
fn admin_resolve_market_ix(
    stake_id: Pubkey,
    wrapper_id: Pubkey,
    admin: &Pubkey,
    pool_pda: Pubkey,
    market: Pubkey,
) -> Instruction {
    Instruction {
        program_id: stake_id,
        accounts: vec![
            AccountMeta::new_readonly(*admin, true),
            AccountMeta::new_readonly(pool_pda, false),
            AccountMeta::new(market, false),
            AccountMeta::new_readonly(wrapper_id, false),
        ],
        data: vec![24u8],
    }
}

/// Common setup: build a live market (marketauth=admin), derive the pool PDA
/// for it, then directly rewrite marketauth in the market's raw bytes to the
/// pool PDA — simulating "InitPool has already run" (proven separately by
/// n6_marketauth_rotation_e2e.rs). Returns (market, mint, wrapper_vault, pool_pda).
fn setup_resolved_ready_market(
    svm: &mut LiteSVM,
    wrapper_id: Pubkey,
    stake_id: Pubkey,
    token_program: Pubkey,
    admin: &Keypair,
    payer: &Keypair,
) -> (Pubkey, Pubkey, Pubkey, Pubkey) {
    let (market, mint, wrapper_vault) =
        build_live_market_v17(svm, wrapper_id, token_program, admin, payer);
    let (pool_pda, _bump) = derive_pool_pda(&stake_id, &market);

    let admin_bytes = admin.pubkey().to_bytes();
    let market_data = svm.get_account(&market).unwrap().data;
    let marketauth_off = find_pubkey_offset(&market_data, &admin_bytes)
        .expect("admin pubkey (== marketauth after InitMarket) must appear in market data");
    assert_eq!(
        read_32_at(svm, &market, marketauth_off),
        admin_bytes,
        "PRE-STATE: marketauth == admin before simulated InitPool rotation"
    );

    write_32_at(svm, &market, marketauth_off, &pool_pda.to_bytes());
    assert_eq!(
        read_32_at(svm, &market, marketauth_off),
        pool_pda.to_bytes(),
        "marketauth must now be the pool PDA (simulating a completed InitPool rotation)"
    );

    (market, mint, wrapper_vault, pool_pda)
}

/// Panics if either .so is missing (GH#311 S-3: a skipped e2e passes vacuously, so a
/// missing artifact is a hard failure). Build them first (`cargo build-sbf`).
fn common_svm_setup() -> Option<(LiteSVM, Pubkey, Pubkey, Pubkey, Keypair, Keypair)> {
    let so = stake_so();
    let wso = wrapper_so();
    if !so.exists() || !wso.exists() {
        panic!(
            "MISSING ARTIFACT (a hard failure, never a skip: GH#311 S-3): .so missing (stake={} wrapper={}) -- run `cargo build-sbf --no-default-features` \
             in percolator-stake and percolator-prog first",
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

    Some((svm, stake_id, wrapper_id, token_program, admin, payer))
}

/// GREEN + strongest possible wire proof: AdminResolveMarket succeeds through
/// the REAL deployed wrapper .so, and a second call afterward fails because the
/// wrapper's OWN `handle_resolve_market` now sees `group.header.mode != 0` and
/// rejects — proving the first call genuinely flipped the wrapper out of Live
/// mode (not just that our instruction returned Ok without the CPI taking
/// effect). This is possible ONLY if the wire (tag 19, 1-byte payload, 2-account
/// shape [admin(signer), market(writable)]) byte-matches exactly what the real
/// wrapper decoder and `handle_resolve_market` expect.
#[test]
fn admin_resolve_market_succeeds_and_actually_flips_wrapper_mode() {
    let Some((mut svm, stake_id, wrapper_id, token_program, admin, payer)) = common_svm_setup()
    else {
        return;
    };
    let (market, _mint, _wrapper_vault, pool_pda) = setup_resolved_ready_market(
        &mut svm,
        wrapper_id,
        stake_id,
        token_program,
        &admin,
        &payer,
    );
    inject_pool(
        &mut svm,
        stake_id,
        wrapper_id,
        market,
        &admin.pubkey(),
        0,
        0,
        0,
    );

    // First call: must succeed (nothing outstanding, admin signs, wire is correct).
    send(
        &mut svm,
        &payer,
        &[&admin],
        admin_resolve_market_ix(stake_id, wrapper_id, &admin.pubkey(), pool_pda, market),
    )
    .unwrap_or_else(|e| panic!("AdminResolveMarket must succeed on a Live market: {e:?}"));

    // Second call: the wrapper's handle_resolve_market checks
    // `group.header.mode != 0` BEFORE anything else and now rejects with
    // EngineLockActive — proof the market genuinely left Live mode.
    svm.expire_blockhash();
    let err = send(
        &mut svm,
        &payer,
        &[&admin],
        admin_resolve_market_ix(stake_id, wrapper_id, &admin.pubkey(), pool_pda, market),
    )
    .expect_err("a SECOND AdminResolveMarket must fail — the market is no longer Live");
    match err {
        TransactionError::InstructionError(_, InstructionError::Custom(_)) => {
            // expected: the wrapper's mode guard (EngineLockActive) fires.
        }
        other => {
            panic!("expected a Custom program error from the wrapper's mode guard, got {other:?}")
        }
    }
}

/// RED: a signer who is not pool.admin cannot trigger the CPI — proves the
/// proxy is admin-gated, not permissionless.
#[test]
fn admin_resolve_market_rejects_non_admin_signer() {
    let Some((mut svm, stake_id, wrapper_id, token_program, admin, payer)) = common_svm_setup()
    else {
        return;
    };
    let attacker = Keypair::new();
    svm.airdrop(&attacker.pubkey(), 20_000_000_000).unwrap();

    let (market, _mint, _wrapper_vault, pool_pda) = setup_resolved_ready_market(
        &mut svm,
        wrapper_id,
        stake_id,
        token_program,
        &admin,
        &payer,
    );
    // pool.admin == admin.pubkey(), NOT attacker.
    inject_pool(
        &mut svm,
        stake_id,
        wrapper_id,
        market,
        &admin.pubkey(),
        0,
        0,
        0,
    );

    let err = send(
        &mut svm,
        &payer,
        &[&attacker],
        admin_resolve_market_ix(stake_id, wrapper_id, &attacker.pubkey(), pool_pda, market),
    )
    .expect_err("AdminResolveMarket must reject a non-admin signer");
    match err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
            assert_eq!(
                code, 2,
                "expected StakeError::Unauthorized (2), got Custom({code})"
            );
        }
        other => panic!("expected Custom(2) Unauthorized, got {other:?}"),
    }
}

/// H-1: AdminResolveMarket must be blocked while flushed insurance has not
/// been recovered from the wrapper (total_flushed > total_recovered_from_wrapper)
/// — the CPI must never reach the wrapper in this case, so the market must
/// remain resolvable-later (mode unchanged) after the rejection.
#[test]
fn admin_resolve_market_h1_blocked_by_outstanding_flushed_insurance() {
    let Some((mut svm, stake_id, wrapper_id, token_program, admin, payer)) = common_svm_setup()
    else {
        return;
    };
    let (market, _mint, _wrapper_vault, pool_pda) = setup_resolved_ready_market(
        &mut svm,
        wrapper_id,
        stake_id,
        token_program,
        &admin,
        &payer,
    );
    // 600 tokens flushed, only 400 recovered from the wrapper -> 200 outstanding.
    inject_pool(
        &mut svm,
        stake_id,
        wrapper_id,
        market,
        &admin.pubkey(),
        600,
        400,
        400,
    );

    let err = send(
        &mut svm,
        &payer,
        &[&admin],
        admin_resolve_market_ix(stake_id, wrapper_id, &admin.pubkey(), pool_pda, market),
    )
    .expect_err("AdminResolveMarket must reject while insurance is unrecovered (H-1)");
    match err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
            assert_eq!(
                code, 24,
                "expected StakeError::InsuranceLossOutstanding (24), got Custom({code})"
            );
        }
        other => panic!("expected Custom(24) InsuranceLossOutstanding, got {other:?}"),
    }

    // The wrapper CPI must never have been reached: marketauth is still the
    // pool PDA (unchanged) and mode is still Live — the market remains
    // resolvable once recovery completes.
    let pool_pda_bytes = pool_pda.to_bytes();
    let market_data = svm.get_account(&market).unwrap().data;
    let off = find_pubkey_offset(&market_data, &pool_pda_bytes)
        .expect("marketauth (pool PDA) must still be present — CPI never fired");
    assert_eq!(read_32_at(&svm, &market, off), pool_pda_bytes);
}

/// H-1: once total_recovered_from_wrapper catches up with total_flushed
/// (nothing outstanding), AdminResolveMarket succeeds — closing the loop on
/// the fix.
#[test]
fn admin_resolve_market_h1_unblocked_after_recovery() {
    let Some((mut svm, stake_id, wrapper_id, token_program, admin, payer)) = common_svm_setup()
    else {
        return;
    };
    let (market, _mint, _wrapper_vault, pool_pda) = setup_resolved_ready_market(
        &mut svm,
        wrapper_id,
        stake_id,
        token_program,
        &admin,
        &payer,
    );
    // Fully recovered from the wrapper: 600 flushed, 600 recovered -> 0 outstanding.
    inject_pool(
        &mut svm,
        stake_id,
        wrapper_id,
        market,
        &admin.pubkey(),
        600,
        600,
        600,
    );

    send(
        &mut svm,
        &payer,
        &[&admin],
        admin_resolve_market_ix(stake_id, wrapper_id, &admin.pubkey(), pool_pda, market),
    )
    .unwrap_or_else(|e| {
        panic!("AdminResolveMarket must succeed once total_flushed <= total_recovered_from_wrapper: {e:?}")
    });
}

/// H-1 RE-REVIEW REGRESSION: this is the reviewer's confirmed bypass shape —
/// `total_returned` alone caught up with `total_flushed` (e.g. via
/// `ReturnInsurance`'s admin-wallet-funded bookkeeping, or the #161
/// last-junior-exit phantom write-off), but `total_recovered_from_wrapper`
/// stayed at 0 (nothing was ever actually pulled back from the wrapper).
/// AdminResolveMarket must STILL reject through the real wrapper-CPI-gated
/// instruction — proving the fix closes the exact hole the re-review found.
#[test]
fn admin_resolve_market_h1_blocked_when_only_total_returned_satisfied() {
    let Some((mut svm, stake_id, wrapper_id, token_program, admin, payer)) = common_svm_setup()
    else {
        return;
    };
    let (market, _mint, _wrapper_vault, pool_pda) = setup_resolved_ready_market(
        &mut svm,
        wrapper_id,
        stake_id,
        token_program,
        &admin,
        &payer,
    );
    // total_returned == total_flushed (the OLD gate's condition is satisfied),
    // but total_recovered_from_wrapper == 0 — nothing was ever CPI'd out of
    // the wrapper. This is the exact state ReturnInsurance-only bookkeeping
    // (or the #161 phantom write-off) produces.
    inject_pool(
        &mut svm,
        stake_id,
        wrapper_id,
        market,
        &admin.pubkey(),
        600,
        600,
        0,
    );

    let err = send(
        &mut svm,
        &payer,
        &[&admin],
        admin_resolve_market_ix(stake_id, wrapper_id, &admin.pubkey(), pool_pda, market),
    )
    .expect_err(
        "AdminResolveMarket must reject when total_returned is satisfied but \
         total_recovered_from_wrapper is not — this is the H-1 re-review finding",
    );
    match err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => {
            assert_eq!(
                code, 24,
                "expected StakeError::InsuranceLossOutstanding (24), got Custom({code})"
            );
        }
        other => panic!("expected Custom(24) InsuranceLossOutstanding, got {other:?}"),
    }

    // The wrapper CPI must never have been reached: marketauth is still the
    // pool PDA and mode is still Live.
    let pool_pda_bytes = pool_pda.to_bytes();
    let market_data = svm.get_account(&market).unwrap().data;
    let off = find_pubkey_offset(&market_data, &pool_pda_bytes)
        .expect("marketauth (pool PDA) must still be present — CPI never fired");
    assert_eq!(read_32_at(&svm, &market, off), pool_pda_bytes);
}

// ═══════════════════════════════════════════════════════════════════════════
// H-1 RE-REVIEW FIX: full real-instruction-flow regression tests.
//
// Everything above this point proves the gate at the STATE level (direct
// StakePool field injection via `inject_pool`). The tests below go one step
// further and drive the ACTUAL `ReturnInsurance` / `RecoverFlushedInsurance`
// instructions through the real stake .so (and, for recovery, the real
// wrapper .so's tag-57 WithdrawInsuranceAsset CPI) — proving the fix holds
// against the genuine instruction paths the reviewer's finding was about, not
// just a hand-constructed pool state that merely LOOKS like their output.
// ═══════════════════════════════════════════════════════════════════════════
