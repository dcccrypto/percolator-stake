//! Task 11 amendment (THIRD EDIT, plan-amended 2026-07-19) — closes the
//! front-running/dilution vector that Task 11's first two edits armed.
//!
//! Task 11 made mode-0 (insurance) pools accrue fees (`total_pool_value()`
//! now folds in `total_fees_earned` for BOTH modes, and the permissionless
//! `AccrueFees` instruction accepts `pool_mode <= 1`). But the pre-accrue
//! guard that runs INSIDE `Deposit`/`Withdraw`/`DepositJunior` to crystallize
//! a pending vault surplus before pricing (`pre_accrue_mode1`,
//! `processor.rs:2443`) was left gated to `pool_mode == 1` only. That opens
//! this attack on a mode-0 pool with a pending, un-accrued vault surplus:
//!
//!   1. Attacker deposits. `Deposit` prices the mint against the STALE stored
//!      `total_pool_value()` (the surplus isn't folded in yet, because the
//!      pre-accrue guard no-ops for mode 0) -- so the attacker mints LP too
//!      cheaply, as if the surplus didn't exist.
//!   2. Attacker self-calls the permissionless `AccrueFees` (no signer/
//!      authority gate beyond "is a signer") in the SAME transaction. The
//!      surplus is now credited to `total_fees_earned` and distributed
//!      pro-rata over the POST-deposit LP supply -- which already includes
//!      the attacker's newly (cheaply) minted shares.
//!
//! Net effect: the attacker captures a slice of fees that accrued BEFORE
//! they staked, and every pre-existing LP holder's real claim (measured via
//! the crate's own `calc_collateral_for_withdraw`) is diluted below what it
//! would have been had the surplus been crystallized first, as it correctly
//! is for mode-1 pools.
//!
//! This test drives the REAL, compiled `percolator_stake.so` (+ real v17
//! `percolator_prog.so` for `InitPool`'s marketauth-rotation CPI) through
//! LiteSVM instruction dispatch, mirroring `mode0_accrue_fees_e2e.rs`'s
//! conventions exactly. The only forged state is the vault's SPL token
//! balance (the sanctioned stand-in for the wrapper's
//! `WithdrawInsuranceReserveToStake` producer) -- pool state, deposits, and
//! fee counters are never hand-set.
//!
//! **Pre-fix** (guard still `pool_mode == 1`-gated): this test's assertions
//! FAIL, and the failure output IS the dilution evidence -- see
//! `task-11-report.md`, "Fix: pre-accrual guard extended to mode 0" for the
//! captured `left`/`right` panic output both directions.
//! **Post-fix** (guard widened to `pool_mode <= 1`, renamed
//! `pre_accrue_fee_modes`): this test PASSES.

use litesvm::LiteSVM;
use percolator_stake::math::{calc_collateral_for_withdraw, calc_lp_for_deposit};
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

// ---- Program IDs (mirrors mode0_accrue_fees_e2e.rs) ----
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

// ---- Wrapper InitMarket (v17) -- copied verbatim from mode0_accrue_fees_e2e.rs. ----

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
    send_batch(svm, payer, signers, vec![ix])
}

/// Like `send`, but for a transaction carrying MULTIPLE program instructions.
/// Used to drive the attacker's Deposit and self-called AccrueFees as ONE
/// atomic transaction, exactly as the exploit description requires ("...then
/// self-calls the permissionless AccrueFees in the same transaction").
fn send_batch(
    svm: &mut LiteSVM,
    payer: &Keypair,
    signers: &[&Keypair],
    ixs: Vec<Instruction>,
) -> Result<(), litesvm::types::FailedTransactionMetadata> {
    let mut all: Vec<&Keypair> = vec![payer];
    all.extend_from_slice(signers);
    let cb_heap =
        solana_sdk::compute_budget::ComputeBudgetInstruction::request_heap_frame(128 * 1024);
    let cb_cu =
        solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let mut all_ixs = vec![cb_heap, cb_cu];
    all_ixs.extend(ixs);
    let tx = Transaction::new_signed_with_payer(
        &all_ixs,
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

// ---- Stake InitPool (tag 0) -- copied verbatim from mode0_accrue_fees_e2e.rs. ----

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

// ---- Stake Deposit (tag 1) -- copied verbatim from mode0_accrue_fees_e2e.rs. ----

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

// ---- Stake AccrueFees (tag 12) -- copied verbatim from mode0_accrue_fees_e2e.rs. ----

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

/// End-to-end exploit demonstration / regression test.
///
/// Setup: InitPool (mode 0) -> genesis Deposit by an honest LP -> a vault
/// surplus lands in the vault (the one sanctioned forgery) -> an ATTACKER
/// deposits and self-calls the real, permissionless AccrueFees IN THE SAME
/// TRANSACTION.
///
/// Correctness oracle (computed independently via the crate's own public
/// `math::calc_lp_for_deposit` / `math::calc_collateral_for_withdraw`, never
/// hand-derived):
///   - `expected_lp_post_accrual`: what the attacker's deposit SHOULD mint if
///     priced against the pool value AFTER the pending surplus is folded in
///     (i.e. the real vault balance right before the attacker's transfer).
///   - `claim_before_correct`: the genesis LP's real collateral claim if the
///     surplus were crystallized (and nothing else changed) -- the honest
///     baseline the genesis LP is entitled to before anyone else joins.
///
/// Assertions (must hold post-fix; FAIL pre-fix and the failure IS the
/// dilution evidence):
///   1. The attacker's ACTUAL minted LP (read from their real SPL LP ATA
///      balance after the real Deposit instruction ran) equals
///      `expected_lp_post_accrual` exactly -- proving the deposit was priced
///      AFTER crystallization, not before.
///   2. The genesis LP's ACTUAL claim (via `pool.calc_collateral_for_withdraw`
///      on the REAL post-transaction pool state) is >= `claim_before_correct`
///      -- proving the attacker's deposit did not dilute the pre-existing
///      holder below their honest baseline.
#[test]
fn mode0_deposit_priced_after_crystallization_not_before() {
    let so = stake_so();
    let wso = wrapper_so();
    if !so.exists() || !wso.exists() {
        eprintln!(
            "SKIP mode0_deposit_priced_after_crystallization_not_before: .so missing \
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
    let genesis_lp = Keypair::new();
    let attacker = Keypair::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 200_000_000_000).unwrap();
    svm.airdrop(&admin.pubkey(), 20_000_000_000).unwrap();
    svm.airdrop(&genesis_lp.pubkey(), 20_000_000_000).unwrap();
    svm.airdrop(&attacker.pubkey(), 20_000_000_000).unwrap();

    // ---- InitPool (real; pool_mode = 0, InitPool's hardcoded default -- the
    // path EVERY real client uses). ----
    let (_market, accts) = setup(&mut svm, wrapper_id, stake_id, token_program, &admin, &payer);
    send(&mut svm, &payer, &[&admin], init_pool_ix(stake_id, &accts, 5, 0))
        .unwrap_or_else(|e| panic!("InitPool must succeed.\nLogs:\n{}", e.meta.logs.join("\n")));
    assert_eq!(read_pool(&svm, &accts.pool_pda).pool_mode, 0, "InitPool must produce a mode-0 pool");

    // ---- Genesis deposit by an honest LP (real instruction). ----
    const GENESIS_DEPOSIT: u64 = 100_000;
    assert!(GENESIS_DEPOSIT > MINIMUM_LIQUIDITY, "must clear the N7 dead-share floor");

    let genesis_ata = Pubkey::new_unique();
    set_token_account(&mut svm, genesis_ata, &accts.collateral_mint, &genesis_lp.pubkey(), GENESIS_DEPOSIT);
    let genesis_lp_ata = Pubkey::new_unique();
    set_token_account(&mut svm, genesis_lp_ata, &accts.lp_mint, &genesis_lp.pubkey(), 0);
    let (genesis_deposit_pda, _) = derive_deposit_pda(&stake_id, &accts.pool_pda, &genesis_lp.pubkey());

    let genesis_dep_ix = deposit_ix(
        stake_id,
        &genesis_lp.pubkey(),
        accts.pool_pda,
        genesis_ata,
        accts.vault,
        accts.lp_mint,
        genesis_lp_ata,
        accts.vault_auth,
        genesis_deposit_pda,
        GENESIS_DEPOSIT,
    );
    send(&mut svm, &payer, &[&genesis_lp], genesis_dep_ix)
        .unwrap_or_else(|e| panic!("Genesis deposit must succeed.\nLogs:\n{}", e.meta.logs.join("\n")));

    let mint_amount_genesis = token_amount(&svm, &genesis_lp_ata);
    assert_eq!(
        mint_amount_genesis,
        GENESIS_DEPOSIT - MINIMUM_LIQUIDITY,
        "sanity: genesis mint = deposit - dead-share floor"
    );

    let pool_before_surplus = read_pool(&svm, &accts.pool_pda);
    let total_lp_supply_before = pool_before_surplus.total_lp_supply;
    assert_eq!(total_lp_supply_before, GENESIS_DEPOSIT, "sanity: full genesis lp_to_mint incl. dead share");
    assert_eq!(
        token_amount(&svm, &accts.vault),
        GENESIS_DEPOSIT,
        "vault holds exactly the genesis deposit before any surplus"
    );

    // ---- The ONE authorized forgery: bump the vault's real SPL balance to
    // simulate the wrapper's WithdrawInsuranceReserveToStake (tag 87) pushing
    // the insurance leg of the trade-fee split into this mode-0 pool's vault.
    // This surplus sits UN-ACCRUED (total_fees_earned is still 0) -- exactly
    // the window the exploit targets. ----
    const SURPLUS: u64 = 50_000;
    let vault_balance_before_attacker_deposit = GENESIS_DEPOSIT + SURPLUS;
    set_token_account(
        &mut svm,
        accts.vault,
        &accts.collateral_mint,
        &accts.vault_auth,
        vault_balance_before_attacker_deposit,
    );

    // ---- Correctness oracle, computed independently via the crate's own
    // public pure-math functions -- never by re-deriving the formula, and
    // never touching pool/deposit/fee state by hand. ----
    let expected_lp_post_accrual = calc_lp_for_deposit(
        total_lp_supply_before,
        vault_balance_before_attacker_deposit, // true, post-crystallization value
        GENESIS_DEPOSIT,                       // attacker's deposit amount, same size as genesis
    )
    .expect("oracle: expected post-accrual mint must be computable");
    let claim_before_correct = calc_collateral_for_withdraw(
        total_lp_supply_before,
        vault_balance_before_attacker_deposit, // true, post-crystallization value
        mint_amount_genesis,
    )
    .expect("oracle: genesis LP's honest baseline claim must be computable");

    // ---- Attacker deposit + self-called AccrueFees, in ONE transaction --
    // exactly the exploit's mechanics: "deposit ... then self-call the
    // permissionless AccrueFees in the same transaction". ----
    const ATTACKER_DEPOSIT: u64 = GENESIS_DEPOSIT;
    let attacker_ata = Pubkey::new_unique();
    set_token_account(&mut svm, attacker_ata, &accts.collateral_mint, &attacker.pubkey(), ATTACKER_DEPOSIT);
    let attacker_lp_ata = Pubkey::new_unique();
    set_token_account(&mut svm, attacker_lp_ata, &accts.lp_mint, &attacker.pubkey(), 0);
    let (attacker_deposit_pda, _) = derive_deposit_pda(&stake_id, &accts.pool_pda, &attacker.pubkey());

    let attacker_dep_ix = deposit_ix(
        stake_id,
        &attacker.pubkey(),
        accts.pool_pda,
        attacker_ata,
        accts.vault,
        accts.lp_mint,
        attacker_lp_ata,
        accts.vault_auth,
        attacker_deposit_pda,
        ATTACKER_DEPOSIT,
    );
    let attacker_accrue_ix = accrue_fees_ix(stake_id, &attacker.pubkey(), accts.pool_pda, accts.vault);

    send_batch(&mut svm, &payer, &[&attacker], vec![attacker_dep_ix, attacker_accrue_ix])
        .unwrap_or_else(|e| {
            panic!(
                "Attacker's deposit+AccrueFees batch must succeed (both are real, valid \
                 instructions on a mode-0 pool post-Task-11).\nLogs:\n{}",
                e.meta.logs.join("\n")
            )
        });

    // ---- Assertions on REAL post-transaction state (nothing hand-set). ----
    let actual_attacker_lp = token_amount(&svm, &attacker_lp_ata);
    let pool_after = read_pool(&svm, &accts.pool_pda);
    let actual_genesis_claim_after = pool_after
        .calc_collateral_for_withdraw(mint_amount_genesis)
        .expect("genesis claim must be computable post-transaction");

    eprintln!(
        "expected_lp_post_accrual={} actual_attacker_lp={} claim_before_correct={} \
         actual_genesis_claim_after={}",
        expected_lp_post_accrual, actual_attacker_lp, claim_before_correct, actual_genesis_claim_after
    );

    assert_eq!(
        actual_attacker_lp, expected_lp_post_accrual,
        "the attacker's deposit must be priced AFTER the pending surplus is crystallized \
         (post-accrual share price), not at the stale pre-accrual price -- a mismatch here \
         means the attacker minted LP too cheaply against an un-accrued surplus"
    );
    assert!(
        actual_genesis_claim_after >= claim_before_correct,
        "the genesis LP's real claim must not fall below their honest baseline \
         (claim_before_correct={}) as a side effect of the attacker's deposit -- \
         actual_genesis_claim_after={} is LOWER, i.e. the attacker's deposit diluted \
         the pre-existing holder by capturing fees earned before the attacker staked",
        claim_before_correct,
        actual_genesis_claim_after
    );
}
