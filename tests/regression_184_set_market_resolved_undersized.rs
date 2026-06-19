//! Regression for #184 — `process_set_market_resolved` must reject an
//! owned-but-undersized pool account BEFORE `bytemuck::from_bytes_mut`
//! reinterprets the data. Mirrors the merged #177/#183 fix in
//! `process_return_insurance`.
//!
//! Before the fix the function validated owner only, then sliced
//! `pool_data[..STAKE_POOL_SIZE]` — a data buffer shorter than
//! `STAKE_POOL_SIZE` made that slice panic (program abort) instead of
//! returning a clean `InvalidAccount` error.
//!
//! This loads ONLY the stake .so (no wrapper needed for tag 18) and sends a
//! `SetMarketResolved` against a stake-program-owned account whose data is
//! shorter than `STAKE_POOL_SIZE`, asserting the program returns
//! `Custom(16)` (StakeError::InvalidAccount) rather than aborting.

use litesvm::LiteSVM;
use percolator_stake::state::STAKE_POOL_SIZE;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
    transaction::{Transaction, TransactionError},
};
use std::path::PathBuf;
use std::str::FromStr;

const STAKE_ID: &str = "9tbLt8fs1C7cJRXAyiGY7Ub88AT7MLWpxLqFNVCkqzA6";

// StakeError::InvalidAccount = 16 (src/error.rs).
const ERR_INVALID_ACCOUNT: u32 = 16;

fn stake_so() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target/deploy/percolator_stake.so");
    p
}

#[test]
fn set_market_resolved_rejects_undersized_pool_184() {
    let so = stake_so();
    if !so.exists() {
        // Build artifact not present (e.g. cargo test without a prior
        // build-sbf). Skip rather than fail — the unit/build-sbf gate covers
        // the rest. Print so the skip is visible in CI logs.
        eprintln!(
            "SKIP set_market_resolved_rejects_undersized_pool_184: stake .so missing at {} \
             — run `cargo build-sbf --no-default-features` first",
            so.display()
        );
        return;
    }

    let mut svm = LiteSVM::new();
    let stake_id = Pubkey::from_str(STAKE_ID).unwrap();
    svm.add_program_from_file(stake_id, so).unwrap();

    // Fund an admin/payer.
    let admin = Keypair::new();
    svm.airdrop(&admin.pubkey(), 1_000_000_000).unwrap();

    // A stake-program-OWNED account whose data is shorter than the pool struct.
    // Ownership passes validate_account_owner; non-emptiness passes
    // validate_account_not_empty; the new length guard is what must catch it.
    let pool_pda = Pubkey::new_unique();
    let undersized = STAKE_POOL_SIZE / 2; // > 0 but < STAKE_POOL_SIZE
    assert!(undersized > 0 && undersized < STAKE_POOL_SIZE);
    svm.set_account(
        pool_pda,
        Account {
            lamports: 1_000_000_000,
            data: vec![0u8; undersized],
            owner: stake_id,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();

    // Tag 18: SetMarketResolved — accounts: [admin (signer), pool_pda].
    let ix = Instruction {
        program_id: stake_id,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(pool_pda, false),
        ],
        data: vec![18u8],
    };

    let tx = Transaction::new(
        &[&admin],
        solana_sdk::message::Message::new(&[ix], Some(&admin.pubkey())),
        svm.latest_blockhash(),
    );

    let err = svm
        .send_transaction(tx)
        .expect_err("undersized pool account must be rejected, not accepted");

    match err.err {
        TransactionError::InstructionError(0, InstructionError::Custom(code)) => {
            assert_eq!(
                code, ERR_INVALID_ACCOUNT,
                "expected StakeError::InvalidAccount ({ERR_INVALID_ACCOUNT}), got Custom({code})"
            );
        }
        other => panic!(
            "expected clean Custom({ERR_INVALID_ACCOUNT}) InvalidAccount, got {other:?} \
             (a ProgramFailedToComplete / abort would indicate the slice panic regressed)"
        ),
    }
}
