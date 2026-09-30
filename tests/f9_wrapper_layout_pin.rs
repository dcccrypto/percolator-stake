//! F-9 security INFO: pin the raw wrapper-layout facts the stake program reads
//! (`state::read_wrapper_terminal`) against every wrapper .so the stake program is
//! expected to work with.
//!
//! For each wrapper .so it runs a REAL InitMarket and a REAL ResolveMarket (tag 19,
//! signed by the init signer = marketauth), then asserts that on the real bytes:
//!   * the header is magic "PERCV16\0", VERSION == `WRAPPER_SUPPORTED_VERSION` (18),
//!     kind == market, and len >= `WRAPPER_MIN_MARKET_LEN` (1350);
//!   * byte `WRAPPER_OFF_MODE` (1218) is 0 while Live and 1 after ResolveMarket;
//!   * `read_wrapper_terminal` classifies them NotTerminal, then Resolved.
//!
//! Which .so files: `F9_WRAPPER_SOS` (colon-separated paths). If it is unset, the
//! sibling `../percolator-prog/target/deploy/percolator_prog.so` is used (the CI
//! checkout). A build with a VERSION other than 18 (e.g. the v17 CI sibling
//! 15eb8b0c) is not pinned; for it the test asserts only that the guard fails
//! closed (UnknownLayout). With `F9_REQUIRE_PINNED_SHA=1`, each .so must also be one of
//! `PINNED_WRAPPERS` below: that is the "every build we ship against" gate. A new
//! wrapper build must be added there only after this test passes on it.
//!
//! Pinned 2026-09-30:
//!   deploy/v18.2-wrapper@6377376a  sha256 4472b3832fda102aae8d28b3c1efc642a4b919f3671d93076ca6f88cce51e98b (on-chain v18.2)
//!   feat/p1-safety-release@c0ffaefa sha256 c4f63d15664a5b2fee77d20100e529c40398dabe36251b2840f7b06f624c0e28 (current P1)
//!   feat/p3-vault-owned-lp@ee29b5ac sha256 608d3f8cd98a03259ef1413c5e22c31e33d3d4b6d3e54669503c0f079aa91e96 (P1+P3 FINAL, program = 267a9017; superseded)
//!   feat/p3-vault-owned-lp@07a1d0eb sha256 8410a5d7e85528bd8ac4a32c3ca5b0c6aa5c6a7ced3499855c252286005c71cc (P1+P3 FINAL; superseded)
//!   feat/p3-vault-owned-lp@58e379f1 sha256 f1a1dfc3ff7e86ffea53394295c8e587f3309e9bda6dd3d9ce6bfcc68e07b21e (P1+P3 FINAL relaunch, engine 35ddd692, `--features devnet`)

#![allow(clippy::result_large_err)]

use litesvm::LiteSVM;
use percolator_stake::state::{
    read_wrapper_terminal, WrapperTerminal, WRAPPER_MIN_MARKET_LEN, WRAPPER_OFF_MODE,
    WRAPPER_SUPPORTED_VERSION,
};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
    transaction::Transaction,
};
use std::path::PathBuf;
use std::str::FromStr;

const PINNED_WRAPPERS: &[(&str, &str)] = &[
    (
        "4472b3832fda102aae8d28b3c1efc642a4b919f3671d93076ca6f88cce51e98b",
        "deploy/v18.2-wrapper@6377376a (deployed v18.2)",
    ),
    (
        "c4f63d15664a5b2fee77d20100e529c40398dabe36251b2840f7b06f624c0e28",
        "feat/p1-safety-release@c0ffaefa (P1)",
    ),
    (
        "608d3f8cd98a03259ef1413c5e22c31e33d3d4b6d3e54669503c0f079aa91e96",
        "feat/p3-vault-owned-lp@ee29b5ac (P1+P3 FINAL, superseded by 07a1d0eb)",
    ),
    (
        "8410a5d7e85528bd8ac4a32c3ca5b0c6aa5c6a7ced3499855c252286005c71cc",
        "feat/p3-vault-owned-lp@07a1d0eb (P1+P3 FINAL, superseded by 58e379f1)",
    ),
    (
        "f1a1dfc3ff7e86ffea53394295c8e587f3309e9bda6dd3d9ce6bfcc68e07b21e",
        "feat/p3-vault-owned-lp@58e379f1 (P1+P3 FINAL relaunch, --features devnet)",
    ),
];

const WRAPPER_MAINNET: &str = "ESa89R5Es3rJ5mnwGybVRG1GrNt9etP11Z5V2QWD4edv";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const MARKET_LEN_V18_CAP1: usize = 3675;
const MARKET_ASSET_GENERATION_FRONTIER_OFF: usize = 1173;
const ASSET0_AUTHORITY_EPOCH_OFF: usize = 1934;

fn wrapper_sos() -> Vec<PathBuf> {
    if let Ok(list) = std::env::var("F9_WRAPPER_SOS") {
        return list
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();
    }
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("percolator-prog/target/deploy/percolator_prog.so");
    vec![p]
}

fn sha256_hex(bytes: &[u8]) -> String {
    solana_sdk::hash::hashv(&[bytes])
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn encode_init_market() -> Vec<u8> {
    let mut out = vec![0u8];
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&10u64.to_le_bytes());
    out.extend_from_slice(&100u64.to_le_bytes());
    out.extend_from_slice(&1u128.to_le_bytes());
    out.extend_from_slice(&2u128.to_le_bytes());
    for v in [10_000u64, 10_000, 10_000, 0, 0] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&0u128.to_le_bytes());
    out.extend_from_slice(&0u128.to_le_bytes());
    for v in [10_000u64, 1, 0, 1, 1, 1, 100] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&10_000_000_000_000_000u128.to_le_bytes());
    out.extend_from_slice(&0u128.to_le_bytes());
    assert_eq!(out.len(), 219);
    out
}

fn send(
    svm: &mut LiteSVM,
    payer: &Keypair,
    signer: &Keypair,
    ix: Instruction,
) -> Result<(), String> {
    svm.expire_blockhash();
    let tx = Transaction::new_signed_with_payer(
        &[
            solana_sdk::compute_budget::ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            ix,
        ],
        Some(&payer.pubkey()),
        &[payer, signer],
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx)
        .map(|_| ())
        .map_err(|e| format!("{:?}\n{}", e.err, e.meta.logs.join("\n")))
}

fn read_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

#[test]
fn f9_wrapper_mode_offset_pinned_against_every_expected_wrapper_so() {
    let require_pinned = std::env::var("F9_REQUIRE_PINNED_SHA").as_deref() == Ok("1");
    let mut ran = 0;
    for so in wrapper_sos() {
        if !so.exists() {
            assert!(
                !require_pinned,
                "F9_REQUIRE_PINNED_SHA=1 but {} is missing",
                so.display()
            );
            eprintln!("SKIP: wrapper .so missing at {}", so.display());
            continue;
        }
        let bytes = std::fs::read(&so).unwrap();
        let sha = sha256_hex(&bytes);
        let pinned = PINNED_WRAPPERS.iter().find(|(h, _)| *h == sha);
        eprintln!(
            "wrapper {} sha256 {sha} pinned={:?}",
            so.display(),
            pinned.map(|p| p.1)
        );
        if require_pinned {
            assert!(
                pinned.is_some(),
                "{} (sha256 {sha}) is not a pinned wrapper build",
                so.display()
            );
        }

        let mut svm = LiteSVM::new().with_spl_programs();
        let wrapper_id = Pubkey::from_str(WRAPPER_MAINNET).unwrap();
        let token_program = Pubkey::from_str(TOKEN_PROGRAM).unwrap();
        svm.add_program(wrapper_id, &bytes);
        let (admin, payer) = (Keypair::new(), Keypair::new());
        svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
        svm.airdrop(&admin.pubkey(), 10_000_000_000).unwrap();
        let (market, mint) = (Pubkey::new_unique(), Pubkey::new_unique());
        let mut md = vec![0u8; 82];
        md[45] = 1;
        svm.set_account(
            mint,
            Account {
                lamports: 1_000_000_000,
                data: md,
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
        send(
            &mut svm,
            &payer,
            &admin,
            Instruction {
                program_id: wrapper_id,
                accounts: vec![
                    AccountMeta::new(admin.pubkey(), true),
                    AccountMeta::new(market, false),
                    AccountMeta::new_readonly(mint, false),
                ],
                data: encode_init_market(),
            },
        )
        .unwrap_or_else(|e| panic!("{}: InitMarket: {e}", so.display()));

        let live = svm.get_account(&market).unwrap().data;
        let version = u16::from_le_bytes([live[8], live[9]]);
        if version != WRAPPER_SUPPORTED_VERSION {
            // Not the pinned layout (e.g. the v17 CI sibling 15eb8b0c, VERSION 17).
            // The pin below does not apply; what MUST hold is that the guard fails
            // closed on it, so no stake instruction trusts byte 1218 there.
            assert!(
                !require_pinned,
                "{}: VERSION {version} under F9_REQUIRE_PINNED_SHA=1",
                so.display()
            );
            assert_eq!(
                read_wrapper_terminal(&live),
                WrapperTerminal::UnknownLayout,
                "{}: VERSION {version} must be refused, not classified",
                so.display()
            );
            eprintln!(
                "NOTE {}: VERSION {version} != {WRAPPER_SUPPORTED_VERSION}; guard fails closed (UnknownLayout); offset pin not applicable",
                so.display()
            );
            ran += 1;
            continue;
        }
        assert!(
            live.len() >= WRAPPER_MIN_MARKET_LEN,
            "{}: market len {}",
            so.display(),
            live.len()
        );
        assert_eq!(
            live[WRAPPER_OFF_MODE],
            0,
            "{}: Live mode byte at {WRAPPER_OFF_MODE}",
            so.display()
        );
        assert_eq!(
            read_wrapper_terminal(&live),
            WrapperTerminal::NotTerminal,
            "{}",
            so.display()
        );

        // Real ResolveMarket (tag 19): [19][asset_generation_frontier][authority_epoch].
        let mut d = vec![19u8];
        d.extend_from_slice(&read_u64(&live, MARKET_ASSET_GENERATION_FRONTIER_OFF).to_le_bytes());
        d.extend_from_slice(&read_u64(&live, ASSET0_AUTHORITY_EPOCH_OFF).to_le_bytes());
        send(
            &mut svm,
            &payer,
            &admin,
            Instruction {
                program_id: wrapper_id,
                accounts: vec![
                    AccountMeta::new(admin.pubkey(), true),
                    AccountMeta::new(market, false),
                ],
                data: d,
            },
        )
        .unwrap_or_else(|e| panic!("{}: ResolveMarket: {e}", so.display()));

        let res = svm.get_account(&market).unwrap().data;
        assert_eq!(
            res[WRAPPER_OFF_MODE],
            1,
            "{}: Resolved mode byte at {WRAPPER_OFF_MODE}",
            so.display()
        );
        assert_eq!(
            read_wrapper_terminal(&res),
            WrapperTerminal::Resolved,
            "{}",
            so.display()
        );
        ran += 1;
    }
    if ran == 0 {
        eprintln!("SKIP: no wrapper .so available; set F9_WRAPPER_SOS");
    }
}
