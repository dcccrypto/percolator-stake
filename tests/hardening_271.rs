//! GH#271 — two pre-audit hardening items, and the guards that keep them true.
//!
//! Neither was an exploitable bug when filed; both are the kind of thing that stops
//! being true quietly. These tests exist so removing either fails CI rather than
//! waiting for an auditor to notice.

use std::fs;
use std::path::Path;

fn manifest() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("Cargo.toml must be readable")
}

fn source() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/processor.rs"))
        .expect("processor.rs must be readable")
}

/// Strip `#`-comments so a mention in prose cannot satisfy the assertion — the
/// mistake that made an indexer migration test vacuous earlier this week.
fn manifest_without_comments() -> String {
    manifest()
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn release_profile_enables_overflow_checks() {
    // Item 2. Without this the deployed SBF release binary WRAPS on integer
    // overflow instead of reverting. Nothing relies on wrapping today — every
    // accounting path uses checked_*/saturating_* or i128 widening — and this
    // keeps that true by construction rather than by review.
    let m = manifest_without_comments();
    let profile = m
        .split("[profile.release]")
        .nth(1)
        .expect("Cargo.toml must declare [profile.release]");
    // Bound the search to the section, so a setting under some LATER table cannot
    // satisfy it.
    let section = profile.split("\n[").next().unwrap_or(profile);
    assert!(
        section
            .lines()
            .any(|l| l.split('#').next().unwrap_or("").replace(' ', "") == "overflow-checks=true"),
        "[profile.release] must set overflow-checks = true; section was:{section}"
    );
}

#[test]
fn recover_flushed_insurance_binds_the_market_to_the_pool_slab() {
    // Item 1. `process_flush_to_insurance` has always checked `pool.slab ==
    // slab.key`; the recover path passed `market` straight through to the tag-57
    // CPI. It was not exploitable — the vault_auth PDA is only that slab's
    // insurance_operator, so the wrapper rejects a foreign market, and the CPI
    // destination is hard-bound to pool.vault regardless — but relying on the far
    // side of a CPI for a check this cheap is exactly what a wrapper change would
    // silently invalidate.
    let src = source();
    let handler = src
        .split("fn process_recover_flushed_insurance")
        .nth(1)
        .expect("the handler must exist");
    // Scope to the handler, not the file: the same guard in FlushToInsurance would
    // otherwise satisfy this and the test would prove nothing.
    let body = handler.split("\nfn ").next().unwrap_or(handler);
    assert!(
        body.contains("pool.slab != market.key.to_bytes()"),
        "process_recover_flushed_insurance must reject a market that is not this \
         pool's slab, before the CPI"
    );
    let guard_at = body
        .find("pool.slab != market.key.to_bytes()")
        .expect("guard present");
    let cpi_at = body.find("invoke_signed").unwrap_or(usize::MAX);
    assert!(
        guard_at < cpi_at,
        "the slab guard must run BEFORE the CPI, not after it"
    );
}
