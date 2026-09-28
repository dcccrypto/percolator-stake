//! Account-metadata doc drift guard (percolator-vault #45 ported check).
//!
//! `src/instruction.rs` doc comments are the published account list that
//! clients, scripts and the SDK are built from. `process_init_pool` REQUIRES
//! the slab to be writable (the marketauth admin-handoff CPI writes it and the
//! handler rejects a read-only slab with `InvalidArgument`), but the InitPool
//! doc listed it as `[]`. A client following the doc builds a transaction that
//! can never succeed. InitTradingPool documents "same as InitPool", so it
//! inherited the same drift.
//!
//! This test ties the doc to the processor: if the handler enforces slab
//! writability, the doc for account 1 must say `writable`.

const INSTRUCTION_RS: &str = include_str!("../src/instruction.rs");
const PROCESSOR_RS: &str = include_str!("../src/processor.rs");

/// Return the doc-comment lines that immediately precede `variant_decl`
/// (e.g. `"    InitPool {"`), i.e. the variant's `///` block.
fn doc_block_for(variant_decl: &str) -> Vec<&'static str> {
    let lines: Vec<&'static str> = INSTRUCTION_RS.lines().collect();
    let idx = lines
        .iter()
        .position(|l| *l == variant_decl)
        .unwrap_or_else(|| panic!("variant declaration {variant_decl:?} not found"));
    let mut block = Vec::new();
    for l in lines[..idx].iter().rev() {
        if l.trim_start().starts_with("///") {
            block.push(*l);
        } else {
            break;
        }
    }
    block.reverse();
    block
}

fn process_init_pool_body() -> &'static str {
    let start = PROCESSOR_RS
        .find("fn process_init_pool(")
        .expect("process_init_pool not found");
    let rest = &PROCESSOR_RS[start..];
    let end = rest[1..].find("\nfn ").map(|e| e + 1).unwrap_or(rest.len());
    &rest[..end]
}

#[test]
fn init_pool_doc_marks_slab_writable_when_processor_requires_it() {
    let body = process_init_pool_body();
    assert!(
        body.contains("!slab.is_writable"),
        "precondition: process_init_pool is expected to reject a read-only slab; \
         if that requirement was removed, revisit this test"
    );

    let block = doc_block_for("    InitPool {");
    let slab_line = block
        .iter()
        .find(|l| l.contains("1. `[") && l.contains("Slab account"))
        .unwrap_or_else(|| panic!("InitPool doc has no account-1 slab line: {block:#?}"));
    let flags = slab_line
        .split('`')
        .nth(1)
        .expect("account line has no `[..]` flag group");
    assert!(
        flags.contains("writable"),
        "InitPool doc lists the slab as {flags} but process_init_pool requires it \
         writable (admin-handoff CPI) — clients following the doc build a tx that \
         always fails: {slab_line}"
    );
}

#[test]
fn init_trading_pool_doc_still_defers_to_init_pool() {
    // InitTradingPool reuses the InitPool account layout; if its doc stops
    // saying so, it needs its own account list (and its own writability check).
    let block = doc_block_for("    InitTradingPool {");
    assert!(
        block.iter().any(|l| l.contains("same as InitPool")),
        "InitTradingPool doc no longer defers to InitPool's account list: {block:#?}"
    );
}
