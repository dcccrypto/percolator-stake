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

/// Body of `fn <name>(` in processor.rs, up to the next top-level `fn`.
fn processor_fn_body(name: &str) -> &'static str {
    let start = PROCESSOR_RS
        .find(&format!("\nfn {name}("))
        .unwrap_or_else(|| panic!("{name} not found"));
    let rest = &PROCESSOR_RS[start + 1..];
    let end = rest[1..].find("\nfn ").map(|e| e + 1).unwrap_or(rest.len());
    &rest[..end]
}

fn account0_flags(variant_decl: &str) -> &'static str {
    let block = doc_block_for(variant_decl);
    let line = block
        .iter()
        .find(|l| l.contains("0. `["))
        .unwrap_or_else(|| panic!("{variant_decl:?} doc has no account-0 line: {block:#?}"));
    line.split('`').nth(1).expect("account line has no `[..]` flag group")
}

/// AUD-FC-B6: the staker is the payer of the deposit-PDA rent (Deposit) and, on v5 FIRST_LOSS
/// pools, of the wrapper units-refresh CPI (Deposit and Withdraw; `cpi_refresh_ins_units` passes
/// it as `AccountMeta::new(payer, true)`). The runtime therefore needs the staker WRITABLE in the
/// outer transaction, otherwise the CPI fails with PrivilegeEscalation. The doc listed it as
/// `[signer]` only, so a relayer-style client (fee payer != staker) following the doc built a
/// transaction that always fails. If the handler passes `user` as a payer, the doc must say
/// `writable`.
#[test]
fn fc_b6_staker_is_documented_writable_where_it_pays() {
    let deposit = processor_fn_body("process_deposit");
    assert!(
        deposit.contains("create_or_adopt_pda(\n            deposit_pda,\n            user,")
            && deposit.contains("v5_read_units(\n            pool,\n            user,"),
        "precondition: process_deposit pays the deposit PDA and the units refresh from `user`; \
         if that changed, revisit this test"
    );
    let withdraw = processor_fn_body("process_withdraw");
    assert!(
        withdraw.contains("v5_read_units(") && withdraw.contains("            user,\n"),
        "precondition: process_withdraw pays the units refresh from `user`; if that changed, \
         revisit this test"
    );
    let cpi_rs = include_str!("../src/cpi.rs");
    assert!(
        cpi_rs.contains("AccountMeta::new(*payer.key, true),"),
        "precondition: the units-refresh CPI takes its payer writable"
    );
    for decl in ["    Deposit { amount: u64 },", "    Withdraw { lp_amount: u64 },"] {
        let flags = account0_flags(decl);
        assert!(
            flags.contains("signer") && flags.contains("writable"),
            "{decl:?} documents the staker as {flags}, but the handler makes it a payer, so it \
             must be writable (AUD-FC-B6)"
        );
    }
}
