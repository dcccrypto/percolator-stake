# Kani Proof Deep Analysis — percolator-stake

**Date:** 2026-02-18  
**Scope:** `/mnt/volume-hel1-1/percolator-stake/kani-proofs/src/lib.rs`  
**Total harnesses:** 33  
**Verification target:** LP math mirror (u32/u64) of `percolator-stake/src/math.rs`

---

## Executive Summary

| Rating | Count | Proofs |
|--------|-------|--------|
| **STRONG** | 23 | Meaningful semantic properties over wide symbolic state spaces |
| **WEAK** | 8 | Panic-safety only, or properties trivially implied by type semantics |
| **UNIT TEST** | 2 | Symbolic inputs but single deterministic code path |
| **TAUTOLOGICAL** | 0 | Two (`proof_flush_preserves_value`, `proof_equal_deposits_equal_lp`) identified and being fixed in parallel task |

The suite is broadly healthy. The conservation, fairness, C9-protection, cooldown, and deposit-cap sections are strong. The arithmetic-safety section is the weakest — 6 of 8 WEAK proofs live there — but these have value as integration smoke tests. The primary risk for auditors is the u32-mirror gap: no proof directly exercises the u64/u128 production arithmetic.

---

## Design Context

| Property | Value |
|----------|-------|
| Program | Insurance LP staking — Percolator Solana perp DEX |
| Key functions | `calc_lp_for_deposit`, `calc_withdraw_amount`, `total_pool_value`, `calc_available_for_flush` |
| Pool value formula | `deposited − withdrawn − flushed + returned` |
| LP state machine | 4 quadrants: (S=0,V=0) → 1:1; (S=0,V>0) → None; (S>0,V=0) → None; (S>0,V>0) → pro-rata |
| Mirror type rationale | u32 inputs / u64 intermediates to keep CBMC SAT formulas tractable (<60s/proof) |
| Bound convention | `< 100` standard; `< 20` for complex multi-operation proofs |

---

## Section 1 — Conservation (5 proofs)

---

### 1.1 `proof_deposit_withdraw_no_inflation`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | supply, pv, deposit ∈ (0, 20) |

**Branch coverage:** Normal pro-rata path only (supply > 0, pv > 0). First-depositor and orphaned-state branches are excluded by assumes.

**What it proves:** For any valid symbolic deposit into an active pool, the collateral returned upon full LP burn never exceeds the original deposit amount — no inflation is possible through a single deposit→withdraw cycle.

**Weaknesses:**
- Bounds are tight (`< 20`). Edge behaviour near u32::MAX in production u64/u128 arithmetic is not covered.
- Does not test the first-depositor quadrant (supply=0, pv=0).
- Early-exit on `lp == 0` or withdraw returning `None` silently skips those branches — valid states that could harbour rounding bugs.

**Recommendations:** Add a separate harness that asserts `back == 0` when `lp == 0` (zero LP for non-zero deposit is a legitimate rounding outcome that should not yield collateral). Extend bounds to `< 1000` if solver time permits.

---

### 1.2 `proof_first_depositor_exact`

| Attribute | Value |
|-----------|-------|
| **Rating** | UNIT TEST |
| **Input type** | Symbolic (amount only; supply/pv concrete at 0) |
| **Bounds** | amount ∈ (0, 100) |

**Branch coverage:** Exclusively the `(supply=0, pv=0)` quadrant — single code branch.

**What it proves:** The first depositor always receives exactly `amount` LP tokens and can redeem them for exactly `amount` collateral.

**Weaknesses:** With both supply and pool value fixed at zero, there is only one reachable code path. The symbolic `amount` adds range coverage but not path coverage. This is effectively a property-based unit test, not a formal proof.

**Recommendations:** Merge into a broader harness that also tests the non-first-depositor path, or at minimum add an assertion that `calc_lp_for_deposit(0, 0, 0) == Some(0)` (the zero-amount edge).

---

### 1.3 `proof_two_depositors_conservation`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | a, b, appreciation ∈ (0, 20) / (< 20) |

**Branch coverage:** First-depositor path (A), then pro-rata path (B) at an appreciated exchange rate. Sequential withdrawal with adjusted supply/value.

**What it proves:** Total collateral withdrawn by two depositors (A first, then B from the residual pool) never exceeds the sum of their deposits plus any external appreciation — a multi-party conservation invariant.

**Weaknesses:** Sequential-withdrawal arithmetic (`pv2 - a_back`, `s2 - a_lp`) uses unchecked subtraction; if `a_back > pv2` (which the prior assertions should prevent but Kani doesn't re-verify this inline), UB would be skipped with `None` early exit. Bounds are very tight.

**Recommendations:** Use `checked_sub` in the harness arithmetic to surface any proof gap, and add ordering-independent coverage (B withdraws before A).

---

### 1.4 `proof_no_dilution`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | init_s, init_pv, a_dep, b_dep ∈ (0, 15) |

**Branch coverage:** Pro-rata deposit path for both A and B. The initial pool is arbitrary (any non-zero supply/value).

**What it proves:** An existing LP holder's redeemable collateral does not decrease after a second depositor joins — dilution is formally ruled out.

**Weaknesses:** Bounds are the tightest in the suite (`< 15`). The property is critical and deserves the widest feasible range. Also tests only the case where both deposits succeed; does not assert what happens when one or both return `None`.

**Recommendations:** Raise bounds to `< 50` and verify solver time remains acceptable. Add a check that if B's deposit fails (returns `None`), A's value is unchanged by construction.

---

### 1.5 `proof_flush_full_return_conservation`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | dep, wd, flush < 100; invariants: wd ≤ dep, flush ≤ dep−wd |

**Branch coverage:** `pool_value` (simple subtraction) and `pool_value_with_flush` (four-operand formula). Tests zero-flush and non-zero-flush paths via symbolic inputs.

**What it proves:** After a flush followed by a complete return of flushed tokens, pool value is restored to `deposited − withdrawn`; partial flush reduces pool value by exactly `flush`.

**Weaknesses:** The harness manually enforces `flush ≤ dep − wd` via an assume, but the production instruction handler must enforce the same invariant. This proof does not verify that the handler enforces it.

**Recommendations:** Add a negative-space proof: when the assume is violated (overflush), `pool_value_with_flush` returns `None`, confirming the checked arithmetic catches it.

---

## Section 2 — Arithmetic Safety (4 proofs)

---

### 2.1 `proof_lp_deposit_no_panic`

| Attribute | Value |
|-----------|-------|
| **Rating** | WEAK |
| **Input type** | Symbolic (full u32 range) |
| **Bounds** | None |

**Branch coverage:** All four LP state quadrants; full u32 input range.

**What it proves:** `calc_lp_for_deposit` never panics or triggers undefined behaviour for any u32 inputs.

**Weaknesses:** Proves only panic-freedom. The function uses `checked_mul`, `checked_div`, and `checked_sub` throughout, so panic-freedom is essentially guaranteed by the type-safe API. No functional property is asserted.

**Recommendations:** Combine with at least one assertion (e.g., result is always `≤ supply` for normal inputs) to add functional value.

---

### 2.2 `proof_collateral_withdraw_no_panic`

| Attribute | Value |
|-----------|-------|
| **Rating** | WEAK |
| **Input type** | Symbolic (full u32 range) |
| **Bounds** | None |

**What it proves:** `calc_collateral_for_withdraw` never panics for any u32 inputs.

**Weaknesses:** Same as 2.1. Adds confidence that no `unwrap()` or unchecked arithmetic was accidentally introduced but proves no functional property.

**Recommendations:** Assert that when `lp == supply`, result `≤ pool_value`.

---

### 2.3 `proof_pool_value_no_panic`

| Attribute | Value |
|-----------|-------|
| **Rating** | WEAK |
| **Input type** | Symbolic (full u32 range) |
| **Bounds** | None |

**What it proves:** `pool_value` (simple `checked_sub`) never panics.

**Weaknesses:** `checked_sub` on primitives cannot panic by definition in Rust. This proof is a near-tautology at the type level, though it does confirm no extra logic was added that could panic.

**Recommendations:** Fold into `proof_pool_value_correctness` which already asserts functional properties symbolically.

---

### 2.4 `proof_flush_available_no_panic`

| Attribute | Value |
|-----------|-------|
| **Rating** | WEAK |
| **Input type** | Symbolic (full u32 range) |
| **Bounds** | None |

**What it proves:** `flush_available` (two `saturating_sub` calls) never panics.

**Weaknesses:** `saturating_sub` on u32 cannot panic by definition. This is the weakest proof in the suite — it asserts a property that is structurally impossible to falsify.

**Recommendations:** Replace with a proof that asserts `flush_available(d, w, f) == flush_available(d, w, f).min(d.saturating_sub(w))` or merge functional assertions from the flush-bounds section.

---

## Section 3 — Fairness / Monotonicity (3 proofs)

---

### 3.1 `proof_lp_rounding_favors_pool`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | s, pv, dep ∈ (0, 100) |

**Branch coverage:** Pro-rata path only (supply > 0, pv > 0, deposit > 0).

**What it proves:** For every successful deposit, `lp × pool_value ≤ deposit × supply` — the floor rounding in LP issuance always favours the pool over the depositor, preventing value extraction via deposit rounding.

**Weaknesses:** Does not test the first-depositor path (where the invariant holds trivially as equality). The upper bound of `< 100` means the intermediate `deposit * supply` (up to ~10,000) fits comfortably in u64 — this should be re-verified if bounds are raised substantially.

**Recommendations:** Add assertion that equality holds when `deposit * supply` is divisible by `pv` (no rounding loss in that case).

---

### 3.2 `proof_larger_deposit_more_lp`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | s, pv ∈ (0, 100); sm ∈ (0, 50); lg ∈ (sm, 100) |

**Branch coverage:** Pro-rata path for two different deposit sizes against the same pool state.

**What it proves:** LP issuance is monotone non-decreasing in deposit size: a larger deposit never yields fewer LP tokens than a smaller one.

**Weaknesses:** The proof only checks the `(Some, Some)` case — when one or both deposits return `None` (e.g., overflow), the proof silently passes. An overflow producing `None` for a large deposit but `Some` for a small one could be a legitimate finding that this proof misses.

**Recommendations:** Add an assertion that if `lg` returns `None` and `sm` returned `Some`, that is only permissible due to overflow (document expected cases).

---

### 3.3 `proof_larger_burn_more_collateral`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | s, pv ∈ (0, 100); sm ∈ (0, 50); lg ∈ (sm, s] |

**Branch coverage:** Withdrawal calculation for two LP burn sizes against the same pool state.

**What it proves:** Collateral returned is monotone non-decreasing in LP burn size: burning more LP never yields less collateral.

**Weaknesses:** Same silent-None gap as 3.2.

**Recommendations:** Assert that both calls succeed or add explicit None-handling to document the expected overflow semantics.

---

## Section 4 — Withdrawal Bounds (2 proofs)

---

### 4.1 `proof_full_burn_bounded`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | s ∈ (0, 100); pv < 100 |

**Branch coverage:** Full LP supply burn (`lp == supply`).

**What it proves:** Burning 100% of LP supply never returns more collateral than the pool value — the pool cannot be drained below zero via a single full withdrawal.

**Weaknesses:** `pv` has no lower bound (can be 0), which means a pool with supply > 0 but pv = 0 would return `Some(0)` — that's technically correct arithmetic but the C9 fix should block deposits into that state. The proof does not cross-reference the C9 invariant.

**Recommendations:** Add a companion proof that `supply > 0 ∧ pv = 0` implies `calc_collateral_for_withdraw` returns 0, and that such a state is unreachable via valid deposits.

---

### 4.2 `proof_partial_less_than_full`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | s ∈ (1, 100); pv ∈ (0, 100); p ∈ (0, s) |

**Branch coverage:** Compares partial burn (p < s) against full burn (s).

**What it proves:** A partial LP burn yields collateral ≤ the full burn — you cannot extract more value by burning fewer tokens.

**Weaknesses:** None significant. This is a straightforward and complete monotonicity check.

---

## Section 5 — Flush Bounds (2 proofs)

---

### 5.1 `proof_flush_bounded`

| Attribute | Value |
|-----------|-------|
| **Rating** | WEAK |
| **Input type** | Symbolic |
| **Bounds** | d, w, f < 100 |

**Branch coverage:** All combinations of d, w, f (including w > d, f > d).

**What it proves:** `flush_available(d, w, f) ≤ d` for all inputs.

**Weaknesses:** The function is implemented as two chained `saturating_sub` calls. `saturating_sub` is guaranteed by Rust semantics to return at most the minuend, so `a.saturating_sub(b) ≤ a` always. The property `flush_available ≤ d` follows immediately without any program logic being exercised — this is a near-tautological consequence of the implementation strategy.

**Recommendations:** Replace with a stronger bound: `flush_available(d, w, f) ≤ d.saturating_sub(w).saturating_sub(f)` (exact value equality proof) to actually verify the formula, not just the bounding property.

---

### 5.2 `proof_flush_max_then_zero`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | d, w, f < 100; w ≤ d; f ≤ d−w |

**Branch coverage:** Exercises the full-exhaustion path: after flushing all available collateral, no more is available.

**What it proves:** Flushing the full available amount leaves exactly zero remaining available for flush — the state is self-consistent and idempotent.

**Weaknesses:** The assume `f ≤ d.saturating_sub(w)` restricts to valid states; no test of the saturating behaviour when already over-flushed.

---

## Section 6 — Pool Value (4 proofs)

*(Note: section header in source says "3 proofs" but contains 4 harnesses.)*

---

### 6.1 `proof_pool_value_correctness`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | d, w < 100 |

**Branch coverage:** Both `Some` (w ≤ d) and `None` (w > d) branches.

**What it proves:** `pool_value` returns `Some(d − w)` exactly when `w ≤ d`, and `None` exactly when `w > d` — the overflow guard works correctly in both directions.

**Weaknesses:** None significant. Clean bi-directional correctness proof.

---

### 6.2 `proof_deposit_increases_value`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | d, w, extra < 100; w ≤ d; extra > 0 |

**Branch coverage:** The `checked_add` success path (d + extra doesn't overflow).

**What it proves:** Any strictly positive deposit strictly increases pool value — the monotone increase property holds for all valid symbolic inputs.

**Weaknesses:** Overflow path (d + extra overflows) is silently skipped. For u32 with bounds < 100, overflow is impossible — but this is an implicit assumption that should be explicit.

---

### 6.3 `proof_flush_return_conservation`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | d, w, f, r < 100; w ≤ d; f ≤ d−w; r ≤ f |

**Branch coverage:** Full-return branch (r == f) and partial-return branch (r < f). Tests the four-variable pool value formula.

**What it proves:** Pool value is always `≤ d − w` (optimistic ceiling), equals `d − w` iff `r == f` (full return), and is strictly less when `r < f` (partial return).

**Weaknesses:** The assume `r ≤ f` is the critical constraint (can't return more than flushed). This is a semantic invariant the production code must enforce — the proof does not verify that the handler enforces it.

---

### 6.4 `proof_returns_increase_value`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | d, w, f, r < 50; w ≤ d; f ≤ d−w; r < f |

**Branch coverage:** Marginal return path (r → r+1), both `pool_value_with_flush` calls succeeding.

**What it proves:** Each unit of insurance return strictly increases pool value — returns are monotone and non-zero.

**Weaknesses:** None significant. The tighter bound (`< 50`) reduces coverage range vs other section-6 proofs but is probably acceptable given the four-variable formula.

---

## Section 7 — Zero-input Boundaries (2 proofs)

---

### 7.1 `proof_zero_deposit_zero_lp`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | s, pv < 100 (all states including s=0, pv=0) |

**Branch coverage:** All four LP state quadrants — tests every branch of `calc_lp_for_deposit` with deposit=0.

**What it proves:** A zero-amount deposit never produces positive LP tokens across any pool state — no free minting is possible.

**Weaknesses:** None. This is a complete boundary check across the full state space.

---

### 7.2 `proof_zero_burn_zero_col`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | s, pv < 100 (all states) |

**Branch coverage:** All supply states including supply=0 (which returns `None`).

**What it proves:** Burning zero LP tokens never produces positive collateral — no free extraction is possible via zero-burn.

**Weaknesses:** None. Clean zero-boundary proof.

---

## Section 8 — Cooldown Enforcement (3 proofs)

---

### 8.1 `proof_cooldown_no_panic`

| Attribute | Value |
|-----------|-------|
| **Rating** | WEAK |
| **Input type** | Symbolic (full u32 range) |
| **Bounds** | None |

**What it proves:** `cooldown_elapsed` never panics for any u32 inputs.

**Weaknesses:** The function is `current_slot >= deposit_slot.saturating_add(cooldown_slots)` — a comparison with saturating addition. Neither can panic. This is a structural impossibility proof.

**Recommendations:** Merge this into `proof_cooldown_exact_boundary` as a combined harness.

---

### 8.2 `proof_cooldown_not_immediate`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | cd ∈ (0, 100); slot < u32::MAX − 100 |

**Branch coverage:** Tests the off-by-one: `current_slot == deposit_slot` with positive cooldown.

**What it proves:** Cooldown is not satisfied immediately at deposit — the same slot the deposit occurs, withdrawal via cooldown is blocked.

**Weaknesses:** The assume `slot < u32::MAX − 100` is needed to prevent saturating_add wraparound from making the proof vacuously true. This is correct but worth documenting in the harness comment.

---

### 8.3 `proof_cooldown_exact_boundary`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | cd < 100; dep_slot < u32::MAX − 100 |

**Branch coverage:** The exact boundary case: `current_slot = deposit_slot + cooldown_slots`.

**What it proves:** At exactly `deposit_slot + cooldown_slots`, the cooldown is satisfied — the `>=` boundary condition is correct.

**Weaknesses:** None. Clean boundary proof.

---

## Section 9 — Deposit Cap (3 proofs)

---

### 9.1 `proof_cap_zero_uncapped`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic (full u32 range) |
| **Bounds** | None |

**Branch coverage:** The `cap == 0` special-case branch exclusively.

**What it proves:** A cap of zero means uncapped — no deposit ever exceeds a zero cap, regardless of amount or existing total.

**Weaknesses:** None. Direct verification of the sentinel-value semantics.

---

### 9.2 `proof_cap_at_boundary`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | cap ∈ (0, 100); existing ≤ cap |

**Branch coverage:** The `total == cap` boundary (total + dep == cap exactly).

**What it proves:** A deposit that brings total exactly to the cap is permitted (does not exceed).

**Weaknesses:** None. Correct off-by-one verification at the upper boundary.

---

### 9.3 `proof_cap_above_boundary`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | cap ∈ (0, 100); existing < cap |

**Branch coverage:** The `total > cap` path (total + dep == cap + 1).

**What it proves:** A deposit that exceeds the cap by exactly one unit is correctly rejected.

**Weaknesses:** Only tests `cap + 1` excess, not arbitrary excess. Given the monotone nature of the check, this is sufficient but noting it for completeness.

---

## Section 10 — C9 Orphaned Value Protection (3 proofs)

---

### 10.1 `proof_c9_orphaned_value_blocked`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | pv ∈ (0, 100); dep ∈ (0, 100) |

**Branch coverage:** The `(supply=0, pv>0)` quadrant exclusively.

**What it proves:** When orphaned value exists (supply burned to zero, but pool value remains from insurance returns), all deposits are blocked — the C9 fix prevents a new depositor from acquiring a claim to pre-existing value they did not contribute.

**Weaknesses:** None. This is the most security-critical proof in the suite and it is well-structured.

---

### 10.2 `proof_c9_valueless_lp_blocked`

| Attribute | Value |
|-----------|-------|
| **Rating** | STRONG |
| **Input type** | Symbolic |
| **Bounds** | supply ∈ (0, 100); dep ∈ (0, 100) |

**Branch coverage:** The `(supply>0, pv=0)` quadrant exclusively.

**What it proves:** When LP exists but pool value is zero (all collateral withdrawn or lost), deposits are blocked — prevents dilution of existing holders' residual claims.

**Weaknesses:** The scenario where this state is reachable in production deserves documentation. The proof blocks the deposit but does not prove the state is unreachable via valid operations.

**Recommendations:** Add a proof that the `(supply>0, pv=0)` state cannot be reached starting from `(0, 0)` through valid deposit/withdraw sequences (a reachability invariant).

---

### 10.3 `proof_c9_true_first_depositor`

| Attribute | Value |
|-----------|-------|
| **Rating** | UNIT TEST |
| **Input type** | Symbolic (dep only; supply/pv concrete at 0) |
| **Bounds** | dep ∈ (0, 100) |

**Branch coverage:** Exclusively the `(supply=0, pv=0)` quadrant — single branch.

**What it proves:** A genuine first depositor (both supply and value are zero) receives exactly `dep` LP tokens.

**Weaknesses:** Supply and pool value are both fixed at zero — only one code branch is exercised. This duplicates `proof_first_depositor_exact` with minor bound differences. As a Kani harness, it adds minimal value beyond what a standard unit test would provide.

**Recommendations:** Consolidate with `proof_first_depositor_exact` and extend to assert that the `(0, 0, 0)` edge case returns `Some(0)`.

---

## Section 11 — Extended Arithmetic Safety (2 proofs)

---

### 11.1 `proof_pool_value_with_flush_no_panic`

| Attribute | Value |
|-----------|-------|
| **Rating** | WEAK |
| **Input type** | Symbolic (full u32 range) |
| **Bounds** | None |

**What it proves:** `pool_value_with_flush` never panics for any four u32 inputs.

**Weaknesses:** The function is two chained `checked_sub` calls followed by `checked_add`, all of which return `Option`. There is no panic path. This is structurally unfalsifiable.

**Recommendations:** Add assertions about when the result is `None` vs `Some` to convert this into the functional correctness proof it should be.

---

### 11.2 `proof_exceeds_cap_no_panic`

| Attribute | Value |
|-----------|-------|
| **Rating** | WEAK |
| **Input type** | Symbolic (full u32 range) |
| **Bounds** | None |

**What it proves:** `exceeds_cap` never panics for any u32 inputs.

**Weaknesses:** The function uses `checked_add` and returns `bool`. The overflow arm returns `true` (correct: overflow means cap exceeded). No panic path exists. This is structurally unfalsifiable.

**Recommendations:** Add assertions about the overflow arm: `if cap > 0 ∧ total + dep overflows → result is true`. This converts the harness from panic-safety to correctness.

---

## Known Gaps and Recommendations

### Gap 1 — u32 Mirror vs u64/u128 Production Arithmetic

**Risk: HIGH**

All 33 proofs operate on the u32/u64 mirror. The production code uses u64 for LP amounts and u128 for intermediate arithmetic. The scale-invariance argument (stated in the crate docstring) is reasonable but unproven. Specifically:

- Floor-rounding properties are scale-invariant for the formulae used ✓
- Overflow guard thresholds differ: mirror checks `> u32::MAX`, production checks `> u64::MAX` ✓ (same guard structure)
- Checked arithmetic semantics are identical ✓

**Recommendation:** Add a companion harness set using `u64` types with the production-equivalent bounds (< 2^32 range) using Kani's `assume` to verify that no new failure modes emerge at production scale. Alternatively, document the scale-invariance argument formally in the crate.

---

### Gap 2 — State Reachability

**Risk: MEDIUM**

No proof verifies that dangerous LP states (`supply=0, value>0` or `supply>0, value=0`) cannot be reached through valid instruction sequences. The C9 proofs verify that *if* the system is in those states, deposits are blocked — but not that production handlers prevent entering those states accidentally.

**Recommendation:** Add a harness that models a sequence of valid operations (deposit → partial withdraw → …) and asserts the invariant `(supply=0 ↔ value=0)` holds after each step (outside the specific C9 edge cases).

---

### Gap 3 — Multi-Flush Sequences

**Risk: MEDIUM**

No proof tests sequential partial flushes (flush₁, then flush₂ on the residual). The `flush_available` function uses the cumulative `flushed` counter, which the proofs treat as a single value. The composition of two partial flushes is not verified.

**Recommendation:** Add a proof asserting `flush_available(d, w, f1) + flush_available(d, w, f1 + f2) ≥ flush_available(d, w, f1 + f2)` (or equivalent) to confirm sequential flush accounting is consistent.

---

### Gap 4 — Slippage / Minimum Out

**Risk: MEDIUM**

No proof verifies slippage protection: that a user specifying `min_lp_out` or `min_collateral_out` cannot receive less than their minimum. This is a front-running/sandwich-attack concern and should be formally verified at the instruction handler level.

---

### Gap 5 — Weak Panic-Safety Proofs (8 proofs)

**Risk: LOW**

The 8 WEAK proofs (Sections 2.1–2.4, 8.1, 11.1–11.2, 5.1) prove properties that are structurally impossible to falsify given the implementation choices (checked arithmetic, saturating arithmetic). They serve as smoke tests that no `unwrap()` or raw arithmetic was accidentally introduced, which has some value, but they should not be counted as meaningful verification coverage.

**Recommendation:** Augment each WEAK proof with at least one functional assertion, or consolidate them with related STRONG proofs.

---

### Gap 6 — Tautological Proofs (Being Fixed)

The following two proofs were identified as tautological and are being corrected in a parallel task:

- **`proof_flush_preserves_value`** — not present in current source (already removed)
- **`proof_equal_deposits_equal_lp`** — not present in current source (already removed)

Replacement harnesses should verify:
- `proof_flush_preserves_value` → assert pool value *decreases* by exactly `flush` (not preserved), then is restored on return
- `proof_equal_deposits_equal_lp` → assert LP equality only when both supply and pool value are proportionally equal (not trivially from identical inputs to identical functions)

---

## Overall Coverage Assessment

| Domain | Coverage | Notes |
|--------|----------|-------|
| LP issuance arithmetic | ✅ Good | Conservation, rounding, monotonicity, zero boundaries |
| LP burn arithmetic | ✅ Good | Bounds, monotonicity, zero boundary |
| Pool value formula | ✅ Good | All four variables covered including flush/return |
| C9 orphaned value | ✅ Strong | All four quadrants explicitly verified |
| Deposit cap | ✅ Strong | Zero-cap, at-boundary, above-boundary |
| Cooldown | ✅ Good | No-panic, off-by-one, exact boundary |
| Flush accounting | ⚠️ Partial | Single-flush covered; sequential flushes not covered |
| State reachability | ❌ Missing | Dangerous states only blocked, not proven unreachable |
| Production u64/u128 | ❌ Missing | Mirror proofs only; scale-invariance unproven formally |
| Instruction handler logic | ❌ Out of scope | Authority checks, account validation not in mirror |
| Slippage protection | ❌ Missing | No min_out assertions |

**Verdict:** The LP math kernel is well-verified for the functional properties that matter most to auditors (conservation, dilution prevention, C9 fix). The verification boundary at the math layer is clear and appropriate. The principal audit risk is the unverified gap between the u32 mirror and the u64/u128 production code — this should be addressed before treating the Kani suite as a formal correctness certificate for the production binary.
