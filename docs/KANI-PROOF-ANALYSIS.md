# Kani Proof Harness Analysis — percolator-stake

**Date:** 2026-02-18
**File:** `kani-proofs/src/lib.rs` — 33 proof harnesses
**Production code:** `src/math.rs` (u64/u128)
**Mirror code:** `kani-proofs/src/lib.rs` (u32/u64)

---

## ⚠️ Structural Issue: Mirror Mismatch

The Kani proofs use a u32/u64 mirror of the production u64/u128 code. **The mirror has a bug:**

```rust
// PRODUCTION (correct):
let lp = (deposit as u128).checked_mul(supply as u128)?.checked_div(pv as u128)?;
if lp > u64::MAX as u128 { None } else { Some(lp as u64) }

// KANI MIRROR (wrong):
let lp = (deposit as u64).checked_mul(supply as u64)?.checked_div(pv as u64)?;
Some(lp as u32) // ← MISSING overflow check! Silently truncates u64→u32
```

**Impact:** For inputs where `deposit * supply / pool_value > u32::MAX`, the mirror silently truncates while production would return `None`. This means proofs verified on the mirror DON'T verify the overflow-guard branch of production code.

**Why it doesn't bite yet:** All proofs use bounds `< 100`, so the max intermediate is 99×99 = 9,801 — well under u32::MAX. But the mirror is structurally unfaithful to production.

**Same issue in `calc_collateral_for_withdraw` mirror.**

**Fix:** Add `if lp > u32::MAX as u64 { None } else { Some(lp as u32) }` to both mirror functions.

---

## ⚠️ Structural Issue: `flush_available` Mismatch

The Kani mirror uses `saturating_sub` (matching `math.rs` helper), but the **production processor** uses `checked_sub` (L4 fix). The proofs verify the weaker `saturating_sub` version, not the production `checked_sub`. Properties proven still hold for `checked_sub` (it's stricter), but the mirror doesn't match what runs on-chain.

---

## Functions Under Test — Branch Map

### `calc_lp_for_deposit(supply, pool_value, deposit)`
| Branch | Condition | Path |
|--------|-----------|------|
| B1 | `supply == 0 && pool_value == 0` | → `Some(deposit)` (first depositor) |
| B2a | `supply == 0` (but pv > 0) | → `None` (orphaned value) |
| B2b | `pool_value == 0` (but supply > 0) | → `None` (valueless LP) |
| B3 | both > 0, mul succeeds, div succeeds | → `Some(lp)` (pro-rata) |
| B3a | mul overflow (u64 from u32 — impossible for u32) | → `None` |
| B3b | div by zero (impossible: pv > 0 in B3) | — |
| B3c | result > u32::MAX (MISSING CHECK in mirror) | → should be `None`, currently truncates |

### `calc_collateral_for_withdraw(supply, pool_value, lp)`
| Branch | Condition | Path |
|--------|-----------|------|
| B1 | `supply == 0` | → `None` |
| B2 | supply > 0, normal | → `Some(col)` |
| B2a | mul overflow | → `None` |
| B2b | result > u32::MAX (MISSING CHECK in mirror) | → should be `None` |

### `pool_value(deposited, withdrawn)`
| Branch | Condition | Path |
|--------|-----------|------|
| B1 | `deposited >= withdrawn` | → `Some(d - w)` |
| B2 | underflow | → `None` |

### `pool_value_with_flush(d, w, f, r)`
| Branch | Condition | Path |
|--------|-----------|------|
| B1 | `d < w` | → `None` (first checked_sub) |
| B2 | `(d-w) < f` | → `None` (second checked_sub) |
| B3 | `(d-w-f) + r` overflow | → `None` (checked_add) |
| B4 | all ok | → `Some(d - w - f + r)` |

### `flush_available(d, w, f)`
| Branch | Condition | Path |
|--------|-----------|------|
| B1 | `d < w` | → 0 (first saturating_sub clamps) |
| B2 | `(d-w) < f` | → 0 (second saturating_sub clamps) |
| B3 | normal | → `d - w - f` |

### `cooldown_elapsed(current, deposit, cooldown)`
| Branch | Condition | Path |
|--------|-----------|------|
| B1 | `deposit + cooldown` overflows u32 | → `saturating_add` clamps to `u32::MAX` |
| B2 | `current >= deposit + cooldown` | → `true` |
| B3 | `current < deposit + cooldown` | → `false` |

### `exceeds_cap(total, deposit, cap)`
| Branch | Condition | Path |
|--------|-----------|------|
| B1 | `cap == 0` | → `false` (uncapped) |
| B2 | `total + deposit` overflows | → `true` |
| B3 | `total + deposit > cap` | → `true` |
| B4 | `total + deposit <= cap` | → `false` |

---

## Per-Proof Analysis

---

### 1. `proof_deposit_withdraw_no_inflation`

**Inputs:**
| Input | Classification | Range |
|-------|---------------|-------|
| supply | Symbolic | 1–19 |
| pv | Symbolic | 1–19 |
| deposit | Symbolic | 1–19 |

**Branch coverage (calc_lp_for_deposit):**
| Branch | Reachable? | Reason |
|--------|-----------|--------|
| B1 (first depositor) | ❌ | supply > 0 AND pv > 0 |
| B2a (orphaned) | ❌ | supply > 0 |
| B2b (valueless) | ❌ | pv > 0 |
| B3 (pro-rata) | ✅ | |
| B3a (mul overflow) | ❌ | 19×19 = 361, fits u64 |
| B3c (truncation) | ❌ | max 361, fits u32 |

**Branch coverage (calc_collateral_for_withdraw):**
| Branch | Reachable? | Reason |
|--------|-----------|--------|
| B1 (supply=0) | ❌ | ns = supply + lp ≥ 2 |
| B2 (normal) | ✅ | |

**Invariant:** `back <= deposit` — conservation (pool-favoring rounding).

**Vacuity risk:** Early return on `Some(lp) if lp > 0` — fires when `deposit * supply / pv` rounds to 0. Example: deposit=1, supply=1, pv=19 → lp=0. Some inputs take the early return. But many don't. Proof is **non-vacuous** for most of the input space.

**Symbolic collapse:** None — supply, pv, deposit vary independently, creating different exchange ratios.

**Rating: STRONG** — genuinely symbolic over the pro-rata path with varied ratios. Missing first-depositor and orphaned branches, but those aren't relevant to this property (conservation only matters in pro-rata).

**Recommendation:** Widen bounds to `< 100` for broader coverage. Add a non-vacuity witness: `kani::cover!(back > 0)` to confirm the assertion path is reached.

---

### 2. `proof_first_depositor_exact`

**Inputs:**
| Input | Classification | Range |
|-------|---------------|-------|
| supply=0 | Concrete | — |
| pool_value=0 | Concrete | — |
| amount | Symbolic | 1–99 |

**Branch coverage (calc_lp_for_deposit):**
| Branch | Reachable? |
|--------|-----------|
| B1 (first depositor) | ✅ (locked in by concrete 0,0) |
| B2a/B2b/B3 | ❌ |

**Branch coverage (calc_collateral_for_withdraw):**
| Branch | Reachable? |
|--------|-----------|
| B1 (supply=0) | ❌ (supply = amount ≥ 1) |
| B2 (normal) | ✅ |

**Invariant:** `lp == amount` AND `back == amount` — exact 1:1 roundtrip.

**Vacuity:** unwrap succeeds always (0,0,amount → Some(amount)). **Non-vacuous.**

**Rating: STRONG** — proves exact roundtrip property universally over all deposit amounts. 2/3 inputs are concrete but that's intentional (first-depositor is a specific state). The roundtrip assertion (`back == amount`) adds real value beyond just testing deposit.

---

### 3. `proof_two_depositors_conservation`

**Inputs:**
| Input | Classification | Range |
|-------|---------------|-------|
| a | Symbolic | 1–99 |
| b | Symbolic | 1–99 |

**Branch coverage:**
- `calc_lp_for_deposit(0, 0, a)`: B1 (first depositor, concrete 0,0) ✅
- `calc_lp_for_deposit(a, a, b)`: B3 (pro-rata, derived supply=a, pv=a) ✅

**Invariant:** `a_back + b_back <= a + b` — total conservation.

**⚠️ Symbolic collapse:** First depositor creates pool where `supply == pool_value == a`. Second deposit: `b_lp = b * a / a = b` (always exact). Ratio is ALWAYS 1:1. The exchange rate never varies from 1.0x. Withdrawals: `a_back = a * (a+b) / (a+b) = a`, `b_back = b`. Conservation is trivially satisfied with equality.

**The solver never explores fractional exchange rates where rounding actually matters.**

**Rating: WEAK** — symbolic collapse locks ratio at 1:1. The conservation property being tested is trivially true (a+b = a+b). Never exercises the case where rounding causes loss (which IS the interesting conservation property).

**Recommendation:** Add `appreciation: u32` symbolic input between deposits:
```rust
let a_lp = calc_lp_for_deposit(0, 0, a).unwrap();
kani::assume(appreciation > 0 && appreciation < 50);
let new_pv = a + appreciation; // pool appreciated
let b_lp = calc_lp_for_deposit(a_lp, new_pv, b);
// Now ratio ≠ 1:1, rounding is non-trivial
```

---

### 4. `proof_no_dilution`

**Inputs:**
| Input | Classification | Range |
|-------|---------------|-------|
| a_dep | Symbolic | 1–49 |
| b_dep | Symbolic | 1–49 |

**⚠️ Symbolic collapse:** Same as proof 3. First depositor creates supply=a_dep, pv=a_dep. After B deposits: `a_value_after = a_dep * (a_dep + b_dep) / (a_dep + b_dep) = a_dep = a_value_before`. Assertion `a_value_after >= a_value_before` always holds with **exact equality**.

**The proof never tests whether the no-dilution property holds when the pool has a non-unity exchange rate** (e.g., after insurance operations change pool_value without changing supply).

**Rating: WEAK** — symbolic collapse, assertion always satisfied with equality. Never tests the interesting case where supply ≠ pool_value.

**Recommendation:** Use 4 symbolic inputs: `init_supply, init_value, a_dep, b_dep` where `init_supply ≠ init_value`:
```rust
let init_s: u32 = kani::any();
let init_pv: u32 = kani::any();
kani::assume(init_s > 0 && init_s < 20);
kani::assume(init_pv > 0 && init_pv < 20);
// A deposits into existing pool
let a_lp = calc_lp_for_deposit(init_s, init_pv, a_dep);
```

---

### 5. `proof_flush_preserves_value`

**Inputs:**
| Input | Classification | Range |
|-------|---------------|-------|
| dep | Symbolic | 0–99 |
| wd | Symbolic | 0–99 |
| flush | Symbolic | 0–99 |

**⚠️ VACUOUS:** The proof computes:
```rust
let pv_before = pool_value(dep, wd).unwrap();
let pv_after = pool_value(dep, wd).unwrap();
assert_eq!(pv_before, pv_after);
```

**This calls the same function with the same arguments twice.** The assertion `f(x) == f(x)` is a tautology. The `flush` variable is computed via `flush_available` but **never used in any assertion**. The proof proves that a pure function is deterministic, nothing more.

**Rating: VACUOUS** — tautology. `flush` variable is dead code within the proof.

**Recommendation:** Replace with a meaningful flush-conservation proof:
```rust
// Before flush: LP holders' claim
let pv = pool_value_with_flush(dep, wd, 0, 0).unwrap(); // no flush yet
// After flush: LP holders' claim includes insurance
let pv_after = pool_value_with_flush(dep, wd, flush, 0); // flush, no returns
// LP value decreased by flush amount (funds moved to insurance)
if let Some(pv_a) = pv_after {
    assert_eq!(pv_a, pv - flush);
}
```
Or test the end-to-end: flush, then full return → back to original value:
```rust
let pv_roundtrip = pool_value_with_flush(dep, wd, flush, flush);
assert_eq!(pv_roundtrip, Some(pool_value(dep, wd).unwrap()));
```

---

### 6. `proof_lp_deposit_no_panic`

**Inputs:**
| Input | Classification | Range |
|-------|---------------|-------|
| supply | Symbolic | full u32 |
| pool_value | Symbolic | full u32 |
| deposit | Symbolic | full u32 |

**Branch coverage:** ALL branches reachable — full u32 range, no assumes.

**Invariant:** Absence of panic (implicit — all operations are checked/Option).

**Rating: STRONG** — exhaustive over full u32 domain, all branches explored, no vacuity risk.

---

### 7. `proof_collateral_withdraw_no_panic`

**Same analysis as proof 6 for `calc_collateral_for_withdraw`.**

**Rating: STRONG**

---

### 8. `proof_pool_value_no_panic`

**Same analysis for `pool_value`.**

**Rating: STRONG**

---

### 9. `proof_flush_available_no_panic`

**Same analysis for `flush_available`.**

**Rating: STRONG**

---

### 10. `proof_equal_deposits_equal_lp`

**Inputs:**
| Input | Classification | Range |
|-------|---------------|-------|
| s | Symbolic | 0–99 |
| pv | Symbolic | 0–99 |
| a | Symbolic | 0–99 |

**Assertion:** `calc_lp_for_deposit(s, pv, a) == calc_lp_for_deposit(s, pv, a)`

**⚠️ VACUOUS** — calling the same pure function with identical arguments is a tautology. The solver doesn't need to explore any branches. This proves Rust functions are deterministic, which is guaranteed by the language for pure functions.

**Rating: VACUOUS** — tautology. Proves nothing about the function's behavior.

**Recommendation:** Test meaningful determinism: "two users depositing the same amount into the same pool state get the same LP." This requires a multi-step scenario where the second deposit happens after pool state updates from the first. Or delete this proof — determinism of pure functions is axiomatic.

---

### 11. `proof_larger_deposit_more_lp`

**Inputs:**
| Input | Classification | Range |
|-------|---------------|-------|
| s | Symbolic | 1–99 |
| pv | Symbolic | 1–99 |
| sm | Symbolic | 1–49 |
| lg | Symbolic | sm+1 to 99 |

**Branch coverage (calc_lp_for_deposit):**
| Branch | Reachable? |
|--------|-----------|
| B1 (first depositor) | ❌ (s > 0, pv > 0) |
| B2a/B2b (orphaned) | ❌ (s > 0, pv > 0) |
| B3 (pro-rata) | ✅ |

**Invariant:** `ll >= ls` — monotonicity.

**Vacuity risk:** `match` with `_ => {}` skips assertion if either returns None. With bounds < 100, neither overflows. Both return Some. **Non-vacuous.**

**Rating: STRONG** — genuine monotonicity proof over symbolic pro-rata inputs.

---

### 12. `proof_larger_burn_more_collateral`

**Same structure as proof 11 for withdrawal.**

**Additional constraint:** `lg <= s` (can't burn more LP than exists).

**Rating: STRONG**

---

### 13. `proof_full_burn_bounded`

**Inputs:**
| Input | Classification | Range |
|-------|---------------|-------|
| s | Symbolic | 1–99 |
| pv | Symbolic | 0–99 |

**Branch coverage:** supply > 0 → B2 (normal). pv=0 → col = 0*0/s = 0 ≤ 0 ✓. pv>0 → col = s*pv/s = pv ≤ pv ✓.

**Invariant:** Full burn (burn all LP) yields at most pool_value.

**Vacuity:** `if let Some(col)` — col always Some since supply > 0 and no overflow at < 100. **Non-vacuous.**

**Rating: STRONG**

---

### 14. `proof_partial_less_than_full`

**Inputs:** s (2–99), pv (1–99), p (1 to s-1). All symbolic.

**Invariant:** Partial burn ≤ full burn.

**Vacuity:** Both calls always return Some. **Non-vacuous.**

**Rating: STRONG**

---

### 15. `proof_flush_bounded`

**Inputs:** d (0–99), w (0–99), f (0–99). All symbolic, no ordering assumes.

**Branch coverage (flush_available):**
| Branch | Reachable? |
|--------|-----------|
| B1 (d < w → clamp 0) | ✅ |
| B2 ((d-w) < f → clamp 0) | ✅ |
| B3 (normal) | ✅ |

**Invariant:** `flush_available(d, w, f) <= d` — always true since result ≥ 0 and ≤ d-w-f ≤ d.

**Rating: STRONG** — all three branches reachable, correct assertion.

---

### 16. `proof_flush_max_then_zero`

**Inputs:** d (0–99), w (0–99), f (0–99). Assumes: w ≤ d, f ≤ d-w.

**Branch coverage:** Assumes lock to B3 (normal path). B1/B2 (underflow clamp) locked out.

**Invariant:** After flushing all available, zero remains.

**Rating: STRONG** — the assumes define "valid accounting state," which is the correct domain for this property. Testing underflow states is meaningless for this assertion (flush_available returns 0 when underflowed, so flushing 0 more still gives 0 — trivially true).

---

### 17. `proof_pool_value_correctness`

**Inputs:** d (0–99), w (0–99). Both symbolic.

**Branch coverage:**
| Branch | Reachable? |
|--------|-----------|
| B1 (d ≥ w → Some) | ✅ |
| B2 (d < w → None) | ✅ |

**Both branches explicitly tested with conditional assertions:**
```rust
if w > d { assert!(r.is_none()); }
else { assert_eq!(r, Some(d - w)); }
```

**Rating: STRONG** — exemplary proof. Both branches tested. Correct value assertion.

---

### 18. `proof_deposit_increases_value`

**Inputs:** d (0–99), w (0–99), extra (1–99). Assumes: w ≤ d, extra > 0.

**Branch coverage:** `d + extra` checked_add — with max 99+99=198, never overflows u32. The `if let Some(new_d)` guard never fails.

**Invariant:** Adding deposits strictly increases pool value.

**Rating: STRONG** — valid-state symbolic proof. The overflow guard not firing is fine (it's just defense-in-depth).

---

### 19. `proof_flush_return_conservation`

**Inputs:** d, w, f, r all symbolic (0–99). Assumes: w ≤ d, f ≤ d-w, r ≤ f.

**Branch coverage (pool_value_with_flush):** All assumes lock to B4 (success). B1/B2/B3 locked out.

**Invariant:** Three sub-properties tested:
1. `pv ≤ d - w` (ceiling: can't exceed original value)
2. `r == f → pv == d - w` (full return = original, conservation)
3. `r < f → pv < d - w` (partial return < original)

**Vacuity:** `if let Some(pv)` — always Some given assumes. **Non-vacuous.** Sub-conditions `r == f` and `r < f` are both reachable (symbolic r ranges from 0 to f).

**Rating: STRONG** — comprehensive flush+return accounting verification with multiple sub-properties.

---

### 20. `proof_returns_increase_value`

**Inputs:** d, w, f, r all symbolic (0–49). Assumes: w ≤ d, f ≤ d-w, r < f.

**Invariant:** `pool_value_with_flush(d, w, f, r+1) > pool_value_with_flush(d, w, f, r)` — returns strictly increase value.

**Vacuity:** `match (Some(b), Some(a))` — both always Some. `r + 1 ≤ f` (since r < f), so `r+1` doesn't exceed flush, and `(d-w-f) + (r+1) ≤ (d-w-f) + f = d-w` — no overflow. **Non-vacuous.**

**Rating: STRONG**

---

### 21. `proof_zero_deposit_zero_lp`

**Inputs:**
| Input | Classification | Range |
|-------|---------------|-------|
| s | Symbolic | 1–99 |
| pv | Symbolic | 1–99 |
| deposit=0 | Concrete | — |

**Branch coverage:** s > 0, pv > 0 → B3 (pro-rata). `0 * s / pv = 0`. Returns Some(0). ✅

**Missing branches:** B1 (0,0,0) → Some(0). B2a (0,>0,0) → None. B2b (>0,0,0) → None.

**Rating: WEAK** — 1/3 inputs concrete. Only tests pro-rata branch. The property "zero deposit gives zero LP" doesn't hold universally: `calc_lp_for_deposit(0, 500, 0)` returns `None`, not `Some(0)`.

**Recommendation:** Remove `s > 0 && pv > 0` assumes. Test all states. Change assertion to handle None:
```rust
let result = calc_lp_for_deposit(s, pv, 0);
assert!(result == Some(0) || result.is_none());
```

---

### 22. `proof_zero_burn_zero_col`

**Inputs:**
| Input | Classification | Range |
|-------|---------------|-------|
| s | Symbolic | 1–99 |
| pv | Symbolic | 1–99 |
| lp=0 | Concrete | — |

**Branch coverage:** s > 0 → B2 (normal). `0 * pv / s = 0`. Some(0). ✅
**Missing:** B1 (s=0, lp=0) → None.

**Rating: WEAK** — same reasoning as proof 21.

**Recommendation:** Same fix: remove s > 0 assume, handle None in assertion.

---

### 23. `proof_cooldown_no_panic`

**Inputs:** 3x kani::any() — full u32 range.

**Branch coverage:** All branches (saturating_add, >=, <) reachable.

**Rating: STRONG**

---

### 24. `proof_cooldown_not_immediate`

**Inputs:** slot (symbolic, 0 to u32::MAX-101), cd (symbolic, 1–99).

**Derived check:** `cooldown_elapsed(slot, slot, cd)` — is `slot >= slot + cd`? Since cd > 0 and no wrap (assume prevents it), this is always `false`.

**Branch coverage:** Only B3 (`current < deposit + cooldown`) exercised. B2 locked out.

**Invariant:** Correct — depositing and checking in the same slot with nonzero cooldown must return false.

**Rating: STRONG** — intentionally tests one branch (negative case). Paired with proof 25 for full coverage.

---

### 25. `proof_cooldown_exact_boundary`

**Inputs:** dep_slot (symbolic, 0 to u32::MAX-101), cd (symbolic, 0–99).

**Check:** `cooldown_elapsed(dep_slot + cd, dep_slot, cd)` — is `dep_slot + cd >= dep_slot + cd`? Always true.

**Branch coverage:** Only B2 (`current >= deposit + cooldown`). Paired with proof 24.

**Weakness:** When `cd = 0`, this tests `cooldown_elapsed(dep_slot, dep_slot, 0) = true` (zero cooldown = immediately elapsed). That's correct but means cd=0 doesn't test a "real" cooldown.

**Rating: STRONG** — paired with proof 24, covers both branches of the boolean return.

---

### 26. `proof_cap_zero_uncapped`

**Inputs:** total (symbolic, full u32), dep (symbolic, full u32). cap=0 concrete.

**Branch coverage:** B1 (cap==0 → false) ✅ — locked in. B2/B3/B4 unreachable.

**Invariant:** Uncapped pool never exceeds cap.

**Rating: STRONG** — tests the specific configuration `cap=0` exhaustively over all (total, dep) pairs. The concrete cap is intentional — it's verifying the uncapped behavior.

---

### 27. `proof_cap_at_boundary`

**Inputs:** cap (symbolic, 1–99), existing (symbolic, 0 to cap).
**Derived:** dep = cap - existing (so total = cap exactly).

**Branch coverage:** B1 locked out (cap > 0). B2 impossible (99+0 < u32::MAX). B4 (total ≤ cap, total == cap) ✅.

**Invariant:** Deposit exactly at cap does not exceed.

**Rating: STRONG** — symbolic boundary test.

---

### 28. `proof_cap_above_boundary`

**Inputs:** cap (symbolic, 1–99), existing (symbolic, 0 to cap-1).
**Derived:** dep = cap - existing + 1 (one over).

**Branch coverage:** B3 (total > cap, total == cap + 1) ✅.

**Rating: STRONG** — symbolic boundary test, complement of proof 27.

---

### 29. `proof_c9_orphaned_value_blocked`

**Inputs:** pv (symbolic, 1–99), dep (symbolic, 1–99). supply=0 concrete.

**Branch coverage:** B1: `0 == 0 && pv == 0`? pv > 0 → false. B2a: `supply == 0`? → true → None ✅.

**Invariant:** Orphaned value state always returns None.

**Rating: STRONG** — proves the C9 fix holds for all pv > 0 and all dep > 0.

---

### 30. `proof_c9_valueless_lp_blocked`

**Inputs:** supply (symbolic, 1–99), dep (symbolic, 1–99). pv=0 concrete.

**Branch coverage:** B1: `supply == 0 && 0 == 0`? supply > 0 → false. B2b: `pool_value == 0`? → true → None ✅.

**Rating: STRONG**

---

### 31. `proof_c9_true_first_depositor`

**Inputs:** dep (symbolic, 1–99). supply=0, pv=0 both concrete.

**Branch coverage:** B1: `0 == 0 && 0 == 0` → true → Some(dep) ✅.

**Invariant:** First-depositor 1:1 still works after C9 fix.

**Rating: STRONG**

---

### 32. `proof_pool_value_with_flush_no_panic`

**Inputs:** 4x kani::any() — full u32 range.

**Rating: STRONG** — exhaustive panic freedom.

---

### 33. `proof_exceeds_cap_no_panic`

**Inputs:** 3x kani::any() — full u32 range.

**Rating: STRONG** — exhaustive panic freedom.

---

## Summary Table

| # | Harness | Rating | Issues |
|---|---------|--------|--------|
| 1 | `proof_deposit_withdraw_no_inflation` | **STRONG** | Tight bounds (< 20). Could add `kani::cover!` for non-vacuity witness |
| 2 | `proof_first_depositor_exact` | **STRONG** | Roundtrip property over symbolic range |
| 3 | `proof_two_depositors_conservation` | **WEAK** | Symbolic collapse: ratio locked at 1:1. Never tests fractional exchange rates |
| 4 | `proof_no_dilution` | **WEAK** | Symbolic collapse: same 1:1 lock as #3. Assertion trivially true with equality |
| 5 | `proof_flush_preserves_value` | **VACUOUS** | Tautology: calls `pool_value(dep, wd)` twice with same args. `flush` var unused |
| 6 | `proof_lp_deposit_no_panic` | **STRONG** | Full u32 range, all branches |
| 7 | `proof_collateral_withdraw_no_panic` | **STRONG** | Full u32 range, all branches |
| 8 | `proof_pool_value_no_panic` | **STRONG** | Full u32 range |
| 9 | `proof_flush_available_no_panic` | **STRONG** | Full u32 range |
| 10 | `proof_equal_deposits_equal_lp` | **VACUOUS** | Tautology: `f(x) == f(x)` |
| 11 | `proof_larger_deposit_more_lp` | **STRONG** | Monotonicity over symbolic pro-rata inputs |
| 12 | `proof_larger_burn_more_collateral` | **STRONG** | Monotonicity |
| 13 | `proof_full_burn_bounded` | **STRONG** | Full burn ≤ pool value |
| 14 | `proof_partial_less_than_full` | **STRONG** | Partial ≤ full |
| 15 | `proof_flush_bounded` | **STRONG** | All 3 saturating branches reachable |
| 16 | `proof_flush_max_then_zero` | **STRONG** | Valid-state constraints appropriate |
| 17 | `proof_pool_value_correctness` | **STRONG** | Exemplary: both branches, value assertion |
| 18 | `proof_deposit_increases_value` | **STRONG** | Strict increase |
| 19 | `proof_flush_return_conservation` | **STRONG** | 3 sub-properties, non-vacuous |
| 20 | `proof_returns_increase_value` | **STRONG** | Strict increase from returns |
| 21 | `proof_zero_deposit_zero_lp` | **WEAK** | deposit=0 concrete. Only pro-rata branch. Property doesn't hold for orphaned states |
| 22 | `proof_zero_burn_zero_col` | **WEAK** | lp=0 concrete. Only supply>0 branch |
| 23 | `proof_cooldown_no_panic` | **STRONG** | Full range |
| 24 | `proof_cooldown_not_immediate` | **STRONG** | Negative case (paired with #25) |
| 25 | `proof_cooldown_exact_boundary` | **STRONG** | Positive case (paired with #24) |
| 26 | `proof_cap_zero_uncapped` | **STRONG** | Full range for uncapped config |
| 27 | `proof_cap_at_boundary` | **STRONG** | Symbolic boundary |
| 28 | `proof_cap_above_boundary` | **STRONG** | Symbolic boundary |
| 29 | `proof_c9_orphaned_value_blocked` | **STRONG** | C9 fix verification |
| 30 | `proof_c9_valueless_lp_blocked` | **STRONG** | C9 fix verification |
| 31 | `proof_c9_true_first_depositor` | **STRONG** | C9 regression test |
| 32 | `proof_pool_value_with_flush_no_panic` | **STRONG** | Full range |
| 33 | `proof_exceeds_cap_no_panic` | **STRONG** | Full range |

## Totals

| Rating | Count | Proofs |
|--------|-------|--------|
| STRONG | 25 | #1, #2, #6–9, #11–20, #23–33 |
| WEAK | 4 | #3, #4, #21, #22 |
| VACUOUS | 2 | #5, #10 |
| UNIT TEST | 0 | — |

## Priority Fixes

1. **DELETE #5 and #10** — tautologies proving nothing. Replace with:
   - #5 → flush+full_return conservation: `pool_value_with_flush(d, w, f, f) == pool_value(d, w)`
   - #10 → delete entirely (determinism of pure functions is axiomatic in Rust)

2. **FIX #3 and #4** — add `appreciation` symbolic input to break the 1:1 ratio lock:
   - Start with pool where `supply ≠ pool_value` to exercise fractional exchange rates

3. **FIX #21 and #22** — remove `s > 0, pv > 0` assumes, handle None in assertion

4. **FIX mirror truncation bug** — add `if lp > u32::MAX as u64 { None }` guard to mirror `calc_lp_for_deposit` and `calc_collateral_for_withdraw`
