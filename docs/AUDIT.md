# percolator-stake Comprehensive Audit

**Date:** 2026-02-18
**Auditor:** Cobra (automated)
**Files:** 8 source files, 2491 lines, 18 Kani proofs, 37 unit tests

---

## CRITICAL Issues

### C0: CPI Instruction Tag Mismatch (Tags 21/22/23)
**File:** `cpi.rs:19-20`
**SEVERITY:** CRITICAL — would invoke wrong wrapper instruction
```rust
// BEFORE (WRONG):
const TAG_SET_INSURANCE_WITHDRAW_POLICY: u8 = 21; // Actually AdminForceCloseAccount!
const TAG_WITHDRAW_INSURANCE_LIMITED: u8 = 22;     // Actually SetInsuranceWithdrawPolicy!

// AFTER (CORRECT):
const TAG_SET_INSURANCE_WITHDRAW_POLICY: u8 = 22;
const TAG_WITHDRAW_INSURANCE_LIMITED: u8 = 23;
```
**Impact:** Tag 21 in the wrapper is `AdminForceCloseAccount`, not insurance policy.
- `AdminSetInsurancePolicy` → would force-close a user's position (fund loss)
- `AdminWithdrawInsurance` → would set insurance policy (no-op at best, wrong config at worst)

**Root cause:** Tag 21 (`AdminForceCloseAccount`) was added to wrapper after our initial tag mapping. We incorrectly assumed tags were contiguous from 20.

**Fix:** Updated tags + added 9 CPI tag verification tests as regression guard.


### C1: `process_withdraw` — LP supply decremented with `saturating_sub` instead of `checked_sub`
**File:** `processor.rs:334`
```rust
pool.total_lp_supply = pool.total_lp_supply.saturating_sub(lp_amount);
```
**Risk:** If `lp_amount > total_lp_supply` (shouldn't happen given LP burn checks, but defense-in-depth), LP supply silently becomes 0 instead of erroring. Could mask accounting bugs.

**Fix:** Use `checked_sub().ok_or(StakeError::Overflow)?` like the other state updates.

### C2: `process_withdraw` — deposit LP amount decremented with `saturating_sub`
**File:** `processor.rs:339`
```rust
deposit_mut.lp_amount = deposit_mut.lp_amount.saturating_sub(lp_amount);
```
**Same issue as C1.** Silent underflow instead of explicit error.

### C3: `process_admin_withdraw_insurance` — `total_returned` never updated
**File:** `processor.rs:493-527`
The pool has a `total_returned` field meant to track collateral returned from insurance. But `process_admin_withdraw_insurance` never increments it after CPI succeeds. This means:
1. Pool value calculation is wrong after insurance withdrawal
2. LP holders can't get their proportional share of returned insurance

**Fix:** After CPI succeeds, increment `pool.total_returned += amount`.

### C4: `pool_value()` doesn't account for `total_returned`
**File:** `state.rs:110`
```rust
pub fn total_pool_value(&self) -> Option<u64> {
    crate::math::pool_value(self.total_deposited, self.total_withdrawn)
}
```
**Problem:** Pool value = `deposited - withdrawn`. But when insurance is returned (via AdminWithdrawInsurance), those tokens go into the vault and belong to LP holders. The returned amount should be added to pool value:
```
pool_value = deposited - withdrawn + returned
```
Without this, LP token price doesn't reflect insurance returns.

## HIGH Issues

### H1: `process_deposit` — no `admin_transferred` check
**File:** `processor.rs:166-260`
Deposits are accepted even before `TransferAdmin` is called. This means users can deposit into a pool where the admin hasn't yet transferred control — the admin could be a malicious human who drains the wrapper instead of the stake program controlling it.

**Recommendation:** Either require `admin_transferred == 1` for deposits, OR clearly document this as intentional (bootstrap period).

### H2: `process_flush_to_insurance` — no admin check
**File:** `processor.rs:358-416`
FlushToInsurance is permissionless (any signer can trigger). While the wrapper's TopUpInsurance is also permissionless, this means anyone can drain the vault into insurance at any time, even against LP holders' interests.

**Risk:** A griefer could flush all vault funds to insurance, leaving nothing for user withdrawals. Users would need to wait for market resolution + AdminWithdrawInsurance to get funds back.

**Recommendation:** Either make this admin-only, or add a max flush percentage per epoch.

### H3: `cpi_withdraw_insurance_limited` — slab marked as `signer` in AccountMeta
**File:** `cpi.rs:312`
```rust
AccountMeta::new(*slab.key, true),  // slab (writable)
```
The slab should be writable but NOT a signer. The wrapper expects slab to be writable only. Marking it as a signer would cause the CPI to fail because we don't have the slab's signature.

**Fix:** Change to `AccountMeta::new(*slab.key, false)`.

### H4: `cpi_withdraw_insurance_limited` — stake_vault and wrapper_vault marked as signers
**File:** `cpi.rs:313-314`
```rust
AccountMeta::new(*stake_vault.key, true),    // authority_ata (writable)
AccountMeta::new(*wrapper_vault.key, true),  // insurance vault (writable)
```
Same issue — these should be `new(*key, false)` (writable, not signer).

### H5: Instruction tag deserialization doesn't validate unused bytes
**File:** `instruction.rs`
For variable-length instructions (UpdateConfig, AdminSetInsurancePolicy), extra trailing bytes after the expected fields are silently ignored. This is standard but could mask bugs.

## MEDIUM Issues

### M1: `math.rs` has both in-file Kani proofs AND separate `kani-proofs/` crate
**Duplication:** The same mathematical properties are proven in two places:
1. `src/math.rs` — uses u64/u128 (production types) with large bounds (1B) — THESE WILL TIMEOUT
2. `kani-proofs/src/lib.rs` — uses u32/u64 (narrow types) with tight bounds — THESE PASS

The `math.rs` proofs give a false sense of security since they'll never actually run successfully on this hardware. They should be removed or marked as requiring a beefy CI runner.

### M2: `StakePool._reserved` is 96 bytes — consider versioning
If the struct needs to change, there's no version field to distinguish old vs new layouts. The `_reserved` field provides space but no upgrade mechanism.

### M3: Missing `deposit_pda.pool` validation in `process_withdraw`
**File:** `processor.rs:306`
The withdraw handler checks `deposit.user` but not `deposit.pool`. A deposit PDA from a different pool (if PDA collision existed) could pass validation. Realistically impossible with PDA derivation, but defense-in-depth.

### M4: No reentrancy guard
CPI calls could theoretically re-enter the program. While Solana's account locking model prevents most reentrancy, explicit guards would be extra safety.

## LOW Issues

### L1: `process_init_pool` doesn't validate collateral_mint matches slab
The pool stores `collateral_mint` but never verifies it matches the slab's actual collateral mint on-chain. If wrong, deposits would work but CPI operations would fail with token mismatches.

### L2: No event emission (logs only)
The program uses `msg!()` for logging but doesn't emit structured events that indexers could parse. Consider using Anchor-style event formats.

### L3: `cpi_top_up_insurance` — signer_ata marked as writable but should verify ownership
The CPI constructs the correct accounts but doesn't independently verify that the vault token account is owned by the vault_auth PDA at the Rust level (relies on wrapper to check).

---

## Kani Proof Coverage Assessment

### Currently Proven (kani-proofs/ — 18 harnesses, all PASS)
✅ Conservation (deposit→withdraw, first depositor, two depositors)
✅ Arithmetic safety (no panics on any input — 4 functions)
✅ Monotonicity (larger deposit → more LP, larger burn → more collateral)
✅ Withdrawal bounds (full burn ≤ pool value, partial ≤ full)
✅ Flush bounds (available ≤ deposited, max flush → 0)
✅ Pool value correctness (None iff overdrawn, deposit increases value)
✅ Zero boundaries (0 in → 0 out)

### NOT Proven (Gaps)
❌ **Dilution attack resistance** — Late depositor can't dilute early depositors' share
❌ **Rounding direction** — LP minting rounds DOWN (pool-favoring, not user-favoring)
❌ **Withdrawal rounding** — Collateral rounds DOWN (pool-favoring)
❌ **Pool value with returns** — pool_value + total_returned consistency
❌ **Flush conservation** — flush doesn't change total pool value
❌ **Three+ depositor conservation** — generalization beyond two
❌ **LP supply invariant** — sum of all deposits' LP == total_lp_supply
❌ **Instruction serialization roundtrip** — pack/unpack consistency
❌ **Cooldown enforcement** — slot arithmetic correctness
❌ **Deposit cap enforcement** — overflow-safe cap checking

### NOT Proven (math.rs in-file — BROKEN)
⚠️ The u64/u128 Kani proofs in `math.rs` will timeout on CBMC. Either:
1. Remove them (rely on kani-proofs/ crate)
2. Reduce bounds to match kani-proofs/
3. Mark with `#[cfg(kani_full)]` for CI-only runs on beefy hardware
