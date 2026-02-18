# Wrapper Hardening Proposal — Remove Admin Foot Guns

> "It's good to limit the admin key to remove any obvious foot guns that an external
> program that is controlling it would accidentally set off" — Toly

## Context

With the PDA-admin architecture, the percolator wrapper's admin is now a program (percolator-stake),
not a human. A buggy admin program could accidentally trigger catastrophic operations.
The wrapper should have defense-in-depth: hard limits that NO admin (human or program) can violate.

## Current Admin Operations & Risk Assessment

| Tag | Instruction | Risk Level | Current Guard | Foot Gun |
|-----|-------------|-----------|---------------|----------|
| 11 | SetRiskThreshold | HIGH | None — any u128 | Bad threshold → cascading liquidations |
| 12 | UpdateAdmin | CRITICAL | None | Accidental lockout (set to zero/wrong addr) |
| 13 | CloseSlab | MEDIUM | vault must be 0 | Destroy market (safe if vault empty) |
| 15 | SetMaintenanceFee | HIGH | None — any u128 | Drain users via excessive fees |
| 16 | SetOracleAuthority | HIGH | None | Set malicious oracle, manipulate prices |
| 18 | SetOraclePriceCap | MEDIUM | None — any u64 | Remove circuit breakers (set to 0) |
| 19 | ResolveMarket | CRITICAL | Requires oracle price set | Force-close active market |
| 20 | WithdrawInsurance | HIGH | Requires RESOLVED + all positions closed | Drain insurance after force-resolve |
| 21 | SetInsuranceWithdrawPolicy | MEDIUM | Requires RESOLVED | Set bad policy parameters |

## Proposed Hardening Changes

### 1. Bound `SetRiskThreshold` (Priority: HIGH)

**Problem:** Any `u128` value accepted. An extreme threshold could trigger mass liquidations.

**Fix:** Add min/max bounds as compile-time constants:
```rust
const MIN_RISK_THRESHOLD: u128 = 100;          // Floor — can't go below
const MAX_RISK_THRESHOLD: u128 = 1_000_000_000; // Ceiling — can't go above

// In SetRiskThreshold handler:
if new_threshold < MIN_RISK_THRESHOLD || new_threshold > MAX_RISK_THRESHOLD {
    return Err(PercolatorError::InvalidConfigParam.into());
}
```

### 2. Cap `SetMaintenanceFee` (Priority: HIGH)

**Problem:** Any `u128` fee accepted. Extreme fee = drain user collateral.

**Fix:** Hard cap on fee per slot:
```rust
// Max maintenance fee: 100 units per slot (~0.08% per hour at 400ms slots)
const MAX_MAINTENANCE_FEE: u128 = 100;

// In SetMaintenanceFee handler:
if new_fee > MAX_MAINTENANCE_FEE {
    return Err(PercolatorError::InvalidConfigParam.into());
}
```

### 3. Two-Step `UpdateAdmin` (Priority: CRITICAL)

**Problem:** Single call transfers admin. Typo in address = permanent lockout.
Especially dangerous when admin is a PDA — wrong derivation = unrecoverable.

**Fix:** Propose → Accept pattern:
```rust
// New field in SlabHeader (use _reserved bytes):
pub pending_admin: [u8; 32],

// Step 1: UpdateAdmin sets pending_admin (current admin signs)
// Step 2: New AcceptAdmin instruction (pending admin signs)
// Admin only changes when BOTH steps complete.
```

**Alternative (lighter):** Add a `burn_admin` flag that prevents setting admin to `[0u8; 32]`.
The two-step approach is safer but requires more state.

### 4. `ResolveMarket` Cooldown (Priority: HIGH)

**Problem:** Admin can resolve a market immediately after creation. This force-closes
all positions at the admin oracle price — potential for abuse.

**Fix:** Minimum market age before resolution:
```rust
// Market must be alive for at least 24 hours (at ~2.5 slots/sec)
const MIN_MARKET_AGE_SLOTS: u64 = 216_000; // ~24 hours

// In ResolveMarket handler:
// Store creation_slot in header (use _reserved bytes)
if clock.slot < creation_slot + MIN_MARKET_AGE_SLOTS {
    return Err(ProgramError::InvalidAccountData);
}
```

### 5. `SetOracleAuthority` Rate Limit (Priority: MEDIUM)

**Problem:** Oracle authority can be changed instantly. A compromised admin
could set a malicious oracle and push bad prices in the same block.

**Fix:** Cooldown between authority changes:
```rust
// Minimum 1000 slots (~6.5 min) between oracle authority changes
const ORACLE_AUTH_COOLDOWN_SLOTS: u64 = 1000;

// Track last_oracle_auth_change_slot in config (_reserved or new field)
if clock.slot < last_oracle_auth_change_slot + ORACLE_AUTH_COOLDOWN_SLOTS {
    return Err(ProgramError::InvalidAccountData);
}
```

### 6. `SetOraclePriceCap` Floor (Priority: MEDIUM)

**Problem:** Setting cap to 0 disables circuit breaker entirely.
A program admin might accidentally disable this protection.

**Fix:** Minimum cap when non-zero:
```rust
// If setting a cap, must be at least 100 e2bps (1%)
const MIN_ORACLE_PRICE_CAP: u64 = 100_00; // 1% in e2bps

// Allow 0 (disabled) but if enabled, must be >= minimum
if max_change_e2bps != 0 && max_change_e2bps < MIN_ORACLE_PRICE_CAP {
    return Err(PercolatorError::InvalidConfigParam.into());
}
```

### 7. Prevent Admin Self-Burn (Priority: LOW)

**Problem:** `UpdateAdmin` can set admin to all zeros, permanently locking the market.
No admin = no resolve, no config changes, no insurance withdrawal ever.

**Fix:**
```rust
if new_admin == Pubkey::default() {
    return Err(PercolatorError::InvalidConfigParam.into());
}
```

## Implementation Order

1. **SetRiskThreshold bounds** — easy, high impact
2. **SetMaintenanceFee cap** — easy, high impact
3. **Prevent admin self-burn** — one line, prevents lockout
4. **ResolveMarket cooldown** — needs creation_slot storage, high impact
5. **SetOracleAuthority rate limit** — needs last_change_slot, medium impact
6. **SetOraclePriceCap floor** — easy, medium impact
7. **Two-step UpdateAdmin** — most complex, but strongest protection

## Backward Compatibility

All changes are additive bounds on existing instructions. No new instructions needed
(except possibly AcceptAdmin for two-step). Existing valid usage stays valid as long
as parameters are within sane ranges.

## Notes

- These are **wrapper-level** safety rails, independent of the stake program
- The stake program adds its OWN policy layer on top (cooldowns, caps, etc.)
- Together they form defense-in-depth: even a fully compromised stake program
  can't set catastrophically bad parameters on the wrapper
- Values for bounds should be reviewed with Toly — these are starting proposals
