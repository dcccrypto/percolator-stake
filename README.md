# percolator-stake

Standalone Insurance LP staking program for [Percolator](https://github.com/aeyakovenko/percolator) — the permissionless perpetual futures engine on Solana.

## Architecture

PDA-admin design — the stake program's PDA **becomes** the wrapper admin, enabling isolated security audits.

```
┌─────────────────────────────────────────────────┐
│                  percolator-stake                │
│                                                  │
│  User ──► Deposit ──► Stake Vault ──► LP Mint    │
│  User ◄── Withdraw ◄─ Stake Vault ◄── LP Burn   │
│                          │                       │
│              FlushToInsurance                     │
│                          │                       │
│                    CPI TopUpInsurance             │
│                          ▼                       │
│  ┌──────────────────────────────────────────┐    │
│  │         percolator-prog (wrapper)        │    │
│  │     stake_pool PDA = wrapper admin       │    │
│  └──────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
```

**PDA derivation:**
- `stake_pool` = `[b"stake_pool", slab_pubkey]` — pool state + wrapper admin
- `vault_auth` = `[b"vault_auth", pool_pda]` — token vault authority
- `stake_deposit` = `[b"stake_deposit", pool_pda, user_pubkey]` — per-user LP position

## Instructions

| # | Instruction | Description |
|---|-------------|-------------|
| 0 | `InitPool` | Create pool, LP mint, vault for a slab |
| 1 | `Deposit` | User deposits tokens → vault, receives LP |
| 2 | `Withdraw` | Burn LP → withdraw from vault (cooldown enforced) |
| 3 | `FlushToInsurance` | Move vault tokens → wrapper insurance via CPI |
| 4 | `UpdateConfig` | Admin updates cooldown period / deposit cap |
| 5 | `TransferAdmin` | One-time transfer: human admin → pool PDA |
| 6 | `AdminSetOracleAuthority` | CPI forward to wrapper |
| 7 | `AdminSetRiskThreshold` | CPI forward to wrapper |
| 8 | `AdminSetMaintenanceFee` | CPI forward to wrapper |
| 9 | `AdminResolveMarket` | CPI forward to wrapper |
| 10 | `AdminWithdrawInsurance` | CPI WithdrawInsuranceLimited (post-resolution) |
| 11 | `AdminSetInsurancePolicy` | CPI SetInsuranceWithdrawPolicy |

## Two-Layer Safety

1. **Wrapper hardening** — constitutional bounds no admin can violate ([PR #5](https://github.com/aeyakovenko/percolator-prog/pull/5))
2. **Stake program policies** — flexible rules (cooldown, caps, flush limits) within those bounds

Security audits are fully isolated between layers.

## Verification

**176 checks, 0 failures.**

### Kani Proofs (35 harnesses)

Uses `#[kani::unwind(33)]` with u32 mirrors for CBMC tractability. Properties proven over bounded domains generalize to production u64/u128 via scale invariance.

| Category | Proofs | Key Properties |
|----------|--------|----------------|
| Conservation | 5 | Deposit→withdraw no-inflation, two-party conservation, flush+return roundtrip |
| Arithmetic Safety | 4 | Panic-freedom across full u32 input space |
| Fairness / Monotonicity | 3 | Rounding favors pool, larger deposit → more LP |
| Withdrawal Bounds | 2 | Full burn ≤ pool value, partial ≤ full |
| Flush Bounds | 2 | Flush ≤ deposited, max flush → zero remaining |
| Pool Value | 4 | Correctness, monotonicity, flush/return conservation |
| Zero Boundaries | 2 | No free LP, no free collateral |
| Cooldown | 3 | No-panic, not-immediate, exact boundary |
| Deposit Cap | 3 | Zero = uncapped, boundary precision |
| C9 Orphaned Value | 3 | All 4 LP state machine quadrants covered |
| Flush Mechanics | 2 | Exact value reduction, determinism |
| Extended Safety | 2 | Full-range panic-freedom for remaining functions |

**Rating: 25 STRONG, 6 GOOD, 4 STRUCTURAL.**

See [`docs/KANI-DEEP-ANALYSIS.md`](docs/KANI-DEEP-ANALYSIS.md) for the full proof-by-proof analysis.

### Tests (141)

| Suite | Count | Coverage |
|-------|-------|----------|
| Math | 63 | Conservation, fairness, edge cases, large values, proptest |
| Unit | 39 | Deposit, withdraw, flush, cooldown, PDA derivation |
| Proptest | 17 | Fuzz LP math across random inputs |
| Struct Layout | 10 | Bytemuck serialization roundtrips |
| CPI Tags | 9 | All wrapper instruction tags verified |
| Error Codes | 3 | Error variant mapping |

## Audit

4 rounds of security review. Full report: [`docs/AUDIT.md`](docs/AUDIT.md).

| Severity | Found | Fixed |
|----------|-------|-------|
| CRITICAL | 11 | 11 ✅ |
| HIGH | 6 | 5 ✅ |
| MEDIUM | 7 | 5 ✅ |
| LOW | 4 | 1 ✅ |

## Build

```bash
# Build BPF
cargo build-sbf

# Run tests
cargo test

# Run Kani proofs (requires cargo-kani)
cd kani-proofs && cargo kani --lib
```

## Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Full architecture with CPI flow diagrams
- [`docs/AUDIT.md`](docs/AUDIT.md) — 4-round security audit report
- [`docs/KANI-DEEP-ANALYSIS.md`](docs/KANI-DEEP-ANALYSIS.md) — Proof-by-proof analysis
- [`docs/WRAPPER-HARDENING.md`](docs/WRAPPER-HARDENING.md) — Wrapper foot gun limits

## License

MIT
