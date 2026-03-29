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

## PDA Reference

This section details all Program Derived Addresses used by the stake program.

### StakePool PDA

The stake pool account holds all global state for a given slab (market).

| Property | Value |
|----------|-------|
| **Seeds** | `[b"stake_pool", slab_pubkey]` |
| **Program ID** | Stake program ID (passed in InitPool) |
| **Owner** | Stake program (created via CPI in InitPool) |
| **Size** | 472 bytes (STAKE_POOL_SIZE) |

**Key Fields:**
- `is_initialized` — 1 if pool is active, 0 otherwise
- `admin` — Pool administrator (can call UpdateConfig, CPI admin functions)
- `admin_transferred` — 1 after TransferAdmin (required before accepting deposits)
- `slab` — The percolator market pubkey this pool manages
- `vault` — Token account holding collateral buffer (owned by vault_auth PDA)
- `lp_mint` — LP token mint (authority = vault_auth PDA)
- `cooldown_slots` — Slot delay before withdrawals allowed (must be > 0)
- `deposit_cap` — Max pool value (0 = unlimited)
- `total_deposited`, `total_lp_supply`, `total_flushed`, `total_returned`, `total_withdrawn` — Accounting totals
- `percolator_program` — Wrapper program ID (for CPI calls)

**Example derivation (Typescript using @solana/web3.js):**

```typescript
import { PublicKey } from '@solana/web3.js';

const programId = new PublicKey('...stake program...');
const slabPubkey = new PublicKey('...market slab...');

const [stakePoolPda, poolBump] = await PublicKey.findProgramAddress(
  [Buffer.from('stake_pool'), slabPubkey.toBuffer()],
  programId
);
```

### VaultAuthority PDA

The vault authority is a PDA that owns the LP mint and vault token account. It signs all vault operations.

| Property | Value |
|----------|-------|
| **Seeds** | `[b"vault_auth", stake_pool_pda]` |
| **Program ID** | Stake program ID |
| **Owner** | System program (PDA has no account, just signing authority) |
| **Used for** | Signing mint_to, burn, transfer via invoke_signed |

**Example derivation:**

```typescript
const [vaultAuthPda, vaultAuthBump] = await PublicKey.findProgramAddress(
  [Buffer.from('vault_auth'), stakePoolPda.toBuffer()],
  programId
);
```

### StakeDeposit PDA (Per-User)

Each user has a deposit PDA per pool that tracks their cooldown and LP balance.

| Property | Value |
|----------|-------|
| **Seeds** | `[b"stake_deposit", pool_pda, user_pubkey]` |
| **Program ID** | Stake program ID |
| **Owner** | Stake program (created via CPI in Deposit) |
| **Size** | 120 bytes (STAKE_DEPOSIT_SIZE) |

**Key Fields:**
- `is_initialized` — 1 if deposit is active
- `pool` — Back-reference to stake pool PDA
- `user` — User pubkey
- `last_deposit_slot` — Slot of most recent deposit (cooldown starts here)
- `lp_amount` — Total LP tokens held by this user

**Example derivation:**

```typescript
const [depositPda, depositBump] = await PublicKey.findProgramAddress(
  [Buffer.from('stake_deposit'), stakePoolPda.toBuffer(), userPubkey.toBuffer()],
  programId
);
```

### Token Accounts (Standard SPL Token)

**LP Mint Account:**
- Mint authority: vault_auth PDA (signs all mint_to and burn operations)
- Freeze authority: vault_auth PDA
- Decimals: 6

**Vault Token Account (Collateral Buffer):**
- Owner: vault_auth PDA
- Mint: collateral_mint (matches slab's collateral)
- Purpose: Holds collateral awaiting flushes to wrapper insurance

**User Collateral ATA:**
- Owner: user pubkey
- Mint: collateral_mint
- Purpose: User's collateral source/destination

**User LP ATA:**
- Owner: user pubkey
- Mint: lp_mint
- Purpose: User's LP token balance

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

# Run Kani proofs (local-only — not run in CI; see .github/workflows/kani-manual.yml for on-demand runs)
# One-time setup: cargo install --locked kani-verifier && cargo kani setup
cd kani-proofs && cargo kani --lib
```

## Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Full architecture with CPI flow diagrams
- [`docs/AUDIT.md`](docs/AUDIT.md) — 4-round security audit report
- [`docs/KANI-DEEP-ANALYSIS.md`](docs/KANI-DEEP-ANALYSIS.md) — Proof-by-proof analysis
- [`docs/WRAPPER-HARDENING.md`](docs/WRAPPER-HARDENING.md) — Wrapper foot gun limits

## Related Repositories

| Repository | Description |
|-----------|-------------|
| [percolator](https://github.com/dcccrypto/percolator) | Core risk engine crate (Rust) |
| [percolator-prog](https://github.com/dcccrypto/percolator-prog) | Solana on-chain program (wrapper) |
| [percolator-matcher](https://github.com/dcccrypto/percolator-matcher) | Reference matcher program for LP pricing |
| [percolator-sdk](https://github.com/dcccrypto/percolator-sdk) | TypeScript SDK for client integration |
| [percolator-ops](https://github.com/dcccrypto/percolator-ops) | Operations dashboard |
| [percolator-mobile](https://github.com/dcccrypto/percolator-mobile) | Solana Seeker mobile trading app |
| [percolator-launch](https://github.com/dcccrypto/percolator-launch) | Full-stack launch platform (monorepo) |

## License

Apache 2.0 — see [LICENSE](LICENSE).
