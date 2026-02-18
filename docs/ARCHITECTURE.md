# percolator-stake — PDA Admin Architecture

## Overview

```
┌─────────────────────────────────────────────────────────┐
│                    percolator-stake                       │
│                  (policy + staking)                       │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌─────────────────────┐   │
│  │  LP Mint  │  │  Vault   │  │  Admin CPI Layer    │   │
│  │  (mint/   │  │ (buffer  │  │  - SetOracle        │   │
│  │   burn)   │  │  tokens) │  │  - SetRisk          │   │
│  └─────┬─────┘  └────┬─────┘  │  - ResolveMarket    │   │
│        │              │        │  - WithdrawInsurance │   │
│        │              │        └──────────┬───────────┘   │
│        │              │                   │               │
│        │         FlushToInsurance    CPI (PDA signs       │
│        │         (CPI TopUpIns)     as wrapper admin)     │
└────────┼──────────────┼───────────────────┼──────────────┘
         │              │                   │
         │              ▼                   ▼
┌────────┴──────────────────────────────────────────────────┐
│              percolator-prog (thin wrapper)                │
│                                                            │
│  header.admin = stake_pool PDA                             │
│                                                            │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────────┐  │
│  │  Slab    │  │  Insurance   │  │  Risk Engine       │  │
│  │  (market │  │  Fund        │  │  (pure math)       │  │
│  │   state) │  │  (in vault)  │  │                    │  │
│  └──────────┘  └──────────────┘  └────────────────────┘  │
│                                                            │
│  Hardened: bounded params, rate limits, cooldowns          │
└────────────────────────────────────────────────────────────┘
```

## PDA Derivation

```
stake_pool PDA:    [b"stake_pool", slab_pubkey]  → wrapper admin
vault_auth PDA:    [b"vault_auth", pool_pda]     → LP mint + vault authority
stake_deposit PDA: [b"stake_deposit", pool_pda, user_pubkey]
```

## Setup Flow

```
1. Human creates market on wrapper (InitMarket, human = admin)
2. Human deploys percolator-stake, calls InitPool(slab, config)
   → Creates: pool PDA, LP mint, collateral vault
3. Human calls TransferAdmin on stake program
   → CPI UpdateAdmin: wrapper admin = pool PDA
   → pool.admin_transferred = true
4. From now on, all admin operations go through stake program
```

## Deposit Flow

```
User → Deposit(amount)
  1. Transfer tokens: user ATA → stake vault
  2. Mint LP tokens to user (pro-rata)
  3. Update: total_deposited += amount, total_lp_supply += lp
  4. Create/update StakeDeposit PDA (cooldown tracking)
```

## Flush to Insurance Flow

```
Anyone → FlushToInsurance(amount)
  1. Verify: amount ≤ (deposited - withdrawn - flushed)
  2. CPI TopUpInsurance:
     - vault_auth PDA signs as "signer"
     - stake vault = "signer_ata" (owned by vault_auth ✓)
     - tokens move: stake vault → wrapper vault
     - wrapper engine.insurance_fund += units
  3. Update: total_flushed += amount
```

## Withdraw Flow

```
User → Withdraw(lp_amount)
  1. Check cooldown (slots since last deposit)
  2. Calculate collateral = lp_amount * pool_value / total_lp_supply
  3. Burn LP tokens from user
  4. Transfer: stake vault → user ATA
  5. Update: total_withdrawn += collateral, total_lp_supply -= lp
  
  NOTE: Withdrawal limited by vault balance (buffer).
  If most funds flushed to insurance, user may need to wait
  for market resolution and AdminWithdrawInsurance.
```

## Admin CPI Flow (any admin operation)

```
Pool admin (human) → AdminSetX(params)
  1. Verify: signer = pool.admin (human who controls the pool)
  2. Verify: pool.admin_transferred = true
  3. Derive pool PDA seeds for signing
  4. CPI to wrapper with pool PDA as signer (= wrapper admin)
  5. Wrapper executes: require_admin(header.admin, pool_pda) ✓
```

## Insurance Return Flow (post-resolution)

```
Pool admin → AdminResolveMarket
  → CPI ResolveMarket (pool PDA signs as admin)
  → Wrapper enters withdraw-only mode

Pool admin → AdminWithdrawInsurance  
  → CPI WithdrawInsurance (pool PDA signs as admin)
  → Tokens: wrapper vault → pool PDA's ATA → stake vault
  → LP holders can now withdraw full value
```

## Security Model

### Two Layers

1. **Wrapper (constitution):** Hard bounds on parameters. No admin can violate.
   - Risk threshold: bounded min/max
   - Maintenance fee: capped
   - Oracle authority: rate-limited changes
   - Market resolution: minimum age cooldown
   - Admin transfer: two-step (proposed)

2. **Stake program (policy):** Flexible rules within constitutional bounds.
   - Deposit caps
   - Withdrawal cooldowns  
   - Flush ratios
   - Who can trigger admin operations
   - LP token economics

### Audit Isolation

- **Wrapper audit:** Focus on math correctness, fund conservation, PDA derivation
- **Stake audit:** Focus on LP economics, policy enforcement, CPI safety
- Changes to stake program don't require re-auditing wrapper (and vice versa)

## Known Limitations (v1)

1. **WithdrawInsurance requires RESOLVED market** — LP stakers can't reclaim
   flushed insurance from active markets. Future wrapper change could add
   bounded insurance withdrawal for live markets.

2. **AdminWithdrawInsurance needs pool PDA-owned ATA** — The wrapper's
   `verify_token_account` checks that the admin's ATA is owned by the admin
   pubkey. Pool PDA needs a dedicated ATA created before this call.

3. **No live insurance yield tracking** — LP value based on vault balance +
   flushed amounts, not real-time insurance fund growth. Future: read slab
   data to get actual insurance_fund balance.

4. **Single-slab pools** — Each pool manages one market. Multi-slab pools
   would require different PDA derivation and more complex accounting.
