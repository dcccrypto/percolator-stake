# percolator-stake

Insurance LP staking program for [Percolator](https://github.com/dcccrypto/percolator), a perpetual futures protocol on Solana. Users deposit collateral into a per-market pool and receive LP tokens. The pool can flush collateral into the wrapper's insurance fund by CPI and take it back after resolution.

The pool PDA becomes the wrapper's admin for that market, so cooldowns, deposit caps and flush limits live in this program and the wrapper stays small.

## How it works

PDAs (all derived under this program's ID):

| PDA | Seeds | Purpose |
|-----|-------|---------|
| `stake_pool` | `[b"stake_pool", slab]` | Pool state; wrapper admin for the market |
| `vault_auth` | `[b"vault_auth", stake_pool]` | Owns the collateral vault and LP mint |
| `stake_deposit` | `[b"stake_deposit", stake_pool, user]` | Per-user deposit slot and LP amount |

The core flow is `InitPool`, `Deposit`, `Withdraw` (after a cooldown) and `FlushToInsurance`. The program also has admin handoff and cooldown-change instructions, insurance authority bind/rotate/burn, fee accrual, a trading-LP pool mode and several CPI proxies to the wrapper.

Instruction tags, data layouts and account lists are documented on the `StakeInstruction` enum in [`src/instruction.rs`](src/instruction.rs). Account layouts are in [`src/state.rs`](src/state.rs).

The pool's `percolator_program` field is checked against an allowlist of wrapper program IDs; the stake program will not CPI into anything else. The devnet wrapper ID is compiled in only with the `devnet` feature, so it cannot end up in a mainnet build.

## Build and test

```bash
cargo build-sbf                  # SBF binary (mainnet allowlist)
cargo build-sbf -- --features devnet
cargo test
```

Kani proofs live in `kani-proofs/` and are not run in CI by default (see `.github/workflows/kani-manual.yml`):

```bash
cargo install --locked kani-verifier && cargo kani setup
cd kani-proofs && cargo kani --lib
```

## Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): architecture and CPI flow
- [`docs/AUDIT.md`](docs/AUDIT.md): audit notes
- [`docs/KANI-DEEP-ANALYSIS.md`](docs/KANI-DEEP-ANALYSIS.md): what the Kani harnesses cover
- [`docs/WRAPPER-HARDENING.md`](docs/WRAPPER-HARDENING.md): wrapper limits the stake program relies on
- [`docs/SECURITY-UPGRADE-AUTHORITY.md`](docs/SECURITY-UPGRADE-AUTHORITY.md): upgrade-authority policy and rotation runbook

## Deployments

Program IDs change on redeploy, so none are listed here. The current devnet IDs are pinned in [percolator-sdk](https://github.com/dcccrypto/percolator-sdk) (`src/config/program-ids.ts`). The upgrade-authority doc sets the policy for any mainnet use: the upgrade authority must be a multisig or burned.

## Related repositories

- [percolator](https://github.com/dcccrypto/percolator): risk engine
- [percolator-prog](https://github.com/dcccrypto/percolator-prog): on-chain wrapper program
- [percolator-sdk](https://github.com/dcccrypto/percolator-sdk): TypeScript SDK
- [percolator-launch](https://github.com/dcccrypto/percolator-launch): web app

## License

Apache-2.0, see [LICENSE](LICENSE).
