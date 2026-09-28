# Upgrade authority: current state, policy, and rotation runbook (#240)

The BPF upgrade authority of a program can replace its bytecode at any time. For a
fund-custody program such as this stake/insurance vault, a single hot key as upgrade
authority means **one compromised key can drain the whole TVL**: deploy a malicious
binary at the same program id, then call it. No on-chain check in this repository can
defend against that, because the replacement binary does not have to contain those checks.

This document records **what the authority actually is today**, the **policy** it must
meet before mainnet, and the **runbook** to get there. `README.md` and
`scripts/check-upgrade-authority.sh` both link here. (PR #247 added those links, but the
file itself was never committed. This file fills that gap.)

## 1. Current state (observed on-chain, read-only)

Observed 2026-09-28 with `solana program show -u devnet <id>`:

| program | cluster | program id | upgrade authority | authority type | last deploy slot |
|---|---|---|---|---|---|
| percolator-stake | devnet | `GCHhcgwPyrai8SWHEVWw3odedguFXEtJobNnWSfWBCU3` | `FbTbDeGWQpjrEqJdqoBHX3sTWHoAmU2xywD7wyxH6WC7` | **single EOA** (System-owned wallet) | 502232296 |
| percolator-prog (wrapper, v18) | devnet | `GnwdeQrAh4qzChJeVLrM21CXXWC1akjLH3DiijwzEEYZ` | `FbTbDeGW…6WC7` (same key) | single EOA | 502228888 |
| percolator-nft | devnet | `CNGBPZRALk9Xu8BdgWNyrLJ7daQ9eJYFf1GnEEC7YCU3` | `FbTbDeGW…6WC7` (same key) | single EOA | 502619804 |
| percolator-match | devnet | `4seJWjv3R5qfXY8R5ntuPHWsoqcVvaxvfFSnU2AnGMhT` | `FbTbDeGW…6WC7` (same key) | single EOA | 502240857 |

Stake ProgramData account: `zBPoHsdoc58UZb6EkZbJNuirr4Seo4bNrSPSumT5RNy`.

What this means:

- **One key upgrades all four devnet programs.** It is also the devnet deploy fee payer
  and every devnet market's oracle authority. A compromise of that one key reaches every
  program and every market.
- **No mainnet deployment of percolator-stake exists.** `src/lib.rs` deliberately has no
  mainnet `declare_id!`. That is the only reason the current state is acceptable: devnet
  holds no real value.
- The gate fails today, **as it should**:

  ```text
  $ scripts/check-upgrade-authority.sh --cluster https://api.devnet.solana.com \
      --program GCHhcgwPyrai8SWHEVWw3odedguFXEtJobNnWSfWBCU3 \
      --program CNGBPZRALk9Xu8BdgWNyrLJ7daQ9eJYFf1GnEEC7YCU3 \
      --program GnwdeQrAh4qzChJeVLrM21CXXWC1akjLH3DiijwzEEYZ
  FAIL  GCHhcgw… — upgrade authority FbTbDeGW… is NEITHER burned NOR allowlisted
  FAIL  CNGBPZR… — …
  FAIL  GnwdeQr… — …
  BLOCKED — at least one program fails the upgrade-authority policy (#240).
  ```

#240 stays open until this table shows a burned or multisig authority for every
**mainnet** program id and the gate passes against mainnet.

Re-verify at any time (read-only, no key needed):

```bash
solana program show -u devnet GCHhcgwPyrai8SWHEVWw3odedguFXEtJobNnWSfWBCU3
solana account      -u devnet FbTbDeGWQpjrEqJdqoBHX3sTWHoAmU2xywD7wyxH6WC7   # Owner: 1111…1111 => plain wallet, not a multisig
```

## 2. Policy

| cluster | requirement |
|---|---|
| devnet | A single key is tolerated, because devnet holds no real value. Record it in the table above and keep it current. |
| mainnet | Before the program custodies any user funds, the upgrade authority MUST be **(a)** a Squads v4 multisig vault PDA with threshold ≥ 2 and ≥ 3 members on separate devices/custodians, or **(b)** burned (`--final`). A single EOA is never acceptable, even briefly after deploy. |

Additional rules:

1. **Deploy from a staging key, then transfer in the same session.** Mainnet deploys may
   use a throwaway deployer key only if `set-upgrade-authority` to the multisig runs
   immediately after, **before** the program is announced or any pool is initialized.
   Then run the gate (§4).
2. **One authority per trust domain, not one per cluster.** The wrapper, stake, nft and
   match programs can share one multisig. The multisig must not also be a market oracle
   authority or a fee payer, so a hot operational key never doubles as upgrade authority.
3. **Burning is irreversible.** Choose `--final` only once the program is frozen for good.
   A burned stake program can never receive a security fix, and every stake pool is
   bound to the wrapper id at compile time (`processor.rs` allowlist). Decide this
   before launch day, not during it.
4. **The allowlist is part of the policy.** The multisig vault address goes into the
   `UPGRADE_AUTH_ALLOWLIST` repo variable. Any other value there is a policy change
   and needs review.

## 3. Rotation runbook

> Changing an upgrade authority is a **human-only** action. Automation and agents must
> not run the commands in this section. They may run §4 (read-only).

### 3a. Transfer to a Squads multisig (recommended)

1. Create a Squads v4 multisig (threshold ≥ 2 of ≥ 3) and note its **vault PDA**
   (vault index 0). The upgrade authority must be the *vault*, not the multisig
   config account.
2. Dry-run on devnet first against a scratch program, and confirm that an upgrade
   proposed and executed through Squads succeeds.
3. For each program id:

   ```bash
   solana program set-upgrade-authority <PROGRAM_ID> \
     --new-upgrade-authority <SQUADS_VAULT_PDA> \
     --skip-new-upgrade-authority-signer-check \
     -k <CURRENT_AUTHORITY_KEYPAIR> -u <cluster>
   ```

   `--skip-new-upgrade-authority-signer-check` is required because a PDA cannot sign.
   Before sending, double-check the vault address character by character. A typo here
   is unrecoverable.
4. Verify (§4). Then retire the old key: it must not remain a signer anywhere else.

### 3b. Burn (make immutable)

```bash
solana program set-upgrade-authority <PROGRAM_ID> --final -k <CURRENT_AUTHORITY_KEYPAIR> -u <cluster>
```

Afterwards `solana program show` reports `Authority: none`, and the gate treats that
as burned.

### 3c. Future upgrades under a multisig

Build reproducibly (the stake devnet build is
`cargo build-sbf -- --features devnet`, the mainnet build is plain). Write the buffer
with `solana program write-buffer`, then `set-buffer-authority` to the Squads vault.
Propose the upgrade in Squads. Each signer independently rebuilds from the tagged
commit and compares the buffer hash (`solana program dump` + `sha256sum`) before
approving.

## 4. Verification gate

```bash
scripts/check-upgrade-authority.sh \
  --cluster https://api.mainnet-beta.solana.com \
  --allow <SQUADS_VAULT_PDA> \
  --program <STAKE_ID> --program <WRAPPER_ID> --program <NFT_ID> --program <MATCH_ID>
```

- Exit code 0 means every program is burned or held by an allowlisted authority.
- An empty `--allow` list means the policy is "must be burned".
- In CI, set the `UPGRADE_AUTH_PROGRAMS` and `UPGRADE_AUTH_ALLOWLIST` repo variables,
  then run the `upgrade-authority-gate` workflow (manual dispatch).

## 5. Open decisions (owner: maintainers)

- [ ] Multisig vs burn for each mainnet program (recommended: multisig for wrapper and
      stake, since both still take security fixes).
- [ ] Squads member set and threshold.
- [ ] Separate the devnet upgrade key from the devnet oracle-authority / fee-payer key.
      Today they are the same key, which widens the blast radius of any leak even on
      devnet.
- [ ] After each rotation, update the §1 table and re-run §4.
