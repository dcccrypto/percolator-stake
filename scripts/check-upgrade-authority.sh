#!/usr/bin/env bash
#
# #240 — Pre-mainnet upgrade-authority gate.
#
# A BPF program's upgrade authority can replace the program bytecode at will. On a
# fund-custody program (this stake/insurance vault, the wrapper, etc.) a SINGLE-EOA
# upgrade authority is a full-TVL-drain risk: one compromised key → malicious upgrade →
# drain. A program CANNOT constrain its own deployer's key choice, so this is enforced
# operationally: before mainnet use, every program's upgrade authority MUST be either
#   (a) BURNED (immutable — deployed/last-upgraded with `--final`), or
#   (b) held by an ALLOWLISTED governance multisig (e.g. a Squads vault PDA).
#
# This script is that gate. Run it in CI and as a manual pre-mainnet check. It exits
# non-zero if ANY checked program's authority is neither burned nor allowlisted.
#
# Usage:
#   scripts/check-upgrade-authority.sh \
#     --cluster https://api.mainnet-beta.solana.com \
#     --allow <GOVERNANCE_MULTISIG_AUTHORITY> [--allow <ANOTHER>] \
#     --program <PROGRAM_ID> [--program <PROGRAM_ID> ...]
#
# Env fallbacks: SOLANA_CLUSTER, UPGRADE_AUTH_ALLOWLIST (comma-separated),
#                UPGRADE_AUTH_PROGRAMS (comma-separated).
#
# Notes:
#   * An EMPTY allowlist means the policy is "must be burned" (strictest).
#   * The System Program id (all-1s) is treated as "no authority" (burned).
#   * Requires the `solana` CLI on PATH.
#
set -euo pipefail

CLUSTER="${SOLANA_CLUSTER:-https://api.mainnet-beta.solana.com}"
ALLOW=()
PROGRAMS=()

# Seed from env (comma-separated) so CI can configure via secrets/vars.
if [[ -n "${UPGRADE_AUTH_ALLOWLIST:-}" ]]; then
  IFS=',' read -r -a _env_allow <<< "$UPGRADE_AUTH_ALLOWLIST"
  ALLOW+=("${_env_allow[@]}")
fi
if [[ -n "${UPGRADE_AUTH_PROGRAMS:-}" ]]; then
  IFS=',' read -r -a _env_progs <<< "$UPGRADE_AUTH_PROGRAMS"
  PROGRAMS+=("${_env_progs[@]}")
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cluster) CLUSTER="$2"; shift 2;;
    --allow)   ALLOW+=("$2"); shift 2;;
    --program) PROGRAMS+=("$2"); shift 2;;
    -h|--help) sed -n '2,40p' "$0"; exit 0;;
    *) echo "unknown argument: $1" >&2; exit 2;;
  esac
done

if [[ ${#PROGRAMS[@]} -eq 0 ]]; then
  echo "error: no --program given (and UPGRADE_AUTH_PROGRAMS unset)" >&2
  exit 2
fi
if ! command -v solana >/dev/null 2>&1; then
  echo "error: solana CLI not found on PATH" >&2
  exit 2
fi

SYSTEM_PROGRAM="11111111111111111111111111111111"
fail=0

echo "Upgrade-authority gate — cluster: $CLUSTER"
if [[ ${#ALLOW[@]} -eq 0 ]]; then
  echo "policy: authority MUST be burned (no governance allowlist provided)"
else
  echo "policy: authority must be burned OR one of: ${ALLOW[*]}"
fi
echo "------------------------------------------------------------------"

for pid in "${PROGRAMS[@]}"; do
  [[ -z "$pid" ]] && continue
  out="$(solana program show --url "$CLUSTER" "$pid" 2>&1 || true)"

  # Burned / immutable: solana reports the program as not upgradeable.
  if printf '%s' "$out" | grep -qiE 'not upgradeable|is not upgradeable|immutable'; then
    echo "PASS  $pid — immutable (upgrade authority burned)"
    continue
  fi

  # Otherwise parse the "Authority: <pubkey>" line.
  auth="$(printf '%s\n' "$out" | awk -F'Authority:' '/Authority:/{gsub(/[[:space:]]/,"",$2); print $2; exit}')"

  if [[ -z "$auth" || "$auth" == "none" || "$auth" == "None" || "$auth" == "$SYSTEM_PROGRAM" ]]; then
    echo "PASS  $pid — no upgrade authority (burned)"
    continue
  fi

  ok=0
  for a in "${ALLOW[@]:-}"; do
    [[ -n "$a" && "$auth" == "$a" ]] && ok=1
  done
  if [[ $ok -eq 1 ]]; then
    echo "PASS  $pid — authority $auth is an allowlisted governance signer"
  else
    echo "FAIL  $pid — upgrade authority $auth is NEITHER burned NOR allowlisted"
    echo "        → single-EOA / unknown authority on a fund-custody program is a"
    echo "          full-TVL-drain risk. Transfer to a Squads multisig or burn (--final)."
    echo "          See docs/SECURITY-UPGRADE-AUTHORITY.md."
    fail=1
  fi
done

echo "------------------------------------------------------------------"
if [[ $fail -eq 0 ]]; then
  echo "OK — all checked programs satisfy the upgrade-authority policy."
else
  echo "BLOCKED — at least one program fails the upgrade-authority policy (#240)."
fi
exit $fail
