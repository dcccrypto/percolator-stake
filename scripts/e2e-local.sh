#!/usr/bin/env bash
# Run the v2.2 LiteSVM e2e suites locally against a wrapper .so that matches their ABI.
#
# The suites (f9_terminal_insurance_recovery_e2e, gh268_cooldown_boundary_e2e,
# d8_jit_closeout_e2e, v5_s3_s1_e2e, ...) load a real percolator-prog wrapper. The
# InitMarket wire, the market account length and the wrapper's pinned stake id must match
# what this branch encodes, or every test (base controls too) fails at InitMarket with
# wrapper Custom(6) or InvalidAccountData.
#
# ci.yml pins the wrapper to WRAPPER_DEPLOYED (15eb8b0c), which predates the v2.2
# (wrapper VERSION 19) ABI these suites encode, and CI only runs on PRs into main.
#
# Matching wrapper (known good on fix/v22-stake-310-313-combined @ a58219b):
#   dcccrypto/percolator-prog aca02ba63114c41817850dc65e598a06f52fc20d
#   dcccrypto/percolator      3ce4cbd1339e420b67a968a2b4cd742765bc1658  (engine, ../percolator path dep)
# Build it once:
#   mkdir -p B/percolator-prog B/percolator
#   git -C <prog-clone>   archive aca02ba63114c41817850dc65e598a06f52fc20d | tar -x -C B/percolator-prog
#   git -C <engine-clone> archive 3ce4cbd1339e420b67a968a2b4cd742765bc1658 | tar -x -C B/percolator
#   (cd B/percolator-prog && cargo build-sbf -- --features devnet)
# `--features devnet` pins stake id 7JrgAUHi..., which is why E2E_STAKE_ID is set below.
#
# Usage: WRAPPER_SO=/abs/B/percolator-prog/target/deploy/percolator_prog.so \
#          scripts/e2e-local.sh <suite> [test-filter]
set -euo pipefail
: "${WRAPPER_SO:?set WRAPPER_SO to the matching percolator_prog.so (see header)}"
[ -f "$WRAPPER_SO" ] || { echo "WRAPPER_SO not found: $WRAPPER_SO" >&2; exit 2; }
suite=${1:?usage: scripts/e2e-local.sh <suite> [test-filter]}
shift
cd "$(dirname "$0")/.."
cargo build-sbf -- --features devnet
export E2E_STAKE_ID=7JrgAUHi4PxaRv5JKHoGAxodDFbozYexpERei66Xgq4V
export F9_WRAPPER_SO=$WRAPPER_SO GH311_WRAPPER_SO=$WRAPPER_SO GH268_WRAPPER_SO=$WRAPPER_SO
exec cargo test --features no-entrypoint --no-fail-fast --test "$suite" -- "$@"
