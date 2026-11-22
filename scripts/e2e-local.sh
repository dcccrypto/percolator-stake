#!/usr/bin/env bash
# Run the v2.2 LiteSVM e2e suites locally against a wrapper .so that matches their ABI.
#
# The suites (f9_terminal_insurance_recovery_e2e, gh268_cooldown_boundary_e2e,
# d8_jit_closeout_e2e, v5_s3_s1_e2e, ...) load a real percolator-prog wrapper. Its InitMarket
# wire and market account length must match what this branch encodes, or every test (base
# controls too) fails at InitMarket with wrapper Custom(6) or InvalidAccountData. The wrapper's
# pinned stake id only matters on the pinned-stake paths (tag 87/116: f9, v5_s3_s1, task13,
# v22live via E2E_STAKE_ID, and d8/gh311).
#
# ci.yml pins the wrapper to WRAPPER_DEPLOYED (15eb8b0c), which predates the v2.2
# (wrapper VERSION 19) ABI these suites encode, and CI runs only for main (push/PR).
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
# Only f9/v5_s3_s1/task13/v22live (F9_WRAPPER_SO) and d8/gh311 (GH311_WRAPPER_SO) take an env
# override. The other wrapper suites (gh268, c1, f3, mode0_*, n6, poc_ah2, poc_ah3,
# poc_last_junior_residual; v16/v17 too, but they encode the older v16/v17 wire) read the CI
# layout ../percolator-prog/target/deploy/percolator_prog.so and panic if it is missing, so
# this script refuses to run unless that sibling file is the same build as WRAPPER_SO.
#
# Usage: WRAPPER_SO=/abs/B/percolator-prog/target/deploy/percolator_prog.so \
#          scripts/e2e-local.sh <suite> [test-filter]
set -euo pipefail
: "${WRAPPER_SO:?set WRAPPER_SO to the matching percolator_prog.so (see header)}"
[ -f "$WRAPPER_SO" ] || { echo "WRAPPER_SO not found: $WRAPPER_SO" >&2; exit 2; }
WRAPPER_SO="$(cd "$(dirname "$WRAPPER_SO")" && pwd)/$(basename "$WRAPPER_SO")"
suite=${1:?usage: scripts/e2e-local.sh <suite> [test-filter]}
shift
cd "$(dirname "$0")/.."
sib="$(cd .. && pwd)/percolator-prog/target/deploy/percolator_prog.so"
if ! cmp -s "$sib" "$WRAPPER_SO"; then
  echo "sibling wrapper $sib is missing or differs from WRAPPER_SO; suites without an env" >&2
  echo "override (gh268, c1, f3, ...) would use it. Copy it first:" >&2
  echo "  mkdir -p \"$(dirname "$sib")\" && cp \"$WRAPPER_SO\" \"$sib\"" >&2
  exit 2
fi
cargo build-sbf -- --features devnet
export E2E_STAKE_ID=7JrgAUHi4PxaRv5JKHoGAxodDFbozYexpERei66Xgq4V
export F9_WRAPPER_SO=$WRAPPER_SO GH311_WRAPPER_SO=$WRAPPER_SO
exec cargo test --features no-entrypoint --no-fail-fast --test "$suite" -- "$@"
