## Summary

<!-- What changed and why -->

## How to test

<!-- Steps to verify -->

## Checklist

- [ ] Tests pass (`cargo test --features no-entrypoint`)
- [ ] Clippy clean (`cargo clippy --features no-entrypoint -- -D warnings`)
- [ ] Format check (`cargo fmt --all -- --check`)
- [ ] **If this PR touches math, proof logic, or invariant code**: run Kani locally before merging
  ```bash
  # One-time setup
  cargo install --locked kani-verifier && cargo kani setup
  # Run harnesses (from kani-proofs/ directory)
  cd kani-proofs && cargo kani --lib
  ```
  Kani is **not** run automatically on every PR. Use the [Kani (Manual)](../../actions/workflows/kani-manual.yml) workflow for on-demand runs.

## Related

<!-- Task ID, issue, or PR -->
