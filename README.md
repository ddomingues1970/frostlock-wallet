# Frostlock Wallet

Frostlock Wallet is a local, non-custodial Bitcoin wallet designed with security
as a primary concern.

The project starts as a text-mode application and keeps the wallet core
separate from its interface so a future GUI can reuse the same key, descriptor,
and transaction logic.

## Current status

This version starts Phase 1 — Foundation:

- documented threat model;
- `frostlock-wallet-secret-v1` format contract;
- BIP84 descriptor policy;
- Rust workspace with wallet core and CLI;
- error and logging policy;
- Bitcoin Core regtest smoke test.

This is not mainnet-ready software and must not receive real funds.

## Local checks

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
scripts/regtest-smoke.sh
```
