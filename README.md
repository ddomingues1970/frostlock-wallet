# Frostlock Wallet

Frostlock Wallet is a local, non-custodial Bitcoin wallet designed with security
as a primary concern.

The project starts as a text-mode application and keeps the wallet core
separate from its interface so a future GUI can reuse the same key, descriptor,
and transaction logic.

## Current status

This phase implements Phase 2 — Keys and backup on top of the Phase 1
foundation:

- 24-word English BIP39 generation and validation;
- BIP32/BIP84 account derivation;
- GPGME-backed encrypted backup and restore;
- mnemonic-derived versus xpub-derived address comparison;
- isolated clean-machine recovery test.

This is not mainnet-ready software and must not receive real funds.

## Local checks

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
scripts/regtest-smoke.sh
scripts/phase2-clean-machine-recovery.sh
```

The GPGME adapter requires GnuPG and the GPGME development library. On Debian
or Ubuntu, install `gpg` and `libgpgme-dev` before building.
