# Frostlock Wallet Architecture

## Workspace

```text
crates/
  wallet-core/        Interface-free domain and security contracts
  secret-store-gpg/   GPGME backup adapter
  wallet-cli/         Text-mode adapter and Bitcoin Core smoke commands
docs/              Security and format contracts
scripts/           Local integration harnesses
```

## Dependency direction

```text
wallet-cli  ───────┐
                    ├── wallet-core
future GUI  ────────┘
```

`wallet-core` must not depend on terminal rendering, GUI frameworks, GPGME
process management, or a concrete filesystem layout. Adapters should
implement narrow interfaces for:

- chain data and transaction broadcast;
- public wallet-state persistence;
- secret-envelope encryption and decryption;
- signer operations over PSBTs.

## Foundation boundaries

### `wallet-core`

- BIP84 policy and external/internal branch paths;
- public descriptor construction;
- `frostlock-wallet-secret-v1` validation;
- stable error codes;
- redacted sensitive values and logging policy constants.

### Phase 2 key boundary

- BIP39 generation is English-only and uses 24 words from the operating
  system cryptographic random source;
- BIP39 seed bytes and BIP32 private keys are short-lived and never returned
  in public structs;
- BIP84 account xpubs and master fingerprints are public recovery metadata;
- address comparison derives the same receive and change paths from both the
  mnemonic and account xpub before reporting success.

### `wallet-cli`

- text-mode command parsing;
- public policy and descriptor inspection;
- authenticated Bitcoin Core RPC connectivity check;
- BIP39 generation and encrypted backup/restore commands;
- address recovery comparison;
- no transaction signing yet.

### `secret-store-gpg`

- GPGME integration;
- full-fingerprint recipient selection;
- encrypted backup envelopes;
- no plaintext temporary files.

### Future `chain-bitcoind`

- BDK chain synchronization through Bitcoin Core RPC;
- local-node authentication;
- broadcast and fee-estimation policies.

## Initial dependency baseline

- stable Rust toolchain (1.99.0 in the current development environment) for
  reproducible local builds;
- `bdk_wallet` 3.2.0;
- `bitcoincore-rpc` 0.19.0;
- `serde` and `serde_json` for versioned metadata;
- `zeroize` for secret buffers under application control;
- `bip39` 3.0.0 for mnemonic generation and validation;
- `gpgme` 0.11.0 for OpenPGP encryption and decryption through GnuPG;
- `tempfile` 3.26.0 for atomic mode-0600 backup creation.

All direct versions are reviewed and captured in `Cargo.lock` for Phase 2.
