# Frostlock Wallet Architecture

## Workspace

```text
crates/
  wallet-core/     Interface-free domain and security contracts
  wallet-cli/      Text-mode adapter and Bitcoin Core smoke commands
docs/              Security and format contracts
scripts/           Local integration harnesses
```

## Dependency direction

```text
wallet-cli  ───────┐
                    ├── wallet-core
future GUI  ────────┘
```

`wallet-core` must not depend on terminal rendering, GUI frameworks, GPG
process management, or a concrete filesystem layout. Future adapters should
implement narrow interfaces for:

- chain data and transaction broadcast;
- public wallet-state persistence;
- secret-envelope encryption and decryption;
- signer operations over PSBTs.

## Phase 1 boundaries

### `wallet-core`

- BIP84 policy and external/internal branch paths;
- public descriptor construction;
- `frostlock-wallet-secret-v1` validation;
- stable error codes;
- redacted sensitive values and logging policy constants.

### `wallet-cli`

- text-mode command parsing;
- public policy and descriptor inspection;
- authenticated Bitcoin Core RPC connectivity check;
- no secret generation or signing yet.

### Future `secret-store-gpg`

- GPGME integration;
- full-fingerprint recipient selection;
- encrypted and optionally signed backup envelopes;
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
- `zeroize` for secret buffers under application control.

All direct versions must be reviewed and captured in `Cargo.lock` before
Phase 2.
