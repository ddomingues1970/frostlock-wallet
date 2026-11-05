# Frostlock Wallet wallet-secret-v1

Status: Phase 2 implementation contract

## Container

The on-disk filename is:

```text
frostlock-wallet-secret-v1.gpg
```

The file contains OpenPGP/GPG ciphertext. Plaintext JSON must never be written
to disk. The GPG adapter uses GPGME and the configured GPG agent and pinentry.
The application never receives a GPG passphrase through command arguments or
environment variables.

## Plaintext payload before GPG encryption

The payload is UTF-8 JSON with this schema:

```json
{
  "format": "frostlock-wallet-secret",
  "version": 1,
  "network": "regtest",
  "policy": {
    "purpose": 84,
    "coin_type": 1,
    "account": 0
  },
  "gpg_recipient_fingerprint": "0123456789abcdef0123456789abcdef01234567",
  "mnemonic": "<secret BIP39 mnemonic>",
  "bip39_passphrase": null
}
```

## Field rules

- `format` must equal `frostlock-wallet-secret`.
- `version` must equal `1`.
- `network` must be one of `bitcoin`, `testnet`, `testnet4`, `signet`, or
  `regtest`.
- `purpose` must equal `84` in Phase 2.
- `coin_type` must be `0` for mainnet and `1` for other supported networks.
- `account` is `0` in the first user flow; the schema keeps it explicit for
  future accounts.
- `gpg_recipient_fingerprint` must be a full 40-character hexadecimal
  fingerprint, never a short key ID.
- `mnemonic` is an English BIP39 phrase, normally 24 words. It is secret
  material and must not appear in logs, errors, process arguments, or the
  public database.
- `bip39_passphrase` is optional secret material. Phase 2 preserves and
  restores it, but the CLI does not accept it through arguments or environment
  variables.

## Public/private separation

The public database stores descriptors derived from the corresponding xpub:

```text
wpkh([fingerprint/84'/coin_type'/account']xpub/0/*)
wpkh([fingerprint/84'/coin_type'/account']xpub/1/*)
```

The first descriptor is the external chain and the second is the internal
change chain. Descriptors must carry a checksum once they are parsed and
persisted by BDK or Bitcoin Core.

## Compatibility and migration

The format version is not the same as a software version. A future breaking
change must create `version: 2` and a separate migration path. The application
must reject unknown versions rather than guessing how to interpret them.

The recovery procedure must include the network, derivation policy, and a
tested mnemonic backup. The GPG envelope is an encrypted convenience backup,
not the only recovery path. Restore must be tested with the corresponding
private GPG key available in the target keyring.

## Phase 2 commands

Create a new wallet and encrypted backup without printing the mnemonic:

```text
cargo run --package frostlock-wallet -- create regtest \
  --recipient FULL_40_HEX_GPG_FINGERPRINT \
  --output frostlock-wallet-secret-v1.gpg
```

Restore the backup and display only public recovery metadata:

```text
cargo run --package frostlock-wallet -- restore frostlock-wallet-secret-v1.gpg
```

Compare the first five external and internal addresses derived from the
mnemonic and account xpub:

```text
cargo run --package frostlock-wallet -- compare-addresses \
  frostlock-wallet-secret-v1.gpg --count 5
```
