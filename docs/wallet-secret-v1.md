# Frostlock Wallet wallet-secret-v1

Status: Phase 1 format contract

## Container

The on-disk filename is:

```text
frostlock-wallet-secret-v1.gpg
```

The file contains OpenPGP/GPG ciphertext. Plaintext JSON must never be written
to disk. The future GPG adapter must use GPGME or a reviewed binding and must
use the GPG agent and pinentry rather than receiving passphrases through command
arguments or environment variables.

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
- `network` must be one of `bitcoin`, `testnet`, `signet`, or `regtest`.
- `purpose` must equal `84` in Phase 1.
- `coin_type` must be `0` for mainnet and `1` for other supported networks.
- `account` is `0` in the first user flow; the schema keeps it explicit for
  future accounts.
- `gpg_recipient_fingerprint` must be a full 40-character hexadecimal
  fingerprint, never a short key ID.
- `mnemonic` is secret material and must not appear in logs, errors, process
  arguments, or the public database.
- `bip39_passphrase` exists in the schema but must remain `null` until the
  recovery UX and backup process explicitly support it.

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
not the only recovery path.
