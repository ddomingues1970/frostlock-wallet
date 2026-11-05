# Phase 2 — Keys and Backup

## Security boundary

Phase 2 keeps private material in the wallet core only for the duration of a
derivation or backup operation. The public result contains the network, BIP84
policy, master fingerprint, account xpub, descriptors, and addresses. It does
not contain a mnemonic, BIP39 seed, xpriv, or GPG passphrase.

## BIP39

- English language only for the first recovery workflow;
- 24 words by default, providing 256 bits of entropy plus the BIP39 checksum;
- generation uses the operating system cryptographic random source through the
  `bip39` crate;
- restored phrases are checksum-validated before derivation.

## BIP32/BIP84

The account path is:

```text
m/84'/coin_type'/account'
```

The receive and change branches are:

```text
m/84'/coin_type'/account'/0/index
m/84'/coin_type'/account'/1/index
```

Mainnet uses coin type `0`; test networks use coin type `1`. The implementation
derives the account xpub from the mnemonic, then independently derives child
public keys from that xpub for comparison.

## GPGME backup

`secret-store-gpg` uses the Rust GPGME bindings and an OpenPGP context. It
selects a recipient by full 40-character fingerprint, rejects unusable keys,
and writes only ciphertext to the backup path. GPGME delegates private-key
passphrase handling to the configured GPG agent and pinentry.

Backups are written through a mode-0600 temporary file in the destination
directory, flushed, synchronized, and renamed without overwriting an existing
destination. Plaintext JSON is never written to a temporary file.

## Recovery verification

The clean-machine test uses two isolated GnuPG homes. It creates a disposable
test key, creates an encrypted wallet backup, exports and imports the private
GPG key into a second empty keyring, restores the backup there, and compares
multiple receive and change addresses. The test passes only when every address
derived from the restored mnemonic matches the address derived from the
restored account xpub.

The test key and all temporary files are removed at the end of the test. They
must never be reused for real funds.
