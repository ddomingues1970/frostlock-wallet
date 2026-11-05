# Frostlock Wallet Threat Model

Status: Phase 1 foundation

## Scope

Frostlock Wallet is a local, single-user, non-custodial Bitcoin wallet. The first
release targets BIP84 single-signature wallets, a local Bitcoin Core node, GPG
encryption for secret material at rest, and a text-mode interface.

The public wallet database is intended to contain only descriptors, addresses,
transaction metadata, UTXOs, and synchronization state. Private key material
belongs in the GPG-encrypted secret envelope and is loaded only when signing.

## Assets

| Asset | Impact if compromised |
| --- | --- |
| BIP39 mnemonic | Full loss of wallet funds |
| Optional BIP39 passphrase | Loss of the associated wallet if unavailable; disclosure can enable spending |
| Derived private keys and xprv values | Full loss of descendant funds |
| GPG private key and recovery material | Ability to decrypt the wallet secret envelope |
| PSBT and unsigned transaction data | Privacy loss or transaction substitution risk if not reviewed |
| Public descriptors and xpub values | Privacy loss; xpubs reveal address history and future addresses |
| Wallet database | Privacy loss, address-gap or recovery-state loss, and possible denial of service |
| Backup files | Potential full wallet compromise or permanent loss |

## Adversaries

1. **Offline file thief** — obtains the database, GPG envelope, or a backup.
2. **Malicious local process** — reads files, arguments, environment, logs, or
   process memory while the wallet is unlocked.
3. **Supply-chain attacker** — compromises a dependency, build, release, or
   development machine.
4. **Untrusted chain endpoint** — returns misleading data or is unavailable.
5. **Operator error** — wrong network, recipient, amount, fee, backup, or
   derivation policy.
6. **Data corruption or interrupted write** — damages the database or secret
   envelope during an update.

## Security goals

- Never persist the mnemonic, BIP39 passphrase, xprv, or private key in the
  public database.
- Never expose secret material through logs, errors, command arguments,
  environment variables, or `Debug` output.
- Make the network, recipient, amount, fee, inputs, and change visible before
  signing.
- Keep the public wallet state usable as a watch-only foundation.
- Make the recovery policy explicit and versioned.
- Keep signing behind an interface that can later support hardware signers and
  offline PSBT workflows.
- Treat corrupted, incompatible, or ambiguous data as a hard failure.

## Controls in Phase 1

- BIP84 is the only supported descriptor policy.
- Mainnet uses coin type `0`; all test networks use coin type `1`.
- Public descriptor construction rejects obvious private extended-key prefixes.
- `wallet-secret-v1` has an explicit format and version field.
- Secret text has redacted `Debug` output and best-effort zeroization.
- Error codes and messages are designed to avoid sensitive data.
- Bitcoin Core regtest is used for deterministic integration checks.
- The CLI checks that the connected node is actually on regtest.
- The workspace pins the direct BDK and RPC client versions.

## Residual risks

GPG encryption protects data at rest; it does not protect secrets from a
compromised operating system while the wallet is unlocked. Phase 1 is therefore
not suitable for meaningful mainnet balances. Hardware signing, watch-only
operation, offline PSBT exchange, and an independent security review are
required before treating the project as a high-value wallet.

## Out of scope for Phase 1

- malware-resistant signing on a compromised host;
- hardware wallets and secure elements;
- multisig;
- Lightning Network;
- Taproot spending policies;
- remote or public blockchain APIs as a default backend;
- formal verification or a third-party audit.

## Security acceptance criteria

Phase 1 is accepted only when:

1. the workspace builds with warnings denied;
2. unit tests cover policy, descriptor separation, secret-format validation,
   and secret redaction;
3. the regtest smoke test starts a temporary Bitcoin Core node, validates the
   chain, mines blocks, and cleans up its own temporary data;
4. the threat model and secret format are reviewed before Phase 2 adds key
   generation or GPG I/O.
