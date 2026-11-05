# Frostlock Wallet Error and Logging Policy

Status: Phase 2 — keys and backup

## Never log

- mnemonic words;
- BIP39 passphrases;
- private keys, xprvs, WIFs, or GPG passphrases;
- RPC usernames, passwords, or cookie contents;
- raw PSBTs or signed transaction hex;
- full xpubs or descriptors unless an explicit diagnostic command requests
  them;
- filesystem contents from secret paths.

## Safe default fields

- event name;
- stable error code;
- network name;
- wallet format version;
- block height and synchronization state;
- counts of addresses, UTXOs, or transactions;
- short internal correlation ID.

Transaction IDs and addresses are public on-chain data but still sensitive from
a privacy perspective. They must not be emitted by default logs; explicit user
commands may display them in the terminal.

## Error behavior

- Return stable machine-readable error codes.
- Keep user-facing messages actionable and free of secret values.
- Do not print dependency errors directly if they may contain credentials,
  request bodies, or file contents.
- Exit non-zero on invalid network, invalid descriptor, corrupt secret format,
  RPC mismatch, or persistence failure.
- Treat unknown secret-format versions as errors, never as best-effort input.

## Debug behavior

Types that may contain secrets must implement redacted `Debug`. The application
must not derive `Debug` for a structure that directly contains secret material
unless every sensitive field is redacted.
