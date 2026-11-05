#!/usr/bin/env bash
set -euo pipefail

if ! command -v gpg >/dev/null 2>&1; then
    echo "error: gpg is required" >&2
    exit 1
fi

source_home="$(mktemp -d /tmp/frostlock-phase2-source.XXXXXX)"
clean_home="$(mktemp -d /tmp/frostlock-phase2-clean.XXXXXX)"
backup_file="$(mktemp /tmp/frostlock-phase2-backup.XXXXXX)"
secret_export="$(mktemp /tmp/frostlock-phase2-secret.XXXXXX)"
chmod 700 "$source_home" "$clean_home"
rm -f -- "$backup_file" "$secret_export"

cleanup() {
    rm -rf -- "$source_home" "$clean_home"
    rm -f -- "$backup_file" "$secret_export"
}

trap cleanup EXIT

gpg --homedir "$source_home" \
    --batch \
    --pinentry-mode loopback \
    --passphrase "" \
    --quick-generate-key \
    "Frostlock Phase 2 Test <frostlock-phase2@example.invalid>" \
    rsa2048 \
    encr \
    0 \
    >/dev/null

fingerprint="$(gpg --homedir "$source_home" --batch --with-colons --list-keys \
    | awk -F: '$1 == "fpr" { print $10; exit }')"

if [[ ! "$fingerprint" =~ ^[[:xdigit:]]{40}$ ]]; then
    echo "error: failed to obtain a full GPG fingerprint" >&2
    exit 1
fi

cargo run --quiet --package frostlock-wallet -- \
    create regtest \
    --recipient "$fingerprint" \
    --output "$backup_file" \
    --gpg-home "$source_home"

gpg --homedir "$source_home" \
    --batch \
    --pinentry-mode loopback \
    --passphrase "" \
    --export-secret-keys \
    --armor \
    "$fingerprint" >"$secret_export"

gpg --homedir "$clean_home" --batch --import "$secret_export" >/dev/null 2>&1

cargo run --quiet --package frostlock-wallet -- \
    restore "$backup_file" \
    --gpg-home "$clean_home"

cargo run --quiet --package frostlock-wallet -- \
    compare-addresses "$backup_file" \
    --count 5 \
    --gpg-home "$clean_home"

echo "Frostlock Wallet Phase 2 clean-machine recovery: PASS"
