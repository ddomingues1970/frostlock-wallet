#!/usr/bin/env bash
set -euo pipefail

if ! command -v bitcoind >/dev/null 2>&1; then
    echo "error: bitcoind is required" >&2
    exit 1
fi

if ! command -v bitcoin-cli >/dev/null 2>&1; then
    echo "error: bitcoin-cli is required" >&2
    exit 1
fi

data_dir="$(mktemp -d /tmp/frostlock-wallet-regtest.XXXXXX)"
rpc_port="18443"
cli_args=(-datadir="$data_dir" -regtest -rpcport="$rpc_port")

cleanup() {
    bitcoin-cli "${cli_args[@]}" stop >/dev/null 2>&1 || true
    rm -rf -- "$data_dir"
}

trap cleanup EXIT

bitcoind \
    -datadir="$data_dir" \
    -regtest \
    -server=1 \
    -daemon=1 \
    -listen=0 \
    -fallbackfee=0.0001 \
    -rpcbind=127.0.0.1 \
    -rpcallowip=127.0.0.1 \
    -rpcport="$rpc_port" \
    >/dev/null

cookie="$data_dir/regtest/.cookie"
for attempt in $(seq 1 30); do
    if [[ -f "$cookie" ]]; then
        break
    fi
    sleep 1
done

if [[ ! -f "$cookie" ]]; then
    echo "error: Bitcoin Core RPC cookie was not created" >&2
    exit 1
fi

cargo run --quiet --package frostlock-wallet -- \
    regtest-check \
    --rpc-url "http://127.0.0.1:$rpc_port" \
    --cookie "$cookie"

bitcoin-cli "${cli_args[@]}" createwallet foundation-smoke >/dev/null
address="$(bitcoin-cli "${cli_args[@]}" -rpcwallet=foundation-smoke getnewaddress)"
bitcoin-cli "${cli_args[@]}" generatetoaddress 101 "$address" >/dev/null

height="$(bitcoin-cli "${cli_args[@]}" getblockcount)"
if [[ "$height" -lt 101 ]]; then
    echo "error: expected at least 101 regtest blocks, got $height" >&2
    exit 1
fi

cargo run --quiet --package frostlock-wallet -- \
    regtest-check \
    --rpc-url "http://127.0.0.1:$rpc_port" \
    --cookie "$cookie"

echo "Frostlock Wallet regtest smoke test: PASS"
