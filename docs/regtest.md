# Frostlock Wallet regtest smoke test

The smoke test is intentionally isolated from mainnet and uses a temporary
Bitcoin Core data directory.

It verifies that:

1. a local Bitcoin Core regtest node can start;
2. the CLI authenticates through the node cookie;
3. the node can mine blocks;
4. the CLI confirms that the chain is regtest;
5. the temporary node is stopped and its temporary data is removed.

Run it with:

```text
scripts/regtest-smoke.sh
```

The test creates an ephemeral Core wallet only to obtain a regtest mining
address. It must never be reused for real funds.
