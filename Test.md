# Testing the BIP448 prototype

## Workspace gate

Run the non-ignored workspace tests from the repository root:

```text
RUSTUP_TOOLCHAIN=1.92.0 cargo test --workspace --locked
```

The integration suites are ignored by default because they require a fresh
Docker stack and activated BIP448 consensus rules. No fixed test count is
published; use the result emitted by the checked-out tree.

## Fresh Docker/Inquisition stack

Before starting, check that no unrelated stack owns the compose file's fixed
container names. Choose a unique lowercase project name, then run:

```text
docker compose -p <project> -f docker-compose-token-servers.yml up --build -d
```

Wait until `http://127.0.0.1:8000/info/config` and the Inquisition RPC are
ready. Create or load the `mercury_test` regtest wallet and mine 101 blocks as
the current CI workflow does. Run suite processes serially: their global guard,
database state, and chain state are not designed for concurrent suite
processes. Record the first attempt and any emitted transaction IDs or
signature counts rather than silently replacing a failure with a retry.

From `clients/tests/rust`, run the complete retained ignored matrix:

```text
RUSTUP_TOOLCHAIN=1.92.0 ML_SETTINGS_FILE=regtest.core.Settings.toml \
  cargo test --locked --test functional -- \
  --ignored --nocapture --test-threads=1

RUSTUP_TOOLCHAIN=1.92.0 ML_SETTINGS_FILE=regtest.core.Settings.toml \
  cargo test --locked --test bip448_primitive_spike -- \
  --ignored --nocapture --test-threads=1

RUSTUP_TOOLCHAIN=1.92.0 ML_SETTINGS_FILE=regtest.core.Settings.toml \
  cargo test --locked --test bip448_csfs_signing -- \
  --ignored --nocapture --test-threads=1

RUSTUP_TOOLCHAIN=1.92.0 ML_SETTINGS_FILE=regtest.core.Settings.toml \
  cargo test --locked --test bip448_deposit -- \
  --ignored --nocapture --test-threads=1

RUSTUP_TOOLCHAIN=1.92.0 ML_SETTINGS_FILE=regtest.core.Settings.toml \
  cargo test --locked --test bip448_transfer_sender -- \
  --ignored --nocapture --test-threads=1

RUSTUP_TOOLCHAIN=1.92.0 ML_SETTINGS_FILE=regtest.core.Settings.toml \
  cargo test --locked --test bip448_withdraw -- \
  --ignored --nocapture --test-threads=1

RUSTUP_TOOLCHAIN=1.92.0 ML_SETTINGS_FILE=regtest.core.Settings.toml \
  cargo test --locked --test lockbox_compatibility -- \
  --ignored --nocapture --test-threads=1
```

Tear down only that exact project and its volumes:

```text
docker compose -p <project> -f docker-compose-token-servers.yml down -v
```

Query Docker by the project label and verify that its containers, network, and
volumes are gone. Do not remove unrelated Docker resources. The
[test-case reference](docs/test_cases.md) states the narrow evidence supplied
by each integration test.

## Prototype boundaries

- Exact legacy duplicate-deposit behavior is not reproduced: paying one
  BIP448 deposit address more than once does not create another wallet coin.
- There is no chain watcher and no automatic selection of a stale state's
  funding source.
- The stale-state end-to-end proof manually selects, rebinds, submits, and
  mines transactions from test code; the running services do not orchestrate
  it.
- BIP448 consensus execution requires the Bitcoin Inquisition revision pinned
  by this repository.
- This is not software for Bitcoin mainnet or production use.
- Start with fresh Mercury and lockbox databases and a fresh client wallet
  database; old data is not migrated.
- Passing tests establish only the assertions and paths that those tests
  execute.
