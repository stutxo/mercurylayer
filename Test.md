# Testing the BIP448 prototype

## Workspace gate

Run the non-ignored workspace tests from the repository root:

```text
RUSTUP_TOOLCHAIN=1.92.0 cargo test --workspace --locked
```

The integration suites are ignored by default because they require a fresh
Docker stack and activated BIP448 consensus rules. The intended matrix is 58
ignored entries across eight binaries; the two environment-controlled child
entries are included because Cargo discovers them as tests.

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

Export the same literal project name into every Cargo process so test helpers
restart only that stack. From `clients/tests/rust`, run the complete retained
ignored matrix:

```text
RUSTUP_TOOLCHAIN=1.92.0 ML_SETTINGS_FILE=regtest.core.Settings.toml \
  COMPOSE_PROJECT_NAME=<project> \
  cargo test --locked --test functional -- \
  --ignored --nocapture --test-threads=1

RUSTUP_TOOLCHAIN=1.92.0 ML_SETTINGS_FILE=regtest.core.Settings.toml \
  COMPOSE_PROJECT_NAME=<project> \
  cargo test --locked --test bip448_primitive_spike -- \
  --ignored --nocapture --test-threads=1

RUSTUP_TOOLCHAIN=1.92.0 ML_SETTINGS_FILE=regtest.core.Settings.toml \
  COMPOSE_PROJECT_NAME=<project> \
  cargo test --locked --test bip448_csfs_signing -- \
  --ignored --nocapture --test-threads=1

RUSTUP_TOOLCHAIN=1.92.0 ML_SETTINGS_FILE=regtest.core.Settings.toml \
  COMPOSE_PROJECT_NAME=<project> \
  cargo test --locked --test bip448_deposit -- \
  --ignored --nocapture --test-threads=1

RUSTUP_TOOLCHAIN=1.92.0 ML_SETTINGS_FILE=regtest.core.Settings.toml \
  COMPOSE_PROJECT_NAME=<project> \
  cargo test --locked --test bip448_duplicates -- \
  --ignored --nocapture --test-threads=1

RUSTUP_TOOLCHAIN=1.92.0 ML_SETTINGS_FILE=regtest.core.Settings.toml \
  COMPOSE_PROJECT_NAME=<project> \
  cargo test --locked --test bip448_transfer_sender -- \
  --ignored --nocapture --test-threads=1

RUSTUP_TOOLCHAIN=1.92.0 ML_SETTINGS_FILE=regtest.core.Settings.toml \
  COMPOSE_PROJECT_NAME=<project> \
  cargo test --locked --test bip448_withdraw -- \
  --ignored --nocapture --test-threads=1

RUSTUP_TOOLCHAIN=1.92.0 ML_SETTINGS_FILE=regtest.core.Settings.toml \
  COMPOSE_PROJECT_NAME=<project> \
  cargo test --locked --test lockbox_compatibility -- \
  --ignored --nocapture --test-threads=1
```

Expected discovery is:

| Binary | Ignored entries |
| --- | ---: |
| `functional` | 2 |
| `bip448_primitive_spike` | 1 |
| `bip448_csfs_signing` | 4 |
| `bip448_deposit` | 13 |
| `bip448_duplicates` | 8 |
| `bip448_transfer_sender` | 6 |
| `bip448_withdraw` | 1 |
| `lockbox_compatibility` | 23 |
| **Total** | **58** |

Tear down only that exact project and its volumes:

```text
docker compose -p <project> -f docker-compose-token-servers.yml down -v
```

Query Docker by the project label and verify that its containers, network, and
volumes are gone. Do not remove unrelated Docker resources. The
[test-case reference](docs/test_cases.md) states the narrow evidence supplied
by each integration test.

## Cooperative duplicate-sweep boundaries

- Once canonical funding is pinned, the wallet keeps one logical `Coin` and
  canonical amount while normalized bindings record every observed
  same-script value. Duplicate indices are stable only inside that wallet
  database and are nested under `coin.duplicates`; passive binding
  synchronization does not sign.
- The exact command `bip448-sweep-duplicate <WALLET_NAME> <STATECHAIN_ID>
  <DUPLICATE_INDEX> <TO_ADDRESS> [FEE_RATE]` sweeps one confirmed duplicate in
  one one-input/one-output transaction. Its checked fee is
  `ceil(112 * fee_rate_sat_per_vbyte)`; a nonpositive/nonfinite rate, fee not
  smaller than the input, or dust output is rejected before signing. Each
  output has its own transaction, fee, and signing count.
- Attempt artifacts and phases are durable and retries reuse the exact request
  and transaction. `SecondArmed` is persisted before a possibly delivered
  `sign/second`, making the statechain permanently exit-only. A duplicate sweep
  never deletes server state; canonical withdrawal is last and requires every
  known current-owner duplicate to be handled. Dust and unresolved bindings
  remain visible and can block that close.
- The client durably records a transfer intent before sender mutation. With no
  intervening different authenticated request, exact same-request
  `/transfer/sender` response-loss replay returns one stored `x1` for the
  active unconsumed owner generation; authentication and generation changes
  are checked against locked rows. BIP448 update-message `x1_pub`, unlock
  `auth_pub_key`, and receiver `batch_data` carry the canonical compressed
  `x1` public generation key. Their signatures respectively bind
  statechain/recipient/generation/ciphertext hash,
  role/statechain/generation, and statechain/`t2`/generation.
- `--force-send-with-duplicates` acknowledges only the cooperative-value
  warning. The receiver rescans independently from height 0, assigns its own
  local indices, and decides whether and when to sweep; the sender receives no
  notification or sweep guarantee. A completed latch creation does not reserve
  future transfer rights against a later durable sweep attempt.
- Live unresolved arbitrary-value duplicates of the current owner remain
  cooperatively server-dependent until exact signed sweep bytes exist or an
  independent spend confirms. Previous-owner and retired late rows stay
  visible but are not actionable. Canonical `U`/`S` packages are the only
  claimed unilateral recovery; the emergency recovery commands can strand
  cooperative-only duplicates.
- There is no multi-input batching, equal-value recovery forest, arbitrary-value
  duplicate unilateral recovery, or exact legacy parity. A canonical attempt
  retires and freezes the address: a duplicate first found afterward blocks
  completion while server state remains, and one found only after deletion may
  be unrecoverable. The receiver key-update crash boundary remains unrepaired.
- Use fresh databases: the client schema has twelve application tables;
  Mercury has six and lockbox has two. The CLI has sixteen commands, including
  exact flag `--force-send-with-duplicates`; the intended ignored matrix has
  58 direct entries in eight binaries. This is an Inquisition-dependent proof
  of concept, with no automatic stale-state watcher, Bitcoin mainnet support,
  or production-use claim. Tests establish only their direct assertions.
