# Testing the BIP448 prototype

The BIP448 integration workflow is implemented entirely in Rust by the
`bip448-test` binary in `clients/tests/rust`. The old Python controller and
helper paths (`scripts/bip448-test`, `scripts/bip448_testlib.py`, and
`scripts/bip448_evidence.py`) do not exist. The workflow neither requires nor
invokes host Python; do not use old Python helper commands for it.

Run every command below from the repository root. Evidence-recorded mutations
(all mutations except `reset`) require a clean Git worktree and record the
exact source commit and Git-status digest.

## Build and check the controller

The controller requires Rust 1.92.0 plus `cargo`, `docker`, `git`, `rustc`, and
`rustup` on `PATH`:

```sh
export RUSTUP_TOOLCHAIN=1.92.0
cargo test --workspace --locked
cargo build --locked --package rust --bin bip448-test
BIP448=./target/debug/bip448-test
"$BIP448" doctor
"$BIP448" --help
```

`doctor` checks the repository shape, required commands, and the exact Rust
toolchain. The workflow uses direct argument vectors; it does not invoke a
shell or a Python helper.

## Quick persistent local flow

Use this path to run one reviewed MATRIX identity while keeping project
metadata and operation evidence available for diagnosis. Pick an unused
lowercase project name and a free range of eight consecutive ports:

```sh
PROJECT=b448-local
BASE_PORT=25400

"$BIP448" configure --project "$PROJECT" --base-port "$BASE_PORT"
"$BIP448" build --project "$PROJECT" --service all
"$BIP448" up --project "$PROJECT"
"$BIP448" ready --project "$PROJECT"
"$BIP448" bootstrap --project "$PROJECT" --require-zero
"$BIP448" test \
  --project "$PROJECT" \
  --target bip448_primitive_spike \
  --test bip448_template_signature_rebinds_prevout_on_inquisition
"$BIP448" status --project "$PROJECT"
"$BIP448" checkpoint --project "$PROJECT" \
  > "target/${PROJECT}-checkpoint.json"
"$BIP448" logs --project "$PROJECT" \
  > "target/${PROJECT}-logs.json"
"$BIP448" down --project "$PROJECT"
"$BIP448" status --project "$PROJECT"
"$BIP448" reset --project "$PROJECT"
```

`--require-zero` proves a fresh height-zero Inquisition chain before mining
the exact 101-block bootstrap. `test` accepts only an exact binary/identity
pair from the Rust MATRIX. This manual path is useful for a focused diagnosis;
it is not the authoritative 59-test verification.

`down` safely removes the selected project's containers, network, volumes,
listeners, and wallet database. It retains `stack.json`, `Settings.toml`, and
operation evidence, so run `checkpoint` and `logs` before destructive cleanup.
`reset` first proves the project is down, then permanently removes its
validated run/evidence tree and exact project-owned deterministic-RNG and
staging tags. Save any reports outside `target/bip448-runs/<PROJECT>` first.

## Authoritative fresh verification

One command owns the complete acceptance run:

```sh
PRIMARY_PROJECT=b448-local-primary
PRIMARY_BASE_PORT=25600

"$BIP448" verify \
  --project "$PRIMARY_PROJECT" \
  --base-port "$PRIMARY_BASE_PORT"
```

With no control overrides, the controller derives the control project as
`b448ctl-` followed by the first 12 lowercase hexadecimal characters of
SHA-256 over the primary project name. Its eight-port base is the primary base
plus 8 when the primary base is at most 65520, or minus 8 otherwise. Explicit
identities are also supported:

```sh
CONTROL_PROJECT=b448-local-control
CONTROL_BASE_PORT=25608

"$BIP448" verify \
  --project "$PRIMARY_PROJECT" \
  --base-port "$PRIMARY_BASE_PORT" \
  --control-project "$CONTROL_PROJECT" \
  --control-base-port "$CONTROL_BASE_PORT"
```

Primary and control names must be different. Their eight-port ranges must be
disjoint. Before creating either run, `verify` requires both run directories
and Docker projects to be absent and reserves all 16 loopback ports together.
It never searches for another port automatically.

The invocation configures and builds both projects from one source identity,
starts and fresh-bootstraps both stacks, runs the primary MATRIX serially,
directly verifies the primary contracts, and proves control isolation. It then
tears down the primary while the control remains ready and unchanged, proves
the control snapshot again, and tears down the control. Success reports
`status: "authoritative"`, `matrix_test_count: 59`,
`complete_first_invocation_target_records: 8`, `retries: 0`,
`mercury_restart_count: 1`, `cleanup_order: ["primary", "control"]`, and final
resource, port, wallet, source, image, and cache accounting.

This command must be the first actual invocation of every MATRIX identity for
the run: do not add a pre-smoke, direct Cargo test, second invocation, or retry.
A source change during the run invalidates it. Preserve a failed run's evidence
and investigate it; a later attempt must start with fresh project identities
and a clean source rather than overwrite or reinterpret the first result.

## MATRIX source of truth

The sole editable list of exact test identities is
[`clients/tests/rust/src/workflow/matrix.rs`](clients/tests/rust/src/workflow/matrix.rs).
The controller also freezes this target order and count split:

| Order | Cargo test binary | Tests |
| ---: | --- | ---: |
| 1 | `functional` | 2 |
| 2 | `bip448_primitive_spike` | 1 |
| 3 | `bip448_csfs_signing` | 4 |
| 4 | `bip448_deposit` | 14 |
| 5 | `bip448_duplicates` | 8 |
| 6 | `bip448_transfer_sender` | 6 |
| 7 | `bip448_withdraw` | 1 |
| 8 | `lockbox_compatibility` | 23 |
|  | **Total** | **59** |

Do not copy the 59 identities into another script or document. The runner
checks Cargo's ignored-test discovery against `MATRIX` and executes the exact
pairs serially with one test thread.

## What authoritative verification proves

The direct verifier is part of `verify`; there is no separate single-stack
verification step. It checks:

- the exact 11 generated `Settings.toml` keys and a 200 Mercury `/info/config`
  response of `{"batchtimeout":20,"version":"0.2.1"}`;
- lexical source inventories of 18 Mercury/token and seven lockbox routes;
- the SHA-pinned 12-table client SQLite migration, complete columns, table
  SQL/CHECKs, three partial unique indexes, zero foreign keys, no legacy backup
  table, two real client loads, and preserved wallet/statechain sentinels;
- one Mercury PostgreSQL migration row and complete live catalogs: Mercury has
  6 tables, 46 columns, 16 constraints, and 14 indexes; lockbox has 2 tables,
  15 columns, 8 constraints, and 4 indexes; and
- exactly one Mercury restart, followed by readiness, unchanged build
  identity, and exactly equal PostgreSQL catalog reports.

The control stack supplies a live isolation proof, not another MATRIX run.
Before the primary MATRIX, after the MATRIX and direct verification, and after
primary teardown, the controller compares the control's topology and stable
container start identities, height-101 chain/wallet state, settings, Mercury
config, client catalog, and PostgreSQL catalogs. Any drift fails the run.

## Evidence, failures, and cleanup

Every mutation writes private evidence under
`target/bip448-runs/<PROJECT>/operations/<UUID>/`: `started.json` is durable
before work begins and `result.json` is written last. Test output is stored as
`test.stdout` and `test.stderr` where applicable, with `bytes` and `sha256`
fields in the result. `checkpoint` reports lifecycle plus all operations;
`logs` reports recorded test output plus bounded Compose logs.

Exit status is 0 for success, 2 for invalid CLI usage, 1 for an operational
controller failure, or the failing child status when a child process fails.
Children run in their own process groups. While a child is active, SIGINT and
SIGTERM are forwarded to the group, descendants are reaped, the signal is
recorded, and the controller exits 130 or 143 respectively.

A `started.json` without `result.json` is incomplete evidence. It blocks every
later mutation for that project except `down`; read-only `status`, `ready`,
`checkpoint`, and `logs` remain available. Inspect and save the evidence, run
`down`, then use explicit `reset` only when permanent evidence removal is
intended.

Normal teardown and reset never prune Docker. Authoritative verification
retains authenticated final image tags and any new BuildKit cache records for
reuse, while proving that pre-existing images, tags, caches, and unrelated
containers/networks/volumes did not disappear or change. `reset` untags only
the exact selected project's deterministic-RNG and leftover staging tags with
no prune; shared fingerprinted production images and build cache remain.

## CI and scope

The integration workflow in [`.github/workflows/tests.yml`](.github/workflows/tests.yml)
builds the Rust controller, runs `doctor`, and invokes authoritative `verify`
exactly once with explicit primary/control identities and port ranges. It does
not duplicate configure/build/up/bootstrap/test orchestration. Always-run CI
steps collect status, checkpoints, logs, and both evidence trees before
ordered cleanup.

Detailed cooperative duplicate-sweep and recovery boundaries remain in the
[README](README.md#cooperative-duplicate-sweep-boundaries); they are not
duplicated in this executable workflow guide.

These tests require fresh databases and the pinned Bitcoin Inquisition
environment. They exercise regtest BIP448 proof-of-concept behavior only: they
do not support Bitcoin mainnet, establish full legacy parity, or make a
production-readiness or production-safety claim. Test success establishes only
the assertions and invariants named by the current Rust MATRIX and verifier.
