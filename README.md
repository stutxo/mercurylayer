# Mercury Layer BIP448 prototype

This repository is a proof-of-concept statechain implementation built around
BIP448 transaction templates and the consensus rules available in the pinned
Bitcoin Inquisition environment. It contains:

- the Rust Mercury HTTP server and shared protocol library;
- the Rust wallet library and `client-rust` command-line application;
- the C++ lockbox service for sealed key shares, BIP448 nonces, partial
  signatures, key updates, and signature counts;
- the optional token HTTP server; and
- unit tests plus ignored Docker/Inquisition integration suites.

Start with [Usage.md](Usage.md), use [Test.md](Test.md) for the executable test
matrix, and read the [BIP448 protocol description](docs/bip448_rebindable_statechains.md).
The [documentation index](docs/README.md) links the API, database, client,
batch/latch, token, and test references.

The annotated tag `bip448-legacy-inclusive-baseline` preserves the older,
legacy-inclusive source tree for historical inspection. It is not a claim that
the current implementation reproduces every behavior in that tree.

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
