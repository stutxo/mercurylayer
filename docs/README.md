# Documentation index

The active documentation describes the BIP448-only prototype in this tree:

- [BIP448 rebindable statechains](bip448_rebindable_statechains.md) — funding
  and state trees, blind signing, transfers, validation, recovery packages, and
  the manually orchestrated stale-state proof.
- [Client guide](client_guide.md) — current settings, lifecycle, commands, and
  command output.
- [Batch and lightning latch](atomic_transfer.md) — the retained one-coin latch
  behavior and its two integration tests.
- [OpenAPI](openapi.yaml) — current Mercury and token-server HTTP paths and
  shared JSON schemas.
- [Databases](server_db.md) — exact fresh Mercury, lockbox, and client schemas.
- [Test cases](test_cases.md) — retained integration suites and the narrow
  claims made by their assertions.
- [Tokens](tokens.md) — optional on-chain token payment and local free-token
  flows.

Repository-level entry points are [usage](../Usage.md), [testing](../Test.md),
the [Mercury server reference](../server/README.md), and the
[lockbox reference](../lockbox/README.md).

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
