# Documentation index

The active documentation describes the BIP448-only prototype in this tree:

- [BIP448 rebindable statechains](bip448_rebindable_statechains.md) — funding
  and state trees, duplicate bindings and sweeps, durable retry, transfers,
  validation, recovery packages, and the manually orchestrated stale-state
  proof.
- [BIP448 client architecture](bip448_client_architecture.md) — the review map
  for domain, storage, passive sync, transfer, withdrawal, receiver, mutation
  guards, and crash/replay boundaries.
- [Client guide](client_guide.md) — current settings, lifecycle, commands, and
  command output, including nested duplicate inventory and one-by-one sweeps.
- [Batch and lightning latch](atomic_transfer.md) — the retained one-coin latch
  behavior and its two integration tests.
- [OpenAPI](openapi.yaml) — current Mercury and token-server HTTP paths and
  shared JSON schemas.
- [Databases](server_db.md) — exact fresh six-table Mercury, two-table lockbox,
  and twelve-table client schemas.
- [Test cases](test_cases.md) — retained integration suites and the narrow
  claims made by their assertions.
- [Tokens](tokens.md) — optional on-chain token payment and local free-token
  flows.

Repository-level entry points are [usage](../Usage.md), [testing](../Test.md),
the [Mercury server reference](../server/README.md), and the
[lockbox reference](../lockbox/README.md).

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
  Mercury has seven and lockbox has two. The CLI has sixteen commands, including
  exact flag `--force-send-with-duplicates`; the intended ignored matrix has
  58 direct entries in eight binaries. This is an Inquisition-dependent proof
  of concept, with no automatic stale-state watcher, Bitcoin mainnet support,
  or production-use claim. Tests establish only their direct assertions.
