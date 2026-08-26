# BIP448 lockbox service

The lockbox is a Crow HTTP service backed by PostgreSQL or an embedded SQLite
database. It stores sealed server key material, idempotent BIP448 signing
rounds, and replay-safe key-update receipts.

## Retained routes

These are the complete application routes declared by `start_server`. With
`LOCKBOX_REQUIRE_AUTH=1`, every route except `POST /verify_statechain` requires
`Authorization: Bearer <LOCKBOX_AUTH_TOKEN>`.

| Method and path | Request | Success response |
| --- | --- | --- |
| `GET /` | none | plain text `Hello, Crow!` |
| `GET /health/ready` | none | JSON `status` |
| `POST /get_public_key` | JSON `statechain_id` | JSON `server_pubkey` |
| `POST /verify_statechain` | JSON `statechain_id`, `challenge` | JSON echoed identifiers and `server_pubkey` |
| `GET /bip448/state/<statechain_id>` | path `statechain_id` | JSON BIP448 state |
| `POST /bip448/get_public_nonce` | statechain/signing IDs plus expected generation and server key | JSON `server_pubnonce` |
| `POST /bip448/get_partial_signature` | signing material plus expected generation and server key | JSON `partial_sig` |
| `GET /signature_count/<statechain_id>` | path `statechain_id` | JSON `sig_count` |
| `POST /keyupdate` | versioned update, expected state, `t2`, and `x1` | JSON replay-safe update receipt |
| `DELETE /delete_statechain/<statechain_id>` | path `statechain_id` | plain text `Statechain deleted.` |

`signing_id` is a 32-byte hexadecimal value and is stored in canonical
lowercase form. `session` must decode to the 133-byte Mercury MuSig session
format. `negate_seckey` must be `0` or `1`, and `server_pub_nonce` must match
the nonce recorded for that statechain and signing identifier. `t2` and `x1`
must each decode to 32 bytes.

## Replay and conflicts

The first nonce request for `(statechain_id, signing_id)` persists a sealed
secret nonce and returns its public nonce. An exact repeat returns that same
public nonce. The partial-signature request claims the session challenge and
negation flag, persists the resulting partial signature, and increments
`sig_count` only when that signature is first saved. An exact repeat returns
the saved partial signature; a different public nonce, challenge, or negation
flag for the same identifier returns a conflict. These database and route
checks make retries idempotent within the implemented service. They do not
provide an external attestation about deletion or operational security.

The durable client gives every canonical or duplicate key-path spend a fresh
opaque `signing_id` and reuses its exact stored first- and second-round JSON on
retry. A successfully persisted partial increments `sig_count` once. Each
one-input duplicate sweep therefore consumes its own count, but it never calls
the deletion route and does not change canonical state history. The first
durable `SecondArmed` phase is exit-only even when the response is lost because
the second request may already have reached this service.

`DELETE /delete_statechain/<statechain_id>` deletes the generated key and
cascades to nonce and key-update receipt rows in one database transaction. The
documentation makes no claim that a server share is verifiably erased from
every storage layer.

The PostgreSQL definitions are in the
[database reference](../docs/server_db.md); the Enclavia SQLite schema is in
`src/sqlite_db_manager.cpp`.

## Enclavia embedded storage

Build the authenticated SQLite image through the repository deployment script:

```sh
infra/enclavia-poc/build-image.sh
```

The image stores `lockbox.seed` and `lockbox.sqlite3` together under `/data`,
uses durable rollback-journal commits, fails closed when only one file exists,
and verifies that the database belongs to the wrapping seed. The Enclavia
creation script requires synchronizer-backed anti-rollback storage and deny-all
egress. This remains a disposable, no-funds beta proof.

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
  Mercury has six, and the Lockbox has three application tables plus SQLite
  seed-verifier metadata when using embedded storage. The CLI has sixteen
  commands, including exact flag `--force-send-with-duplicates`; the intended
  ignored matrix has 58 direct entries in eight binaries. This is an
  Inquisition-dependent proof
  of concept, with no automatic stale-state watcher, Bitcoin mainnet support,
  or production-use claim. Tests establish only their direct assertions.
