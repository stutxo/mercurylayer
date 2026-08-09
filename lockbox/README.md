# BIP448 lockbox service

The lockbox is a Crow HTTP service backed by PostgreSQL. It stores sealed
server key material in `generated_public_key` and idempotent BIP448 signing
rounds in `bip448_nonce_state`.

## Retained routes

These are the complete application routes declared by `start_server`:

| Method and path | Request | Success response |
| --- | --- | --- |
| `GET /` | none | plain text `Hello, Crow!` |
| `POST /get_public_key` | JSON `statechain_id` | JSON `server_pubkey` |
| `POST /bip448/get_public_nonce` | JSON `statechain_id`, `signing_id` | JSON `server_pubnonce` |
| `POST /bip448/get_partial_signature` | JSON `statechain_id`, `signing_id`, `negate_seckey`, `session`, `server_pub_nonce` | JSON `partial_sig` |
| `GET /signature_count/<statechain_id>` | path `statechain_id` | JSON `sig_count` |
| `POST /keyupdate` | JSON `statechain_id`, `t2`, `x1` | JSON `server_pubkey` |
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

`DELETE /delete_statechain/<statechain_id>` deletes rows from both lockbox
tables in a database transaction. The documentation makes no claim that a
server share is verifiably erased from every storage layer.

The exact table definitions are in the [database reference](../docs/server_db.md).

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
