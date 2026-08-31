# Mercury BIP448 server

`mercury-server` is the Rocket service used by the BIP448 client. It stores
statechain, latch, transfer, token, blind-signing replay, and nonce-lease state
in PostgreSQL and delegates sealed-key operations to a configured lockbox.

## Configuration

`ServerConfig::load` reads these `Settings.toml` keys, with the corresponding
environment variable taking precedence:

| TOML key | Environment variable | Shape |
| --- | --- | --- |
| `network` | `BITCOIN_NETWORK` | string |
| `batch_timeout` | `BATCH_TIMEOUT` | unsigned integer seconds |
| `enclaves` | `ENCLAVES` | array of enclave objects; the environment value is JSON |
| `db_user` | `DB_USER` | string |
| `db_password` | `DB_PASSWORD` | string |
| `db_host` | `DB_HOST` | string |
| `db_port` | `DB_PORT` | unsigned 16-bit integer |
| `db_name` | `DB_NAME` | string |
| `token_server_url` | `TOKEN_SERVER_URL` | optional string |

Each enclave object requires `url` and `allow_deposit`. Direct Enclavia
`ws://`/`wss://` transports also require 96-hex `pcr0`, `pcr1`, and `pcr2`
measurements. `debug` and `allow_unattested` default to `false`.

Every Lockbox transport requires a 64-hex `LOCKBOX_AUTH_TOKEN` environment
variable. Cleartext `http://` is accepted only when `network = "regtest"`.
Outside regtest, unattested `https://` requires an explicit
`allow_unattested = true`; production and hosted signet deployments should use
an attested `ws://` or `wss://` endpoint instead. Debug attestation is refused
unless the network is exactly `regtest` and
`MERCURY_ALLOW_DEBUG_ENCLAVES=1`; `debug = true` is never valid for HTTP(S).
Mercury verifies authenticated Lockbox readiness before serving requests and
keeps the SDK's attested channel active with an authenticated `/health/live`
request every ten minutes. A failed keepalive reconnects and re-attests against
the pinned PCRs before the next interval. Transient failures retry only
operations whose exact request is replay-safe.

When `token_server_url` is set, `/deposit/get_token` proxies token generation
to that service. When it is absent, the local path creates a free,
already-confirmed token unless the configured `network` string is literally
`mainnet`. This exact string comparison is a development guard, not validation
of Bitcoin network semantics or a production-safety boundary. The fresh
database schema is documented in [the database reference](../docs/server_db.md).

Deposit initialization reserves its statechain ID and Lockbox index in a
dedicated PostgreSQL row keyed by the immutable token ID; incomplete
reservations are never active statechains. Mercury waits up to five seconds for
key creation, reconnects and re-attests after a failure, then retries the exact
request once for up to five seconds. The Lockbox's atomic get-or-create operation
makes that replay return the same key. If both responses are ambiguous, Mercury
observes durable Lockbox state for up to 12 seconds with bounded exponential
backoff. One transaction then creates the active statechain, spends the token,
and retains the completed reservation as an exact-retry receipt. The recovery
path remains below the browser's 65-second Mercury request limit.

## Mounted HTTP routes

Optional fields below may be omitted or sent as JSON `null`. Every other body
field shown is required by the shared Serde DTO.

| Method and path | Request | Success response |
| --- | --- | --- |
| `GET /deposit/get_token` | none | `token_id`, `payment_method`, `deposit_address`, `fee`, `confirmation_target` |
| `POST /deposit/init/pod` | `auth_key`, `token_id`, `signed_token_id` | `server_pubkey`, `statechain_id` |
| `POST /bip448-statechain/sign/first` | `statechain_id`, `signed_statechain_id`, `signing_id` | `server_pubnonce` |
| `POST /bip448-statechain/sign/second` | `statechain_id`, `signed_statechain_id`, `signing_id`, `negate_seckey`, `session`, `server_pub_nonce` | `partial_sig` |
| `GET /bip448-statechain/signature-count/<statechain_id>` | path `statechain_id` | `sig_count` |
| `GET /transfer/paymenthash/<batch_id>` | path `batch_id` | `hash` |
| `POST /transfer/paymenthash` | `statechain_id`, `auth_sig`, `batch_id` | `hash` |
| `POST /transfer/transfer_preimage` | `statechain_id`, `auth_sig`, `previous_user_auth_key`, `batch_id` | `preimage` |
| `POST /transfer/sender` | `statechain_id`, `auth_sig`, `new_user_auth_key`, optional `batch_id` | `x1` |
| `POST /transfer/update_msg` | `statechain_id`, `auth_sig`, `new_user_auth_key`, `x1_pub`, `enc_transfer_msg` | `updated` |
| `GET /transfer/get_msg_addr/<new_auth_key>` | path `new_auth_key` | `list_enc_transfer_msg` |
| `GET /info/statechain/<statechain_id>` | path `statechain_id` | `enclave_public_key`, `num_sigs`, `statechain_info`, `x1_pub` |
| `POST /transfer/unlock` | `statechain_id`, `auth_sig`, optional `auth_pub_key` | `message` |
| `POST /transfer/receiver` | `statechain_id`, optional `batch_data`, `t2`, `auth_sig` | `server_pubkey`; a locked or expired batch returns `code`, `message` |
| `POST /withdraw/complete` | `statechain_id`, `signed_statechain_id` | `message` |
| `GET /info/config` | none | `batchtimeout`, `version` |

`statechain_info` is an array of rows with `statechain_id`, `server_pubnonce`,
`challenge`, and `tx_n`. `x1_pub` is nullable. The signing identifier is an
opaque 32-byte hexadecimal string; it is normalized to lowercase. The
`negate_seckey` wire value must be `0` or `1`. The complete response and error
schema is in [OpenAPI](../docs/openapi.yaml).

## Transfer-generation fencing and close

The client persists a transfer intent before its first sender mutation. Under
the locked current-owner authentication row, an exact active
`/transfer/sender` request replays the stored `x1` after response loss instead
of allocating another share. That guarantee applies while no different
authenticated request has replaced the server's one-row transfer generation;
a consumed `key_updated = true` generation is not replayed.

Both `/transfer/sender` and `/transfer/update_msg` return `404` when the
statechain is absent and `401` when the current owner's signature is invalid.
An absent coin from an earlier Lockbox deployment must use its saved on-chain
recovery transaction; it cannot be initialized on the replacement Lockbox.

The three later transfer mutations bind to that exact generation:

- `/transfer/update_msg` requires canonical compressed `x1_pub`. Its owner
  signature covers the domain-separated digest of statechain ID, recipient
  authentication key, `x1_pub`, and the SHA-256 of decoded ciphertext bytes.
- For BIP448 `/transfer/unlock`, existing `auth_pub_key` is required and carries
  the canonical compressed public key derived from `x1`. It is a generation
  tag, not the authentication key. `auth_sig` covers the domain-separated
  statechain/generation digest and the authenticated `CurrentOwner` (`0x00`) or
  `Recipient` (`0x01`) role; each role clears only its own flag.
- For BIP448 `/transfer/receiver`, existing `batch_data` is required and
  carries the same canonical `x1` public key. The recipient signature covers
  the domain-separated digest of statechain ID, the exact 32-byte `t2`, and
  that generation. Batch validation, authentication, the lockbox call, and
  conditional Mercury updates run while the generation rows are locked.

These operations share the `statechain_data` then `statechain_transfer` lock
order, so a stale generation cannot mutate its successor. The receiver's
lockbox-success/Mercury-commit crash boundary remains unrepaired.

`/withdraw/complete` accepts only a successful lockbox delete with the exact
body `Statechain deleted.` before running all Mercury deletes in one fallible
transaction. Duplicate sweeps do not call this route; only an accepted
canonical withdrawal can close the statechain.

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
  59 direct entries in eight binaries. This is an Inquisition-dependent proof
  of concept, with no automatic stale-state watcher, Bitcoin mainnet support,
  or production-use claim. Tests establish only their direct assertions.
