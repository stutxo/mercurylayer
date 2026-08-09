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
| `enclaves` | `ENCLAVES` | array of `{ url, allow_deposit }`; the environment value is JSON |
| `db_user` | `DB_USER` | string |
| `db_password` | `DB_PASSWORD` | string |
| `db_host` | `DB_HOST` | string |
| `db_port` | `DB_PORT` | unsigned 16-bit integer |
| `db_name` | `DB_NAME` | string |
| `token_server_url` | `TOKEN_SERVER_URL` | optional string |

When `token_server_url` is set, `/deposit/get_token` proxies token generation
to that service. When it is absent, the local path creates a free,
already-confirmed token unless the configured `network` string is literally
`mainnet`. This exact string comparison is a development guard, not validation
of Bitcoin network semantics or a production-safety boundary. The fresh
database schema is documented in [the database reference](../docs/server_db.md).

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
| `POST /transfer/update_msg` | `statechain_id`, `auth_sig`, `new_user_auth_key`, `enc_transfer_msg` | `updated` |
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
