# Deposit tokens

Mercury can issue either an on-chain payment token through the optional token
server or a free local token for a non-mainnet development network. A token is
consumed when `/deposit/init/pod` successfully initializes a statechain; it is
not the statecoin funding output.

## Token-server configuration

The token Rocket service reads these settings keys and environment variables:

| TOML key | Environment variable | Meaning |
| --- | --- | --- |
| `public_key_descriptor` | `PUBLIC_KEY_DESCRIPTOR` | descriptor used by the Core wallet setup |
| `network` | `BITCOIN_NETWORK` | Bitcoin network string |
| `core_rpc_url` | `CORE_RPC_URL` | Core/Inquisition RPC URL |
| `core_rpc_auth` | `CORE_RPC_AUTH` | optional `none`, `userpass`, or `cookie` |
| `core_rpc_user` | `CORE_RPC_USER` | username for `userpass` |
| `core_rpc_password` | `CORE_RPC_PASSWORD` | password for `userpass` |
| `core_rpc_cookie_file` | `CORE_RPC_COOKIE_FILE` | cookie path for `cookie` |
| `core_rpc_wallet` | `CORE_RPC_WALLET` | optional wallet name; default `mercury_tokens` |
| `core_rpc_wallet_create` | `CORE_RPC_WALLET_CREATE` | optional boolean; default `true` |
| `fee` | `FEE` | exact token payment amount in satoshis |
| `confirmation_target` | `CONFIRMATION_TARGET` | required confirmations |
| `db_user` | `DB_USER` | PostgreSQL user |
| `db_password` | `DB_PASSWORD` | PostgreSQL password |
| `db_host` | `DB_HOST` | PostgreSQL host |
| `db_port` | `DB_PORT` | PostgreSQL port |
| `db_name` | `DB_NAME` | PostgreSQL database |

Mercury selects this service with its optional `token_server_url` setting or
`TOKEN_SERVER_URL` environment variable.

## On-chain token flow

`GET /token/token_gen` asks the configured Core wallet for a new address,
generates a UUID token ID, inserts a row with `confirmed = false` and
`spent = false`, and returns:

```json
{
  "token_id": "...",
  "deposit_address": "...",
  "fee": 1000,
  "confirmation_target": 1
}
```

The numbers above illustrate the fields; their actual values come from the
token-server settings. Pay exactly `fee` satoshis to `deposit_address`.

`GET /token/token_verify/<token_id>` returns 404 for an unknown ID. If the row
is already confirmed or spent, it returns the stored booleans. Otherwise it:

1. parses the stored address and requires the configured network;
2. calls `listunspent` for the dedicated token wallet and address;
3. selects an output whose value is exactly the configured fee;
4. returns both flags false if no such output exists or its confirmation count
   is below the target; and
5. marks and returns `confirmed = true` once the target is met. A target of
   zero confirms an exact-value output immediately.

Every `200` verification response has this shape:

```json
{
  "confirmed": true,
  "spent": false
}
```

The boolean values reflect the current row.

With `token_server_url` configured, Mercury's `GET /deposit/get_token` proxies
`/token/token_gen` and adds `payment_method = "onchain"`. Its shared response
has `token_id`, `payment_method`, `deposit_address`, `fee`, and
`confirmation_target`.

## Free local token flow

When `token_server_url` is absent and Mercury's configured network is not
mainnet, `GET /deposit/get_token` inserts a local token with
`confirmed = true`, `spent = false`, and no on-chain address. It returns:

```json
{
  "token_id": "...",
  "payment_method": "free",
  "deposit_address": null,
  "fee": 0,
  "confirmation_target": 0
}
```

The free branch returns an internal-server error when Mercury is configured
with the literal network string `mainnet`. This is a development guard, not a
statement of deployment readiness on any other network.

## Token consumption during deposit initialization

`POST /deposit/init/pod` receives `auth_key`, `token_id`, and
`signed_token_id`. Mercury verifies the Schnorr signature of the token ID,
rejects an authentication key already assigned to a statechain, requires a
known unspent token, and requires confirmation. For an unconfirmed on-chain
row it asks the token server to verify the payment. It then requests a new
lockbox public key, inserts the Mercury statechain row, and updates the token
row to `spent = true`.

The final `tokens` table has only these columns:

```text
id serial4 PRIMARY KEY
token_id varchar NULL UNIQUE
onchain_address varchar NULL
confirmed boolean DEFAULT false
spent boolean DEFAULT false
```

The exact API schemas are in [openapi.yaml](openapi.yaml), and the literal
table definition is in [server_db.md](server_db.md).

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
