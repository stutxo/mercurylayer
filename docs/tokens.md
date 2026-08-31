# Deposit tokens

Mercury can issue either an on-chain payment token through the optional token
server or a free local token for a non-mainnet development network. A token is
consumed when `/deposit/init/pod` successfully initializes a statechain; it is
not the statecoin funding output.

The token is consumed creating one logical statechain; it does not bind a
funding amount. The client later pins the canonical funding amount. Paying the
resulting aggregate Bitcoin script again does not consume another token or
create a second statechain; those later same-script outputs are client-side
cooperative bindings described below.

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
