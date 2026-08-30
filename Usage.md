# BIP448 client usage

Run the command-line client from the workspace root with:

```text
RUSTUP_TOOLCHAIN=1.92.0 cargo run -p client-rust -- <COMMAND>
```

The client loads `Settings.toml` by default. `ML_SETTINGS_FILE` selects another
settings file; an explicit extension or path is used as written, otherwise
`.toml` is appended. `ML_NETWORK=regtest` selects
`regtest.Settings.toml` when `ML_SETTINGS_FILE` is unset. `chain_backend`
supports authenticated Bitcoin Core RPC (`core`) and Esplora (`explorer`);
the latter requires `explorer_url`.

## Complete command surface

Angle-bracketed arguments are required and square-bracketed arguments or
options are optional. These spellings are the Clap command names.

```text
create-wallet <NAME>
new-token
new-bip448-deposit-address <WALLET_NAME> <TOKEN_ID> <AMOUNT>
bip448-recovery-fee-address <WALLET_NAME>
broadcast-bip448-recovery-package [OPTIONS] <WALLET_NAME> <STATECHAIN_ID> <ROLE> [CHANGE_ADDRESS]
list-statecoins <WALLET_NAME>
bip448-withdraw <WALLET_NAME> <STATECHAIN_ID> <TO_ADDRESS> [FEE_RATE]
bip448-sweep-duplicate <WALLET_NAME> <STATECHAIN_ID> <DUPLICATE_INDEX> <TO_ADDRESS> [FEE_RATE]
new-transfer-address [OPTIONS] <WALLET_NAME>
bip448-transfer-send [OPTIONS] <WALLET_NAME> <STATECHAIN_ID> <TO_ADDRESS> [BATCH_ID]
bip448-transfer-cancel <WALLET_NAME> <STATECHAIN_ID>
transfer-receive <WALLET_NAME>
payment-hash <WALLET_NAME> <STATECHAIN_ID>
confirm-pending-invoice <WALLET_NAME> <STATECHAIN_ID>
retrieve-pre-image <WALLET_NAME> <STATECHAIN_ID> <BATCH_ID>
get-payment-hash <BATCH_ID>
```

`new-transfer-address` accepts `-b` or `--generate-batch-id`.
`bip448-transfer-send` accepts exactly
`--force-send-with-duplicates` for the explicit duplicate warning
acknowledgement. The flag does not apply to another command and does not bypass
ownership, transfer-intent, withdrawal-attempt, exit-only, history, count,
batch, recipient, or server checks.

For `broadcast-bip448-recovery-package`, use the canonical `ROLE` value
`funding_update` or `settlement` and choose exactly one fee source:

- repeat `--fee-input <FEE_INPUTS>` with values encoded as
  `txid:vout:value_sats`; or
- pass `--fund-from-wallet` to discover confirmed inputs at the wallet-derived
  recovery fee address.

The recovery command also accepts `--fee-rate <FEE_RATE>` in sat/vbyte. Its
optional `CHANGE_ADDRESS` receives fee-input change; when explicit keyless
inputs are used and it is omitted, the wallet-derived recovery fee address is
used. `bip448-withdraw` and `bip448-sweep-duplicate` use their optional fee
rate as sat/vbyte with the fixed 112-vbyte one-input/one-output estimate. If
omitted, the estimated rate is capped by `max_fee_rate`; an explicit rate is
not rewritten. A rate must be finite and positive, the fee uses checked
`ceil(112 * rate)`, and the destination output must remain at or above its
script dust value.

## Duplicate inventory and sweep

`list-statecoins` still emits one object per logical coin. Once canonical
funding is pinned, every additional output to its exact aggregate script is
listed under `coin.duplicates`, regardless of value. Choose the stable index
shown by that wallet database and sweep exactly one confirmed duplicate with:

```text
bip448-sweep-duplicate <WALLET_NAME> <STATECHAIN_ID> <DUPLICATE_INDEX> <TO_ADDRESS> [FEE_RATE]
```

Index `0` is canonical and is rejected. The `DUPLICATE_INDEX` grammar is
base-10 `u32`; it accepts `4294967295` and rejects negative, nondecimal, and
overflow values. Success prints `statechain_id`, `duplicate_index`, exact
`source_outpoint`, `amount_sats`, `sweep_txid`, `broadcast_status`, and
`exit_only`. A retry must use the same destination and, when supplied, the
bit-identical fee rate recorded by the durable attempt.

See the [client guide](docs/client_guide.md) for the lifecycle and exact JSON
fields printed by each workflow command.

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
  Mercury has six and lockbox has two. The CLI has sixteen commands, including
  exact flag `--force-send-with-duplicates`; the intended ignored matrix has
  58 direct entries in eight binaries. This is an Inquisition-dependent proof
  of concept, with no automatic stale-state watcher, Bitcoin mainnet support,
  or production-use claim. Tests establish only their direct assertions.
