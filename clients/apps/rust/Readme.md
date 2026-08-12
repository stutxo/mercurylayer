# `client-rust`

This crate is the command-line front end to the BIP448 wallet library. From the
workspace root, invoke it as `cargo run -p client-rust -- <COMMAND>`. From this
directory, `cargo run -- <COMMAND>` is equivalent.

## Commands and arguments

The complete Clap surface is:

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
`bip448-transfer-send` accepts only `--force-send-with-duplicates`; it
acknowledges the cooperative duplicate warning and bypasses no other gate.

`bip448-sweep-duplicate` accepts a base-10 nonzero `u32` index, including
`4294967295`, and sweeps exactly the confirmed binding selected by the index
shown in this wallet's `coin.duplicates` list. Its optional `FEE_RATE` and the
one-input/one-output fee and dust rules match `bip448-withdraw`. Success is one
JSON object with `statechain_id`, `duplicate_index`, `source_outpoint`,
`amount_sats`, `sweep_txid`, `broadcast_status`, and `exit_only`.

`broadcast-bip448-recovery-package` documents only the canonical roles
`funding_update` and `settlement`. It requires exactly one of:

- one or more `--fee-input <FEE_INPUTS>` options, each formatted
  `txid:vout:value_sats`; or
- `--fund-from-wallet`.

It also accepts `--fee-rate <FEE_RATE>`. The optional positional
`CHANGE_ADDRESS` is used for fee-input change. `bip448-withdraw` has its own
optional positional `FEE_RATE`.

Configuration is loaded by the wallet library. `ML_SETTINGS_FILE` selects the
settings file; `ML_NETWORK=regtest` selects `regtest.Settings.toml` only when
that variable is absent. Current settings fields and command output are listed
in the [client guide](../../../docs/client_guide.md).

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
