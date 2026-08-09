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
new-transfer-address [OPTIONS] <WALLET_NAME>
bip448-transfer-send <WALLET_NAME> <STATECHAIN_ID> <TO_ADDRESS> [BATCH_ID]
bip448-transfer-cancel <WALLET_NAME> <STATECHAIN_ID>
transfer-receive <WALLET_NAME>
payment-hash <WALLET_NAME> <STATECHAIN_ID>
confirm-pending-invoice <WALLET_NAME> <STATECHAIN_ID>
retrieve-pre-image <WALLET_NAME> <STATECHAIN_ID> <BATCH_ID>
get-payment-hash <BATCH_ID>
```

`new-transfer-address` accepts `-b` or `--generate-batch-id`.

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
