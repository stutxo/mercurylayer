# Mercury Layer BIP448 prototype

This repository is a proof-of-concept statechain implementation built around
BIP448 transaction templates and the consensus rules available in the pinned
Bitcoin Inquisition environment. It contains:

- the Rust Mercury HTTP server and shared protocol library;
- the Rust wallet library and `client-rust` command-line application;
- the C++ lockbox service for sealed key shares, BIP448 nonces, partial
  signatures, key updates, and signature counts;
- the optional token HTTP server; and
- unit tests plus ignored Docker/Inquisition integration suites.

Repeated payments to an accepted BIP448 aggregate funding script are tracked
as cooperative duplicate bindings. They do not create extra public wallet
coins. The client displays them under the one logical coin, can sweep them one
at a time, and permits canonical cooperative close only after every known
current-owner duplicate has a safe resolution.

Start with [Usage.md](Usage.md), use [Test.md](Test.md) for the executable test
matrix, and read the [BIP448 protocol description](docs/bip448_rebindable_statechains.md).
The [documentation index](docs/README.md) links the API, database, client,
batch/latch, token, and test references.

The annotated tag `bip448-legacy-inclusive-baseline` preserves the older,
legacy-inclusive source tree for historical inspection. It is not a claim that
the current implementation reproduces every behavior in that tree.

## Enclavia Lockbox on Mutinynet

The BIP448 Mercury coordinator can run on signet against a separately deployed
Enclavia Lockbox. Mercury pins the enclave's PCR0/1/2 measurements, verifies
attestation through the Enclavia SDK, and sends signing requests through the
encrypted direct channel.

Deployment assets — the Enclavia enclave runbook and scripts, the Mutinynet
Compose stack, and the EC2 publisher — live in the private
[`mercury-deploy`](https://github.com/stutxo/mercury-deploy) companion
repository so this tree stays focused on protocol code.

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
