# Mercury BIP448 Mutinynet browser wallet

Static Rust/WASM wallet for the core BIP448 statecoin lifecycle on Mutinynet
signet. The visible application deliberately stays focused:

1. create or restore a local wallet and onboard bitcoin through a one-time
   deposit address;
2. send, receive, and cancel offchain statecoin transfers;
3. cooperatively withdraw to an onchain address;
4. sweep an extra deposit when one is detected; and
5. download the saved update and settlement transactions as raw hex, then
   unilaterally exit with them if Mercury is unavailable.

The normal path is deposit → offchain transfer → cooperative withdrawal.
Unilateral exit is the server-independent recovery path. This remains a
Mutinynet test bench rather than a production wallet.

Offchain transfers are asynchronous. The sender uploads an encrypted handoff,
then can close the wallet. The recipient wallet accepts it automatically on its
next background check, so both people never need to be online at the same time.
While a transfer is possible or pending, the client checks Mercury every
second; full onchain reconciliation runs every 5 seconds to avoid repeating
unrelated Esplora requests.

The protocol layer retains durable journals and validation for every
irreversible signing boundary. Command-oriented controls such as payment
latches, explicit fee inputs, and deployment editors are not part of the
focused browser interface. The Enclave disclosure checks the configured
runtime and shows its endpoint, mode, authentication, PCR measurements, and
trust model.

## Security and recovery model

The versioned wallet state is stored under
`mercury-bip448-mutinynet-browser-wallet-v1` in `localStorage`. It includes the
seed phrase, private shares, unused receive keys, every pending deposit
address and amount, exact transfer, cooperative-withdrawal and duplicate-sweep
journals, state history, accepted BIP448 recovery transactions, and exact
unilateral-exit package attempts. It is not encrypted. Web Locks serialize
mutations across tabs, and every protocol boundary checkpoints the exact
`localStorage` revision before continuing.

The UI can download the signed update and settlement parent transactions as
raw `.hex` files. Those files do not contain the CPFP fee child generated at
broadcast time and are not a wallet backup. The UI reveals and imports seed
phrases, but intentionally has no snapshot-file import or export. A seed phrase
restores keys, not statechain IDs, the server share, signed BIP448
update/settlement transactions, or package attempts. Keep this browser's local
data intact until the statechain has settled.

The launch Lockbox and Mercury database start with empty state. After a fresh
`v1` wallet is successfully persisted, startup erases every other key in the
browser-wallet namespace. Prelaunch wallet snapshots are intentionally not
migrated into the launch deployment.

The browser uses the Enclavia SDK directly rather than trusting Mercury to
report its own attestation. **Verify enclave** opens an end-to-end encrypted
Noise channel from browser WASM to the configured Lockbox, verifies the
production AWS Nitro COSE certificate chain, binds the attestation document to
that Noise handshake, and requires exact PCR0/1/2 matches. **Verify coin** uses
the same direct attested channel to send a fresh random challenge and
statechain ID to the Lockbox. The browser requires the response to echo both
values and to return the server share already recorded with the wallet coin.
The browser is not given Mercury's Lockbox bearer token: every Lockbox route
except this read-only proof rejects browser requests as unauthorized. Mercury
neither sees the encrypted proof request nor supplies its response; it can
deny its separate service but cannot forge a successful direct proof.
Cached proofs without the direct-verification method marker are discarded on
load rather than relabeled; the rest of the `v1` wallet snapshot stays intact.

Direct attestation and statechain proof operations are each bounded at 20
seconds. Mercury HTTP calls are bounded at 65 seconds. A deposit that exceeds
three seconds keeps the operation disabled but replaces the generic busy text
with elapsed time and an explicit reminder that its persisted pending deposit
can be retried.

## Offchain send and receive

A receiver creates a one-time `tml1…` Mercury address containing separate user
and authentication public keys. The sender:

1. locks the current generation with Mercury and receives an idempotent `x1`;
2. signs the receiver's next BIP448 recovery state with the enclave;
3. encrypts the complete recovery history to the receiver authentication key;
4. uploads the exact encrypted message and marks the coin in transfer.

The receiver independently verifies the confirmed, unspent funding output,
state history, transfer authorization, signature count, recovery templates, and
enclave key generation before authorizing the key-share rotation. Sender and
receiver journals are stored before each irreversible request so reloading the
page resumes the same operation rather than inventing new protocol material.

## Cooperative withdrawal and duplicate outputs

Sync assigns a stable local binding index to every output paying the statecoin
funding address. Binding index `0` is canonical; later outputs are duplicates.
Confirmed duplicates remain controlled by the current owner but are not added
to the statecoin balance. The UI requires each duplicate to be swept or
independently confirmed spent before it closes the canonical statechain.

Cooperative withdrawal and duplicate sweep use durable
`Prepared → FirstArmed → NonceStored → SecondArmed → Signed` journals. The
second signing request is the irreversible boundary: after it is armed, the
coin is exit-only. Reloading resumes the exact nonce, signing session,
transaction, broadcast, and canonical `withdraw/complete` request.

Transfer cancellation is a successor transfer back to a fresh local one-time
address.

## Hosted Enclavia deployment

Open the public Mutinynet wallet at [bip448.cash](https://bip448.cash/).
Production deployment assets and credentials are maintained separately so they
do not live in this protocol repository. The hosted production-mode defaults
are:

- Mercury API: `https://bip448.cash`;
- chain API: `https://mutinynet.com/api`;
- explorer: `https://mutinynet.com`;
- Enclavia HTTPS endpoint:
  `https://11b69774-3ba1-4911-8897-ab2380488cdb.enclaves.beta.enclavia.io`;
- PCR0: `4adae8229127fb7e2403ab0651fd6bc5f13cf72c95938a3b4d5fbf2f86f5529f12b97c124a7eb1832ae223d48aafc737`;
- PCR1: `20167032afc54a578d7fa4509dd79e880d504a9d933d820d55a45a8a06880843176a9be7c6ddd375efc5557c2ad8370d`;
- PCR2: `624a5ff2de7daa1a1105837719d0dfc870ccca4ad519a2bc4a96fe53c368b9cd20b1e934f24f36236dd59ae5b3ab997e`.

The Lockbox uses Nitro hardware isolation, encrypted persistent storage,
anti-rollback protection, and synchronizer recovery. This remains a Mutinynet
evaluation deployment; do not use real funds.

## Live wallet and unilateral-exit demonstration

1. Reveal and record the seed phrase, then keep this browser's local data intact.
2. Create one or more deposit addresses and fund the chosen address with its
   exact requested value from the [Mutinynet faucet](https://faucet.mutinynet.com).
   The Onboard selector shows one saved address at a time, selects the newest
   by default, and labels every option with its current funding or recovery
   status. The wallet continues watching every saved address, so accidentally
   funding an older selection remains recoverable.
3. While the wallet is visible, it checks transfer mailboxes every second and
   performs a full onchain update every 5 seconds without disabling or changing
   the status shown by the rest of the interface. Hidden tabs pause polling.
   Once funded, BIP448 `sign/first` and `sign/second` store the pre-signed `U`
   and `S` transactions for logical state `N=1`.
4. Verify the Enclavia Lockbox proof from the statechain card. The browser opens
   its own attested Noise channel to the Lockbox, sends a fresh challenge, and
   checks the echoed challenge, statechain ID, saved server share, and pinned PCRs.
5. Fund the displayed recovery-fee address and wait for that UTXO to confirm.
6. Broadcast the **U package**. The browser builds and signs a CPFP child and
   posts `[U, child]` to Mutinynet Esplora `POST /txs/package`.
7. Wait while the UI counts confirmations against the record's committed
   `challenge_delay` (currently 144 blocks).
8. Fund the recovery-fee address again if its prior change is not yet confirmed.
9. When the countdown reaches zero, broadcast the **S package**. The settlement
   pays the complete canonical value to the browser-derived recovery address.

Completed withdrawals remain in the Offboard selector with a `WITHDRAWN` label.
Their statecoin card collapses to its summary by default and can be expanded to
inspect the saved details.

All fee controls default to 0.1 sat/vB and accept 0.1–10 sat/vB. Required
whole-satoshi fees are rounded up, so the resulting effective rate can be
slightly above the selected value.

Steps 6-9 make no Mercury or Lockbox request. They demonstrate the unilateral
BIP448 path from already accepted local recovery state.

## Build

The supported build path is containerized because the patched secp256k1 library
needs Clang for `wasm32-unknown-unknown`:

```sh
docker build \
  --file web-wallet/Dockerfile \
  --tag mercury-bip448-web-wallet:local \
  .

docker run --rm -p 127.0.0.1:3000:8080 \
  mercury-bip448-web-wallet:local
```

For a host build, install Rust 1.92, Clang, Node.js, `wasm-pack`, and the WASM
target, then run `web-wallet/build.sh`.

## Browser tests

The Playwright suite uses a reusable Mercury/Mutinynet route harness and a
deterministic, protocol-valid recovery snapshot. Seventeen browser scenarios
cover the focused chrome, invisible one-second transfer polling with five-second
full reconciliation, mobile double-tap, input-focus, offboard-panel sizing,
busy-state About access, seed replacement safety, automatic-token onboarding,
status-labelled compact selection of multiple unused deposit addresses,
one-time mobile receive addresses, enclave runtime verification, coin-specific
server-share and PCR verification, durable
send resumption, cooperative withdrawal, extra-deposit sweep, raw
recovery-transaction downloads, and complete unilateral U/S package broadcast
with reloads.

Rust tests provide the cryptographic protocol layer: a complete
token-to-confirmed deposit, real blinded MuSig signing for duplicate sweep plus
canonical withdrawal, full two-wallet send/receive with Lockbox key rotation,
cancellation back to the sender, exact replay, and validation of every
persisted checkpoint.

```sh
npm ci --prefix web-wallet
npx --prefix web-wallet playwright install chromium
docker build --file web-wallet/Dockerfile \
  --build-arg WEB_WALLET_FEATURES=e2e-harness \
  --tag mercury-bip448-web-wallet:e2e .
npm --prefix web-wallet run test:e2e
```

The `e2e-harness` build argument swaps the attested Enclavia SDK channel for
plain HTTP calls the Playwright harness can stand in for; production images
must be built without it.

Set `UPDATE_WEB_WALLET_FIXTURES=1` when intentionally regenerating the fixture;
the Rust unit test otherwise rejects fixture drift.

The mnemonic and testnet WIF values under `tests/fixtures` are deterministic,
public test material with no mainnet value.

## Limitations

- Mutinynet test funds only.
- One local browser wallet; secrets and protocol journals are stored
  unencrypted in `localStorage`.
- Package or transaction acceptance by one Mutinynet node does not guarantee
  network-wide propagation; the UI follows confirmation rather than assuming
  propagation.
- The 144-block challenge is real. Recovery does not bypass or shorten it.
