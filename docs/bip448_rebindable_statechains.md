# BIP448 Rebindable Statechains

This document records the protocol direction for the additive rebindable statechain work and explains, from first principles, why the protocol works.

The protocol has exactly three transaction roles: `Tx0` (funding), `U(n)` (update, which *is* state n), and `S(n)` (settlement). There is no separate "state transaction" — the state-n transaction is `U(n)`.

## Why BIP448, Not APO

APO/BIP118 is not available on Bitcoin today. Current Taproot signatures commit to the exact input being spent, so a pre-signed transaction cannot normally be rebound to a different previous output.

The implementation target for this repository is therefore not BIP118/APO. The target is the Bitcoin Inquisition BIP448 opcode bundle:

- BIP446 `OP_TEMPLATEHASH` (`0xce`).
- BIP348 `OP_CHECKSIGFROMSTACK` (`0xcc`).
- BIP349 `OP_INTERNALKEY` (`0xcb`).

Inquisition constrains these Tapscript `OP_SUCCESSx` bytes into real opcodes. This makes it possible to verify a signature over a transaction template that does not commit to the exact previous output. That is the rebindability needed for eltoo-like state updates.

## The Problem: Normal Signatures Nail You To One Specific Coin

When you sign a normal Bitcoin transaction, the signature commits to (among other things) **which exact output you're spending** — the `txid:vout` of the input. Change the input to point at a different coin, and the signature is garbage.

That sounds like a technicality, but it kills a whole class of protocols. Suppose two parties share a coin off-chain and update its state 100 times. State 100 is the truth. But the transaction from state 5 is still sitting on someone's disk, and it is *still valid on-chain* — Bitcoin doesn't know state 5 is stale. If the old owner broadcasts state 5, what can the current owner do? They would want to respond with state 100... but their state-100 transaction was pre-signed to spend the **funding output**, not the output that state 5 just created. Its signature is bound to the wrong prevout. They're stuck.

The historical fixes are all awkward:

- **Lightning's answer:** punishment — each party holds a revocation secret for every old state and takes *all* the cheater's money if an old state appears. It works, but requires storing data per state, and it does not translate to statechains: the new owner of a statechain wasn't a participant in the old states, so they cannot hold revocation material for them.
- **Current Mercury's answer:** decrementing timelocks — each newer backup transaction becomes valid *earlier* than the older ones. It works, but the coin has a finite lifetime (the timelock room runs out) and every transfer burns some of it.

What you actually want is one simple rule, enforced by consensus:

> **The newest state can always spend the older state, wherever it lands. The older state can never spend the newer one.**

That is eltoo / LN-Symmetry. And it requires a signature that is **not** nailed to a specific prevout — a *rebindable* signature.

## What BIP448 Gives You: A Signature Over The Transaction's "Fingerprint Minus The Prevout"

BIP448 is three small Tapscript opcodes that compose into exactly this. Think of them as three Lego bricks:

**`OP_TEMPLATEHASH` (BIP446, byte `0xce`)** — pushes a 32-byte hash of *the transaction currently being validated*. The hash covers: version, locktime, all input sequences, **all outputs**, the input index, and the annex. It deliberately **omits**: the prevout (`txid:vout`), the spent amount, and the spent scriptPubKey.

So it is a fingerprint of "what this transaction *does*" — where the money goes, what timelocks it carries — with the "which coin it takes the money *from*" field blanked out.

**`OP_CHECKSIGFROMSTACK` / CSFS (BIP348, byte `0xcc`)** — verifies a BIP340 Schnorr signature over an **arbitrary message from the stack**, instead of over the transaction sighash. Normal `OP_CHECKSIG` says "verify a signature over *this transaction*." CSFS says "verify a signature over *whatever these 32 bytes are*." The signature is a raw 64-byte BIP340 signature over the message bytes — no sighash byte, no extra hashing.

**`OP_INTERNALKEY` (BIP349, byte `0xcb`)** — pushes the Taproot internal key of the output being spent. A convenience/optimization: instead of hard-coding a pubkey in the script, the script says "use whatever key this output was built with."

Now compose them:

```text
OP_TEMPLATEHASH  OP_INTERNALKEY  OP_CHECKSIGFROMSTACK
```

Execution, step by step, with a 64-byte signature as the only witness item:

```text
stack: [sig]
OP_TEMPLATEHASH      → [sig, fingerprint]     # fingerprint of the SPENDING tx
OP_INTERNALKEY       → [sig, fingerprint, P]  # the aggregate key
OP_CHECKSIGFROMSTACK → [1]                    # did P sign this fingerprint?
```

In English: **"You may take this coin if the key P has signed the fingerprint of the transaction you're taking it with."**

And here is the punchline: because the fingerprint omits the prevout, you can take an already-signed transaction, **re-point its input at a different coin, and the signature stays valid** — the fingerprint didn't change. That is rebinding. It is the same effect `SIGHASH_ANYPREVOUT` (BIP118) would have given, built out of smaller parts.

> **Intuition:** a normal Bitcoin signature is a ticket for one specific seat: "spend coin `abc123:0`, nothing else." A BIP448 template signature is a ticket for the show: "any coin whose script accepts this key may be spent by *this exact transaction*." You lock down everything about the transaction itself — outputs, locktime, sequences — and free up only the one thing you can't predict: which output it will end up spending.

## The Three Transactions

There is one key throughout: **`P = user_share + server_share`**, Mercury's aggregate key. Mercury's transfer protocol already has the property that `P` stays *constant* forever while the ability to sign moves from old owner to new owner (the server updates its share and deletes the old one). Every output below is `TR(P, {...leaves})`.

### `Tx0` — The Funding Transaction (The Vault Door)

The deposit. It locks the coin into a Taproot output with **one** script leaf — the bare primitive:

```text
funding_update_leaf:
OP_TEMPLATEHASH OP_INTERNALKEY OP_CHECKSIGFROMSTACK
```

Meaning: "this coin can be pulled into any transaction whose fingerprint P has signed." No state gate is needed — it is the entry point, state 0 in spirit.

### `U(n)` — The Update Transaction (The State Itself)

`U(n)` **is** state n. It is a small transaction:

- `nLockTime = 500_000_000 + n` — the state number, smuggled into the locktime field
- one protocol input, prevout initially a **placeholder** (this is the rebindable part), sequence non-final
- output: the **state output** for state n (plus the fee-bump anchor selected in Phase 3)

Its input carries the CSFS signature by `P` over `U(n)`'s fingerprint. That signature is what user and server create together (blinded MuSig) whenever the statechain moves to state n — at deposit for `U(1)`, at each transfer for `U(n+1)`.

The state output has **two** leaves:

```text
state_update_leaf(n):                                     # "a STRICTLY newer state may replace me"
<500_000_000 + n + 1> OP_CHECKLOCKTIMEVERIFY OP_DROP
OP_TEMPLATEHASH OP_INTERNALKEY OP_CHECKSIGFROMSTACK

state_settlement_leaf(settlement_template_hash(n)):        # "or exactly S(n) may cash me out"
<32-byte hash of S(n)> OP_TEMPLATEHASH OP_EQUAL
```

Leaf 1 is the same primitive as the funding leaf, plus a **CLTV gate**. Leaf 2 is the exact-template exit hatch, described next.

Notice the update gate uses `n + 1` on purpose, so only a *strictly newer* update (`U(m)`, `m ≥ n+1`) can replace the state-n output — `U(n)` carries locktime `n` and so cannot spend its own output. Why the `+1` matters: once `U(n)` is broadcast its CSFS signature is public and the P2A fee anchor is keyless, so if the update leaf gated at `n` too, *anyone* could rebind `U(n)` back onto the output it just created — remaking an identical state-n output and restarting `S(n)`'s challenge-delay clock over and over, stalling the owner's exit forever. Gating at `n+1` makes that self-replay impossible while still letting any genuinely newer state override an older one. The settlement leaf has no separate CLTV gate: `OP_TEMPLATEHASH` commits to `S(n)`'s `nLockTime`, so any transaction that passes `OP_EQUAL` already has the committed `500_000_000 + n` locktime.

The settlement challenge delay is enforced by the settlement transaction's committed `nSequence` plus BIP68 sequence locks, not by a duplicate `OP_CHECKSEQUENCEVERIFY` in the script.

### `S(n)` — The Settlement Transaction (The Exit Hatch)

`S(n)` pays the coin to the current owner's normal wallet address. It has:

- `nLockTime = 500_000_000 + n` (same state number)
- `nSequence = challenge_delay` — a BIP68 **relative** timelock: "I can only confirm `challenge_delay` blocks after the output I spend was confirmed"
- prevout: placeholder, rebindable just like `U(n)`

Here is the elegant part: **`S(n)` is never signed by anyone.** Look at leaf 2 again: the state output's script *contains the 32-byte fingerprint of `S(n)` verbatim*. The script check is:

```text
push expected fingerprint → compute actual fingerprint of the spending tx → OP_EQUAL
```

"You may take this coin if you *are* the transaction I was built to expect." The authorization is not a signature — it is identity. `S(n)` was decided (and its hash baked into the output) *before* `U(n)` was ever signed. That is why the build order is:

```text
build S(n) → hash it → build the state output containing the hash → build and sign U(n) paying to that output
```

This kills a whole trust problem: the server can never withhold your exit. If you hold `U(n)` and its signature, your exit path is *physically inside* `U(n)`'s output script. There is nothing more to ask anyone for. The settlement witness is just `[script, control block]` — no signature stack item at all.

## The Lifecycle — Where Rebinding Actually Happens

**Deposit:** fund `Tx0`. User and server co-sign `U(1)` (which commits to `S(1)`'s hash). The owner stores `U(1)`, `S(1)`, the signature, and the scripts. Nothing else goes on-chain. The coin now floats off-chain.

**Transfer (state n → n+1):** the receiver builds their `S(n+1)` (paying *their* recovery address), computes its hash, builds the state-(n+1) output, and gets `U(n+1)` signed by `P`. The server updates key shares — `P` unchanged, the old owner's share dead. The receiver verifies everything by *reconstruction*: rebuild the templates byte-for-byte, recompute the hashes, check the signature. The old owner keeps their stale `U(n)`, `S(n)`... which are still consensus-valid. That is deliberate — the script handles it.

**Honest exit (current owner at state 9):**

```text
1. Take U(9), rebind its input:  placeholder → Tx0's outpoint.   Signature still valid.
2. Broadcast U(9). Coin moves into the state-9 output.
3. Wait challenge_delay blocks (BIP68 forces this on S(9) anyway).
4. Take S(9), rebind its input:  placeholder → U(9)'s outpoint.  Hash still matches.
5. Broadcast S(9). Coin lands in the owner's wallet.
```

**The cheat, and why it fails** — this is the whole reason the protocol exists:

```text
Old owner broadcasts stale U(5) spending Tx0.        (valid! consensus can't know it's stale)
Coin is now in the state-5 output... but S(5) must wait challenge_delay blocks.

The current owner's watcher sees U(5). During the window:
  Take U(9). Rebind its input → U(5)'s output. Broadcast.

Does consensus accept it?
  ✓ CSFS:  P signed U(9)'s fingerprint; the fingerprint ignores the prevout swap.
  ✓ Update gate on U(5)'s output: requires locktime ≥ 500000006 (state 5's gate is 5+1).
           U(9) carries 500000009. Pass.
The coin fast-forwards from state 5 to state 9. S(5) is now spending a coin
that no longer exists. Wait the delay, settle with S(9). Done.
```

And why can't the old owner do the same in reverse?

```text
Old owner tries U(5) against the state-9 output:
  ✗ Update gate requires locktime ≥ 500000010 (state 9's gate is 9+1). U(5) carries 500000005. Rejected.
Old owner tries S(5) against it:
  ✗ Settlement gate requires locktime ≥ 500000009 (S(5) carries 500000005) — and the
    settlement leaf's committed hash is S(9)'s, not S(5)'s. Two locked doors.
```

And why can't *anyone* — even the current owner's own broadcast, replayed by a griefer — stall the exit by re-applying `U(9)` to the output it just created?

```text
Griefer tries U(9) against U(9)'s own state-9 output:
  ✗ Update gate requires locktime ≥ 500000010 (state 9's gate is 9+1). U(9) carries 500000009. Rejected.
```

This last case is exactly why the update gate is `n+1` and not `n`: it forbids same-state
replay, so no one can keep recreating the state-9 output to reset S(9)'s challenge clock.

That is the asymmetry, enforced purely by script: **newer spends older; older can never spend newer.** One transaction pair to store, no punishment machinery, no per-state secrets.

Two supporting details worth understanding:

- **Why `nLockTime` works as a state counter:** CLTV just does a numeric comparison between the script's number and the transaction's locktime. By using `500_000_000 + n`, the values fall in Bitcoin's *timestamp* range — and `500_000_001` is a date in 1985, permanently in the past. Consensus never actually makes anyone *wait* for these locktimes; the field degenerates into a pure monotonic counter. (This is the standard eltoo trick, used by the BIP442 LN-Symmetry sketch.)
- **Why the CLTV gate must exist at all:** the fingerprint does not commit to the scriptPubKey being spent. Without the gate, an old `U(5)` signature would be rebindable onto the *state-9* output too — rebinding would work backwards as well as forwards. The gate is the ratchet that gives rebinding a direction.
- **Why the update gate is `n+1`, not `n`:** `S(n)` can settle its own state because its template hash commits to locktime `n`, but the update leaf gates one higher, at `n+1`. This makes forward progress *strict*: a state-`n` output can only be advanced by state `n+1` or later, never by `U(n)` itself. If it gated at `n`, the now-public `U(n)` signature plus the keyless anchor would let anyone replay `U(n)` onto its own output indefinitely, resetting the settlement delay each time — a liveness attack. The `+1` closes it without weakening override, since a genuinely newer state always has a number `> n`.

## Why BIP448 Enables This, In One Paragraph

Because eltoo needs exactly one primitive Bitcoin never had: **a consensus-checked signature over a transaction that doesn't say which coin it spends.** BIP118/APO proposed that as a new sighash mode and never activated. BIP448 gets the identical effect from parts: `OP_TEMPLATEHASH` manufactures the "transaction minus prevout" message, CSFS verifies a signature over that message instead of over a sighash, and `OP_INTERNALKEY` wires the check to the aggregate key the output already has — which composes perfectly with Mercury, because Mercury's transfer protocol already keeps that key constant while quietly moving the *ability to sign it* to each new owner and deleting it from the old one. The signature stays valid wherever the coin is; the script ratchet ensures only newer states use that freedom; the pre-committed settlement hash guarantees the exit needs no one's permission.

## What BIP448 Does Not Fix

The trust assumptions that remain:

- You still trust the server not to secretly sign a competing higher state with someone else and not to collude with a previous owner. The script removes settlement from that trust surface, not state creation.
- Someone must be watching the chain during challenge windows. An offline owner with no watcher can lose to a stale-state broadcast that settles unchallenged.
- The fingerprint ignores input *amounts*, so all fee and value discipline lives in validation code rather than in Script — which is why the implementation plan is insistent about fee-bump anchors, value schedules, and receiver-side byte-for-byte reconstruction.
- BIP448 is not active on Bitcoin mainnet. This protocol runs against Bitcoin Inquisition (regtest/signet), where the three opcodes are merged but must be activated by deployment signaling.

## Local Implementation Targets

The code and tests for this path must target:

- Bitcoin Inquisition commit `f5365867662091c2dbf1b2d438b8bb477a3dcb6f`.
- `rust-bitcoin` branch `inquisition-bip448-support-0.30.2`, pinned in `Cargo.lock` at `fa687ecd59ed2de49c32a3b85115ce4024406766`.

This work must remain additive beside the existing Mercury decrementing-locktime backup transaction protocol until the BIP448 path has independent end-to-end tests.
