# Fresh database schemas

The current prototype is bootstrapped from one consolidated Mercury migration,
two lockbox table initializers, and one consolidated client SQLite migration.
Use empty databases and a new wallet file. These definitions are not an
upgrade path for an older deployment, and no data migration is implemented.

## Mercury PostgreSQL: six tables

`server/migrations/0001_bip448_schema.sql` creates exactly the following six
tables and one partial unique index:

```sql
CREATE TABLE public.statechain_data (
    id serial4 NOT NULL,
    token_id varchar NULL UNIQUE,
    auth_xonly_public_key bytea NULL,
    server_public_key bytea NULL UNIQUE,
    statechain_id varchar NULL UNIQUE,
    enclave_index integer NOT NULL,
    CONSTRAINT statechain_data_pkey PRIMARY KEY (id),
    CONSTRAINT statechain_data_server_public_key_ukey UNIQUE (server_public_key)
);

CREATE TABLE public.lightning_latch (
    id serial4 NOT NULL,
    statechain_id varchar NOT NULL,
    sender_auth_xonly_public_key bytea NULL,
    batch_id varchar NOT NULL,
    pre_image varchar NULL,
    locked boolean NOT NULL DEFAULT true,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT lightning_latch_pkey PRIMARY KEY (id),
    CONSTRAINT unique_statechain_sender_batch UNIQUE (statechain_id, batch_id)
);

CREATE TABLE public.statechain_transfer (
    id serial4 NOT NULL,
    statechain_id varchar NULL UNIQUE,
    new_user_auth_public_key bytea NULL,
    x1 bytea NULL,
    encrypted_transfer_msg bytea NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    key_updated boolean DEFAULT false,
    batch_id varchar NULL,
    batch_time TIMESTAMPTZ NULL,
    locked boolean NOT NULL DEFAULT false,
    locked2 boolean NOT NULL DEFAULT false,
    CONSTRAINT statechain_transfer_pkey PRIMARY KEY (id)
);

CREATE TABLE public.tokens (
    id serial4 PRIMARY KEY,
    token_id varchar NULL UNIQUE,
    onchain_address varchar NULL,
    confirmed boolean DEFAULT false,
    spent boolean DEFAULT false
);

CREATE TABLE public.bip448_signature_data (
    id serial4 NOT NULL,
    statechain_id varchar NOT NULL,
    signing_id varchar NOT NULL,
    server_pubnonce varchar NULL,
    challenge varchar NULL,
    negate_seckey boolean NULL,
    server_partial_sig varchar NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT bip448_signature_data_pkey PRIMARY KEY (id),
    CONSTRAINT bip448_signature_data_signing_id_ukey
        UNIQUE (statechain_id, signing_id),
    CONSTRAINT bip448_signature_data_signing_id_check
        CHECK (signing_id ~ '^[0-9a-f]{64}$')
);

CREATE TABLE public.signing_nonce_leases (
    statechain_id varchar NOT NULL,
    signing_id varchar NOT NULL,
    lease_token varchar NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT signing_nonce_leases_pkey PRIMARY KEY (statechain_id),
    CONSTRAINT signing_nonce_leases_signing_id_check
        CHECK (signing_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT signing_nonce_leases_lease_token_check
        CHECK (lease_token ~ '^[0-9a-f]{32}$')
);

CREATE UNIQUE INDEX bip448_signature_data_one_incomplete_per_statechain_idx
ON public.bip448_signature_data (statechain_id)
WHERE server_partial_sig IS NULL;
```

`server_public_key` in `statechain_data` has both the inline unique constraint
and the explicitly named unique constraint shown above; the documentation
preserves that literal migration shape.

## Lockbox PostgreSQL: two tables

The lockbox creates these two tables with `IF NOT EXISTS` when it starts:

```sql
CREATE TABLE IF NOT EXISTS generated_public_key (
    id SERIAL PRIMARY KEY,
    statechain_id varchar(50),
    sealed_keypair BYTEA,
    public_key BYTEA UNIQUE,
    sig_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS bip448_nonce_state (
    id SERIAL PRIMARY KEY,
    statechain_id varchar(50) NOT NULL,
    signing_id varchar(64) NOT NULL,
    public_nonce BYTEA NOT NULL,
    sealed_secnonce BYTEA NOT NULL,
    challenge varchar(64) NULL,
    negate_seckey INTEGER NULL,
    partial_sig varchar NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT bip448_nonce_state_unique UNIQUE (statechain_id, signing_id),
    CONSTRAINT bip448_nonce_state_signing_id_check
        CHECK (signing_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT bip448_nonce_state_challenge_check
        CHECK (challenge IS NULL OR challenge ~ '^[0-9a-f]{64}$'),
    CONSTRAINT bip448_nonce_state_negate_check
        CHECK (negate_seckey IS NULL OR negate_seckey IN (0, 1)),
    CONSTRAINT bip448_nonce_state_claim_check CHECK (
        (challenge IS NULL AND negate_seckey IS NULL AND partial_sig IS NULL)
        OR (challenge IS NOT NULL AND negate_seckey IS NOT NULL)
    )
);
```

The claim constraint permits a claimed row whose partial signature is still
null so an exact retry can finish or recover the signing round.

## Client SQLite: twelve tables

`clients/libs/rust/migrations/0001_bip448_client_schema.sql` creates exactly
these twelve tables and three explicit partial unique indexes. The migration is
fresh-database-only; changing this consolidated file is not an upgrade path.

```sql
CREATE TABLE IF NOT EXISTS wallet (
    wallet_name TEXT UNIQUE,
    wallet_json BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS bip448_statechains (
    wallet_name TEXT NOT NULL,
    statechain_id TEXT NOT NULL,
    aggregate_pubkey TEXT NOT NULL,
    funding_txid TEXT NOT NULL,
    funding_vout INTEGER NOT NULL,
    funding_value_sats INTEGER NOT NULL,
    latest_state_number INTEGER NOT NULL,
    challenge_delay INTEGER NOT NULL,
    amount_sats INTEGER NOT NULL,
    network TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (wallet_name, statechain_id)
);

CREATE TABLE IF NOT EXISTS bip448_transfer_messages (
    wallet_name TEXT NOT NULL,
    statechain_id TEXT NOT NULL,
    recipient_auth_pubkey TEXT NOT NULL,
    transfer_msg_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (wallet_name, statechain_id, recipient_auth_pubkey)
);

CREATE TABLE IF NOT EXISTS bip448_pending_deposit_signings (
    wallet_name TEXT NOT NULL,
    statechain_id TEXT NOT NULL,
    update_template_hash TEXT NOT NULL,
    signing_id TEXT NOT NULL,
    client_secret_nonce TEXT NOT NULL,
    client_public_nonce TEXT NOT NULL,
    blinding_factor TEXT NOT NULL,
    server_public_nonce TEXT NULL,
    state_locktime INTEGER NULL
        CHECK (state_locktime IS NULL
               OR state_locktime BETWEEN 500000000 AND 1000000000),
    funding_txid TEXT NULL,
    funding_vout INTEGER NULL,
    funding_value_sats INTEGER NULL,
    settlement_template_hash TEXT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (wallet_name, statechain_id)
);

CREATE TABLE IF NOT EXISTS bip448_pending_transfer_signings (
    wallet_name TEXT NOT NULL,
    statechain_id TEXT NOT NULL,
    funding_txid TEXT NOT NULL,
    funding_vout INTEGER NOT NULL,
    funding_value_sats INTEGER NOT NULL,
    update_template_hash TEXT NOT NULL,
    settlement_template_hash TEXT NOT NULL,
    state_locktime INTEGER NOT NULL CHECK (state_locktime >= 500000000),
    signing_id TEXT NOT NULL,
    client_secret_nonce TEXT NOT NULL,
    client_public_nonce TEXT NOT NULL,
    blinding_factor TEXT NOT NULL,
    server_public_nonce TEXT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (wallet_name, statechain_id)
);

CREATE TABLE IF NOT EXISTS bip448_scan_cursors (
    wallet_name TEXT NOT NULL,
    script_pubkey TEXT NOT NULL,
    coverage_start_height INTEGER NOT NULL CHECK (
        coverage_start_height BETWEEN 0 AND 4294967295
    ),
    scan_revision INTEGER NOT NULL CHECK (scan_revision >= 0),
    last_scanned_height INTEGER NOT NULL,
    last_scanned_block_hash TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (wallet_name, script_pubkey)
);

CREATE TABLE IF NOT EXISTS bip448_scanned_outpoints (
    wallet_name TEXT NOT NULL,
    txid TEXT NOT NULL,
    vout INTEGER NOT NULL,
    script_pubkey TEXT NOT NULL,
    value_sats INTEGER NOT NULL,
    height INTEGER NOT NULL,
    reserved_by TEXT NULL,
    reserved_at INTEGER NULL,
    PRIMARY KEY (wallet_name, txid, vout)
);

CREATE TABLE IF NOT EXISTS bip448_package_attempts (
    wallet_name TEXT NOT NULL,
    statechain_id TEXT NOT NULL,
    role TEXT NOT NULL,
    parent_txid TEXT NOT NULL,
    child_txid TEXT NOT NULL,
    child_tx_hex TEXT NOT NULL,
    fee_inputs_json TEXT NOT NULL,
    target_feerate_sat_per_vbyte REAL NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('Pending', 'Submitted', 'Confirmed', 'Abandoned')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (wallet_name, statechain_id, role)
);

CREATE TABLE IF NOT EXISTS bip448_state_history (
    wallet_name TEXT NOT NULL,
    statechain_id TEXT NOT NULL,
    state_number INTEGER NOT NULL,
    entry_json TEXT NOT NULL,
    PRIMARY KEY (wallet_name, statechain_id, state_number)
);

CREATE TABLE IF NOT EXISTS bip448_funding_bindings (
    wallet_name TEXT NOT NULL,
    statechain_id TEXT NOT NULL,
    binding_index INTEGER NOT NULL CHECK (binding_index BETWEEN 0 AND 4294967295),
    txid TEXT NOT NULL CHECK (length(txid) = 64),
    vout INTEGER NOT NULL CHECK (vout BETWEEN 0 AND 4294967295),
    value_sats INTEGER NOT NULL CHECK (value_sats BETWEEN 0 AND 2100000000000000),
    script_pubkey TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('Canonical', 'Duplicate')),
    observation_status TEXT NOT NULL CHECK (observation_status IN (
        'Mempool', 'Unconfirmed', 'Confirmed', 'SpentMempool',
        'SpentUnconfirmed', 'SpentConfirmed', 'Absent'
    )),
    funding_height INTEGER NULL CHECK (
        funding_height IS NULL OR funding_height BETWEEN 0 AND 4294967295
    ),
    spend_txid TEXT NULL CHECK (spend_txid IS NULL OR length(spend_txid) = 64),
    spend_height INTEGER NULL CHECK (
        spend_height IS NULL OR spend_height BETWEEN 0 AND 4294967295
    ),
    last_scanned_height INTEGER NOT NULL CHECK (
        last_scanned_height BETWEEN 0 AND 4294967295
    ),
    owner_user_pubkey TEXT NOT NULL,
    owner_state_number INTEGER NOT NULL CHECK (
        owner_state_number BETWEEN 1 AND 4294967295
    ),
    ownership_status TEXT NOT NULL CHECK (ownership_status IN ('Current', 'Previous')),
    first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (wallet_name, statechain_id, binding_index),
    UNIQUE (wallet_name, txid, vout),
    CHECK (
        (binding_index = 0 AND role = 'Canonical') OR
        (binding_index > 0 AND role = 'Duplicate')
    ),
    CHECK (
        (observation_status = 'SpentMempool'
         AND spend_txid IS NOT NULL AND spend_height IS NULL) OR
        (observation_status IN ('SpentUnconfirmed', 'SpentConfirmed')
         AND spend_txid IS NOT NULL AND spend_height IS NOT NULL) OR
        (observation_status NOT IN ('SpentMempool', 'SpentUnconfirmed', 'SpentConfirmed')
         AND spend_txid IS NULL AND spend_height IS NULL)
    ),
    CHECK (
        (observation_status = 'Mempool' AND funding_height IS NULL) OR
        (observation_status IN (
            'Unconfirmed', 'Confirmed', 'SpentUnconfirmed', 'SpentConfirmed'
         )
         AND funding_height IS NOT NULL) OR
        observation_status IN ('SpentMempool', 'Absent')
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS bip448_one_canonical_binding
ON bip448_funding_bindings (wallet_name, statechain_id)
WHERE role = 'Canonical';

CREATE TABLE IF NOT EXISTS bip448_withdrawal_attempts (
    wallet_name TEXT NOT NULL,
    statechain_id TEXT NOT NULL,
    binding_index INTEGER NOT NULL CHECK (binding_index BETWEEN 0 AND 4294967295),
    attempt_kind TEXT NOT NULL CHECK (attempt_kind IN ('Duplicate', 'Canonical')),
    owner_user_pubkey TEXT NOT NULL,
    owner_state_number INTEGER NOT NULL CHECK (
        owner_state_number BETWEEN 1 AND 4294967295
    ),
    source_txid TEXT NOT NULL CHECK (length(source_txid) = 64),
    source_vout INTEGER NOT NULL CHECK (source_vout BETWEEN 0 AND 4294967295),
    source_value_sats INTEGER NOT NULL CHECK (
        source_value_sats BETWEEN 0 AND 2100000000000000
    ),
    source_script_pubkey TEXT NOT NULL,
    destination_address TEXT NOT NULL,
    destination_script_pubkey TEXT NOT NULL,
    fee_rate_sat_per_vbyte REAL NOT NULL CHECK (fee_rate_sat_per_vbyte > 0),
    fee_sats INTEGER NOT NULL CHECK (fee_sats >= 0),
    lock_time INTEGER NOT NULL CHECK (lock_time BETWEEN 0 AND 499999999),
    unsigned_tx_hex TEXT NOT NULL,
    signing_id TEXT NOT NULL CHECK (length(signing_id) = 64),
    signed_statechain_id TEXT NOT NULL,
    sign_first_payload_json TEXT NOT NULL,
    client_secret_nonce TEXT NOT NULL,
    client_public_nonce TEXT NOT NULL,
    blinding_factor TEXT NOT NULL,
    server_public_nonce TEXT NULL,
    message_hex TEXT NULL,
    output_pubkey TEXT NULL,
    client_partial_sig TEXT NULL,
    encoded_session TEXT NULL,
    sign_second_payload_json TEXT NULL,
    server_partial_sig TEXT NULL,
    aggregate_signature TEXT NULL,
    signed_tx_hex TEXT NULL,
    txid TEXT NULL CHECK (txid IS NULL OR length(txid) = 64),
    phase TEXT NOT NULL CHECK (phase IN (
        'Prepared', 'FirstArmed', 'NonceStored', 'SecondArmed', 'Signed'
    )),
    broadcast_status TEXT NOT NULL CHECK (broadcast_status IN (
        'NotBroadcast', 'Accepted', 'Confirmed', 'NeedsRebroadcast',
        'Conflicting', 'Conflicted'
    )),
    completion_status TEXT NOT NULL CHECK (completion_status IN (
        'NotApplicable', 'Open', 'CloseArmed', 'Closed'
    )),
    closing_tip_height INTEGER NULL CHECK (
        closing_tip_height IS NULL OR closing_tip_height BETWEEN 0 AND 4294967295
    ),
    closing_tip_hash TEXT NULL CHECK (closing_tip_hash IS NULL OR length(closing_tip_hash) = 64),
    closing_bindings_json TEXT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (wallet_name, statechain_id, binding_index),
    UNIQUE (wallet_name, statechain_id, signing_id),
    CHECK (
        (binding_index = 0 AND attempt_kind = 'Canonical'
         AND completion_status IN ('Open', 'CloseArmed', 'Closed')
         AND closing_tip_height IS NOT NULL AND closing_tip_hash IS NOT NULL
         AND closing_bindings_json IS NOT NULL) OR
        (binding_index > 0 AND attempt_kind = 'Duplicate'
         AND completion_status = 'NotApplicable'
         AND closing_tip_height IS NULL AND closing_tip_hash IS NULL
         AND closing_bindings_json IS NULL)
    ),
    CHECK (
        phase IN ('Prepared', 'FirstArmed') OR
        (server_public_nonce IS NOT NULL AND message_hex IS NOT NULL
         AND output_pubkey IS NOT NULL AND client_partial_sig IS NOT NULL
         AND encoded_session IS NOT NULL AND sign_second_payload_json IS NOT NULL)
    ),
    CHECK (
        phase <> 'Signed' OR
        (server_partial_sig IS NOT NULL AND aggregate_signature IS NOT NULL
         AND signed_tx_hex IS NOT NULL AND txid IS NOT NULL)
    ),
    CHECK (phase = 'Signed' OR broadcast_status = 'NotBroadcast'),
    CHECK (
        completion_status <> 'CloseArmed' OR
        (phase = 'Signed' AND broadcast_status <> 'NotBroadcast')
    ),
    CHECK (
        completion_status <> 'Closed' OR
        (phase = 'Signed' AND broadcast_status <> 'NotBroadcast')
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS bip448_one_active_withdrawal_signing
ON bip448_withdrawal_attempts (wallet_name, statechain_id)
WHERE phase <> 'Signed';

CREATE TABLE IF NOT EXISTS bip448_transfer_intents (
    wallet_name TEXT NOT NULL,
    statechain_id TEXT NOT NULL,
    intent_id TEXT NOT NULL CHECK (length(intent_id) = 64),
    predecessor_intent_id TEXT NULL CHECK (
        predecessor_intent_id IS NULL OR
        (length(predecessor_intent_id) = 64 AND predecessor_intent_id <> intent_id)
    ),
    activity_status TEXT NOT NULL CHECK (activity_status IN ('Active', 'Superseded')),
    intent_kind TEXT NOT NULL CHECK (intent_kind IN ('UserTransfer', 'Cancellation')),
    acknowledge_cooperative_duplicates INTEGER NOT NULL CHECK (
        acknowledge_cooperative_duplicates IN (0, 1)
    ),
    recipient_address TEXT NOT NULL,
    receiver_user_pubkey TEXT NOT NULL,
    recipient_auth_pubkey TEXT NOT NULL,
    batch_id TEXT NULL,
    sender_signed_statechain_id TEXT NOT NULL,
    planned_state_number INTEGER NOT NULL CHECK (
        planned_state_number BETWEEN 1 AND 4294967295
    ),
    expected_signature_count INTEGER NOT NULL CHECK (
        expected_signature_count BETWEEN 1 AND 4294967295
    ),
    previous_locktime INTEGER NOT NULL CHECK (
        previous_locktime BETWEEN 500000000 AND 4294967294
    ),
    prior_pending_signing_id TEXT NULL CHECK (
        prior_pending_signing_id IS NULL OR length(prior_pending_signing_id) = 64
    ),
    prior_transfer_recipient_auth_pubkey TEXT NULL,
    prior_transfer_msg_hash TEXT NULL CHECK (
        prior_transfer_msg_hash IS NULL OR length(prior_transfer_msg_hash) = 64
    ),
    reuse_pending INTEGER NOT NULL CHECK (reuse_pending IN (0, 1)),
    reuse_signed_state INTEGER NOT NULL CHECK (reuse_signed_state IN (0, 1)),
    clear_local_attempt INTEGER NOT NULL CHECK (clear_local_attempt IN (0, 1)),
    generated_coin_user_pubkey TEXT NULL,
    generated_coin_auth_pubkey TEXT NULL,
    generated_coin_address TEXT NULL,
    phase TEXT NOT NULL CHECK (phase IN (
        'Prepared', 'SenderArmed', 'X1Stored', 'SenderFinished', 'ReceiverAccepted'
    )),
    server_x1 TEXT NULL CHECK (server_x1 IS NULL OR length(server_x1) = 64),
    current_pending_signing_id TEXT NULL CHECK (
        current_pending_signing_id IS NULL OR length(current_pending_signing_id) = 64
    ),
    state_signing_phase TEXT NOT NULL CHECK (state_signing_phase IN (
        'NotStarted', 'FirstArmed', 'NonceStored', 'SecondArmed', 'Signed'
    )),
    server_partial_sig TEXT NULL CHECK (
        server_partial_sig IS NULL OR length(server_partial_sig) = 64
    ),
    update_signature TEXT NULL CHECK (
        update_signature IS NULL OR length(update_signature) = 128
    ),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (wallet_name, statechain_id, intent_id),
    CHECK (
        (intent_kind = 'UserTransfer'
         AND generated_coin_user_pubkey IS NULL
         AND generated_coin_auth_pubkey IS NULL
         AND generated_coin_address IS NULL) OR
        (intent_kind = 'Cancellation'
         AND generated_coin_user_pubkey IS NOT NULL
         AND generated_coin_auth_pubkey IS NOT NULL
         AND generated_coin_address IS NOT NULL)
    ),
    CHECK (
        (phase IN ('Prepared', 'SenderArmed') AND server_x1 IS NULL) OR
        (phase IN ('X1Stored', 'SenderFinished', 'ReceiverAccepted')
         AND server_x1 IS NOT NULL)
    ),
    CHECK (
        (prior_transfer_recipient_auth_pubkey IS NULL
         AND prior_transfer_msg_hash IS NULL) OR
        (prior_transfer_recipient_auth_pubkey IS NOT NULL
         AND prior_transfer_msg_hash IS NOT NULL)
    ),
    CHECK (reuse_pending = 0 OR prior_pending_signing_id IS NOT NULL),
    CHECK (reuse_signed_state = 0 OR reuse_pending = 1),
    CHECK (
        (reuse_signed_state = 1
         AND planned_state_number = expected_signature_count) OR
        (reuse_signed_state = 0
         AND expected_signature_count < 4294967295
         AND planned_state_number = expected_signature_count + 1)
    ),
    CHECK (reuse_pending = 0 OR clear_local_attempt = 0),
    CHECK (
        clear_local_attempt = 0 OR prior_pending_signing_id IS NOT NULL
        OR prior_transfer_msg_hash IS NOT NULL
    ),
    CHECK (intent_kind = 'UserTransfer' OR batch_id IS NULL),
    CHECK (
        intent_kind = 'Cancellation' OR
        phase IN ('Prepared', 'SenderArmed', 'X1Stored')
    ),
    CHECK (
        (phase IN ('Prepared', 'SenderArmed')
         AND state_signing_phase = 'NotStarted'
         AND current_pending_signing_id IS NULL
         AND server_partial_sig IS NULL AND update_signature IS NULL) OR
        (phase = 'X1Stored' AND (
            (state_signing_phase = 'NotStarted'
             AND current_pending_signing_id IS NULL
             AND server_partial_sig IS NULL AND update_signature IS NULL) OR
            (state_signing_phase IN ('FirstArmed', 'NonceStored', 'SecondArmed')
             AND reuse_signed_state = 0
             AND current_pending_signing_id IS NOT NULL
             AND server_partial_sig IS NULL AND update_signature IS NULL) OR
            (state_signing_phase = 'Signed'
             AND current_pending_signing_id IS NOT NULL
             AND update_signature IS NOT NULL
             AND ((reuse_signed_state = 0 AND server_partial_sig IS NOT NULL) OR
                  (reuse_signed_state = 1 AND server_partial_sig IS NULL)))
         )) OR
        (phase IN ('SenderFinished', 'ReceiverAccepted')
         AND intent_kind = 'Cancellation'
         AND state_signing_phase = 'Signed'
         AND current_pending_signing_id IS NOT NULL
         AND update_signature IS NOT NULL
         AND ((reuse_signed_state = 0 AND server_partial_sig IS NOT NULL) OR
              (reuse_signed_state = 1 AND server_partial_sig IS NULL)))
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS bip448_one_active_transfer_intent
ON bip448_transfer_intents (wallet_name, statechain_id)
WHERE activity_status = 'Active';
```

There are zero client foreign keys. `bip448_funding_bindings` normalizes
canonical index 0 and every stable duplicate index. Consensus-valid values are
represented as `u64` in Rust and constrained to Bitcoin's maximum-money domain
in SQLite.
`bip448_withdrawal_attempts` stores the immutable source, fee, transaction,
signing payloads, phases, broadcast facts, and canonical close snapshot.
`bip448_transfer_intents` is the local durable request/response and successor
journal for transfer sender initialization and state signing; it does not add
a Mercury table. `coverage_start_height` and monotonically increasing
`scan_revision` fence stale scan and wallet writes.

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
