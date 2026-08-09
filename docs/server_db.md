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

## Client SQLite: nine tables

`clients/libs/rust/migrations/0001_bip448_client_schema.sql` creates exactly
these nine tables:

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
```

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
