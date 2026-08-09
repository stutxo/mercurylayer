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
        CHECK (state_locktime IS NULL OR state_locktime BETWEEN 500000000 AND 1000000000),
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
