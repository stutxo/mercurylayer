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
