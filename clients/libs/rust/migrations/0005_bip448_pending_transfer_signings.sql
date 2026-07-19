CREATE TABLE IF NOT EXISTS bip448_pending_transfer_signings (
    wallet_name TEXT NOT NULL, statechain_id TEXT NOT NULL,
    funding_txid TEXT NOT NULL, funding_vout INTEGER NOT NULL, funding_value_sats INTEGER NOT NULL,
    update_template_hash TEXT NOT NULL, settlement_template_hash TEXT NOT NULL, state_locktime INTEGER NOT NULL CHECK (state_locktime >= 500000000),
    signing_id TEXT NOT NULL, client_secret_nonce TEXT NOT NULL, client_public_nonce TEXT NOT NULL,
    blinding_factor TEXT NOT NULL, server_public_nonce TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (wallet_name, statechain_id)
);
