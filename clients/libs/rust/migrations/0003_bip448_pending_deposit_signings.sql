CREATE TABLE IF NOT EXISTS bip448_pending_deposit_signings (
    wallet_name TEXT NOT NULL,
    statechain_id TEXT NOT NULL,
    update_template_hash TEXT NOT NULL,
    signing_id TEXT NOT NULL,
    client_secret_nonce TEXT NOT NULL,
    client_public_nonce TEXT NOT NULL,
    blinding_factor TEXT NOT NULL,
    server_public_nonce TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (wallet_name, statechain_id)
);
