CREATE TABLE IF NOT EXISTS bip448_state_history (
    wallet_name TEXT NOT NULL,
    statechain_id TEXT NOT NULL,
    state_number INTEGER NOT NULL,
    entry_json TEXT NOT NULL,
    PRIMARY KEY (wallet_name, statechain_id, state_number)
);
