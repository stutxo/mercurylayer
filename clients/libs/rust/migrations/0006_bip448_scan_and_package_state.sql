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
    reserved_by TEXT,
    reserved_at INTEGER,
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
    status TEXT NOT NULL CHECK (status IN ('Pending', 'Submitted', 'Confirmed', 'Abandoned')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (wallet_name, statechain_id, role)
);
