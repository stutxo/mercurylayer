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
