ALTER TABLE bip448_pending_deposit_signings
ADD COLUMN state_locktime INTEGER
CHECK (
    state_locktime IS NULL
    OR state_locktime BETWEEN 500000000 AND 1000000000
);

ALTER TABLE bip448_pending_deposit_signings
ADD COLUMN funding_txid TEXT;

ALTER TABLE bip448_pending_deposit_signings
ADD COLUMN funding_vout INTEGER;

ALTER TABLE bip448_pending_deposit_signings
ADD COLUMN funding_value_sats INTEGER;

ALTER TABLE bip448_pending_deposit_signings
ADD COLUMN settlement_template_hash TEXT;
