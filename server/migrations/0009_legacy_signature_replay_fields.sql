-- Legacy Mercury-side nonce replay state for prototype nonce safety.
--
-- Legacy clients already send server_pub_nonce on sign/second. Mercury uses it
-- as the opaque nonce identity for fencing conflicting blinded challenges and
-- for replaying exact retries after a successful lockbox response was stored.
ALTER TABLE public.statechain_signature_data
ADD COLUMN negate_seckey integer NULL,
ADD COLUMN server_partial_sig varchar NULL,
ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE public.statechain_signature_data
ADD CONSTRAINT statechain_signature_data_negate_seckey_check
CHECK (negate_seckey IS NULL OR (negate_seckey >= 0 AND negate_seckey <= 255));
