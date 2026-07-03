-- The signing_nonce_leases primary key is the load-bearing single in-flight
-- round invariant for both legacy and BIP448 signing. Durable protocol
-- ownership lives in statechain_signing_protocol. The older partial index was
-- a conservative DB backstop and is redundant with those invariants.
DROP INDEX IF EXISTS public.bip448_signature_data_one_incomplete_per_statechain_idx;
