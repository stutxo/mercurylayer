-- Fence in-flight lockbox nonce creation against stale lease reclamation.
--
-- `get_public_nonce` mutates the lockbox's single sealed nonce slot for a
-- statechain_id. Handlers therefore need an unambiguous lease identity so a
-- delayed handler cannot delete or refresh a lease that was already reclaimed
-- and replaced by a newer request.
ALTER TABLE public.signing_nonce_leases
ADD COLUMN lease_token varchar NULL;

UPDATE public.signing_nonce_leases
SET lease_token = md5(random()::text || clock_timestamp()::text || statechain_id)
WHERE lease_token IS NULL;

ALTER TABLE public.signing_nonce_leases
ALTER COLUMN lease_token SET NOT NULL;

ALTER TABLE public.signing_nonce_leases
ADD CONSTRAINT signing_nonce_leases_lease_token_check CHECK (lease_token ~ '^[0-9a-f]{32}$');
