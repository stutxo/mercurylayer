-- Repair mixed historical rows from deployments that had BIP448 signing data
-- before the durable protocol-ownership migration. If a BIP448 round already
-- has a lockbox nonce but no partial signature, preserve its completion path by
-- making BIP448 the owner and aligning the single nonce lease with that round.

WITH incomplete_bip448_nonce_round AS (
	SELECT DISTINCT ON (statechain_id)
		statechain_id,
		signing_id
	FROM public.bip448_signature_data
	WHERE server_pubnonce IS NOT NULL
	  AND server_partial_sig IS NULL
	ORDER BY statechain_id, created_at ASC, id ASC
)
INSERT INTO public.statechain_signing_protocol (statechain_id, protocol)
SELECT statechain_id, 'bip448'
FROM incomplete_bip448_nonce_round
ON CONFLICT (statechain_id) DO UPDATE
SET protocol = EXCLUDED.protocol,
	updated_at = NOW()
WHERE public.statechain_signing_protocol.protocol <> EXCLUDED.protocol;

WITH incomplete_bip448_nonce_round AS (
	SELECT DISTINCT ON (statechain_id)
		statechain_id,
		signing_id
	FROM public.bip448_signature_data
	WHERE server_pubnonce IS NOT NULL
	  AND server_partial_sig IS NULL
	ORDER BY statechain_id, created_at ASC, id ASC
)
DELETE FROM public.signing_nonce_leases AS lease
USING incomplete_bip448_nonce_round AS incomplete
WHERE lease.statechain_id = incomplete.statechain_id
  AND (
		lease.protocol <> 'bip448'
		OR lease.signing_id IS DISTINCT FROM incomplete.signing_id
	);

WITH incomplete_bip448_nonce_round AS (
	SELECT DISTINCT ON (statechain_id)
		statechain_id,
		signing_id
	FROM public.bip448_signature_data
	WHERE server_pubnonce IS NOT NULL
	  AND server_partial_sig IS NULL
	ORDER BY statechain_id, created_at ASC, id ASC
)
INSERT INTO public.signing_nonce_leases (statechain_id, protocol, signing_id, lease_token)
SELECT
	statechain_id,
	'bip448',
	signing_id,
	md5(random()::text || clock_timestamp()::text || statechain_id || signing_id)
FROM incomplete_bip448_nonce_round
ON CONFLICT (statechain_id) DO NOTHING;
