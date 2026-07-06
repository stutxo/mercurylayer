-- Restore the BIP448 incomplete-round partial index as a DB-level backstop.
-- The endpoint lease table fences active requests, but this index cheaply
-- prevents a second durable incomplete BIP448 round for the same statechain.

-- Deployments that ran migration 0006 without this backstop may have already
-- accumulated multiple incomplete rows for one statechain. Deduplicate before
-- recreating the unique index. Keep the row referenced by the active BIP448
-- lease when present; otherwise keep a row that has a lockbox nonce; otherwise
-- keep the oldest reservation.
WITH ranked_incomplete AS (
	SELECT
		signature.id,
		ROW_NUMBER() OVER (
			PARTITION BY signature.statechain_id
			ORDER BY
				CASE
					WHEN lease.statechain_id IS NOT NULL THEN 0
					WHEN signature.server_pubnonce IS NOT NULL THEN 1
					ELSE 2
				END,
				signature.created_at ASC,
				signature.id ASC
		) AS row_rank
	FROM public.bip448_signature_data AS signature
	LEFT JOIN public.signing_nonce_leases AS lease
		ON lease.statechain_id = signature.statechain_id
		AND lease.protocol = 'bip448'
		AND lease.signing_id = signature.signing_id
	WHERE signature.server_partial_sig IS NULL
)
DELETE FROM public.bip448_signature_data AS signature
USING ranked_incomplete AS ranked
WHERE signature.id = ranked.id
  AND ranked.row_rank > 1;

CREATE UNIQUE INDEX IF NOT EXISTS bip448_signature_data_one_incomplete_per_statechain_idx
ON public.bip448_signature_data (statechain_id)
WHERE server_partial_sig IS NULL;
