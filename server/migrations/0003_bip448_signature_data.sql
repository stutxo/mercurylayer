-- BIP448 statechain blind-signing state (Phase 5).
--
-- This table is additive and parallel to statechain_signature_data, which
-- keeps serving the legacy Taproot key-path signing flow unchanged. BIP448
-- CSFS signing preserves the same blind-server boundary: the server stores no
-- state number, transaction role, template hash, output, locktime, or other
-- transaction-derived metadata. `signing_id` is an opaque client-generated
-- retry/idempotency identifier.
--
-- The unique constraint on (statechain_id, signing_id) is load-bearing: one
-- blind signing record may exist per opaque signing id. Exact retries are
-- replayed idempotently; conflicting blinded challenges for the same
-- signing_id are rejected without learning what transaction was being signed.
CREATE TABLE public.bip448_signature_data (
	id serial4 NOT NULL,
	statechain_id varchar NOT NULL,
	signing_id varchar NOT NULL,
	server_pubnonce varchar NULL,
	challenge varchar NULL,
	negate_seckey boolean NULL,
	server_partial_sig varchar NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT bip448_signature_data_pkey PRIMARY KEY (id),
	CONSTRAINT bip448_signature_data_signing_id_ukey UNIQUE (statechain_id, signing_id),
	CONSTRAINT bip448_signature_data_signing_id_check CHECK (signing_id ~ '^[0-9a-f]{64}$')
);

-- The lockbox has one sealed nonce slot per statechain_id, shared by legacy
-- and BIP448 signing endpoints. This lease is acquired before either endpoint
-- asks the lockbox for a fresh public nonce and is released after sign/second
-- completes, preventing cross-route nonce overwrites.
CREATE TABLE public.signing_nonce_leases (
	statechain_id varchar NOT NULL,
	protocol varchar NOT NULL,
	signing_id varchar NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT signing_nonce_leases_pkey PRIMARY KEY (statechain_id),
	CONSTRAINT signing_nonce_leases_protocol_check CHECK (protocol IN ('legacy', 'bip448')),
	CONSTRAINT signing_nonce_leases_signing_id_check CHECK (signing_id IS NULL OR signing_id ~ '^[0-9a-f]{64}$'),
	CONSTRAINT signing_nonce_leases_bip448_identity_check CHECK (
		(protocol = 'bip448' AND signing_id IS NOT NULL)
		OR (protocol = 'legacy' AND signing_id IS NULL)
	)
);

-- Preserve any legacy nonce rounds that were already incomplete when this
-- additive migration is applied.
INSERT INTO public.signing_nonce_leases (statechain_id, protocol)
SELECT DISTINCT statechain_id, 'legacy'
FROM public.statechain_signature_data
WHERE statechain_id IS NOT NULL
  AND server_pubnonce IS NOT NULL
  AND challenge IS NULL
ON CONFLICT DO NOTHING;

-- The unchanged lockbox stores one sealed nonce per statechain_id. Prevent a
-- second BIP448 sign/first from reserving another nonce before the first
-- sign/second has produced and stored the partial signature.
CREATE UNIQUE INDEX bip448_signature_data_one_incomplete_per_statechain_idx
ON public.bip448_signature_data (statechain_id)
WHERE server_partial_sig IS NULL;
