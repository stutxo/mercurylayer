-- Durable protocol ownership for each statechain signing coin.
--
-- The lockbox keeps one signature counter per statechain_id, shared by legacy
-- and BIP448 signing. A coin therefore must not mix protocols after first use.
-- This table makes that single-protocol rule an atomic database invariant. It
-- stores only the protocol family selected for the statechain, never BIP448
-- role, state number, template hash, output, locktime, or transaction-derived
-- metadata.
CREATE TABLE public.statechain_signing_protocol (
	statechain_id varchar NOT NULL,
	protocol varchar NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CONSTRAINT statechain_signing_protocol_pkey PRIMARY KEY (statechain_id),
	CONSTRAINT statechain_signing_protocol_protocol_check CHECK (protocol IN ('legacy', 'bip448'))
);

-- Preserve protocol ownership for coins that already signed before this
-- invariant was introduced. Legacy is inserted first because it predates the
-- additive BIP448 path; any inconsistent pre-existing mixed coin remains
-- legacy-owned and future BIP448 signing is blocked.
INSERT INTO public.statechain_signing_protocol (statechain_id, protocol)
SELECT DISTINCT statechain_id, 'legacy'
FROM public.statechain_signature_data
WHERE statechain_id IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO public.statechain_signing_protocol (statechain_id, protocol)
SELECT DISTINCT statechain_id, 'bip448'
FROM public.bip448_signature_data
ON CONFLICT DO NOTHING;
