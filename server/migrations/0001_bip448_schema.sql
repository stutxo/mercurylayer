CREATE TABLE public.statechain_data (
    id serial4 NOT NULL,
    token_id varchar NULL UNIQUE,
    auth_xonly_public_key bytea NULL,
    server_public_key bytea NULL UNIQUE,
    statechain_id varchar NULL UNIQUE,
    enclave_index integer NOT NULL,
    CONSTRAINT statechain_data_pkey PRIMARY KEY (id),
    CONSTRAINT statechain_data_server_public_key_ukey UNIQUE (server_public_key)
);

CREATE TABLE public.lightning_latch (
    id serial4 NOT NULL,
    statechain_id varchar NOT NULL,
    sender_auth_xonly_public_key bytea NULL,
    batch_id varchar NOT NULL,
    pre_image varchar NULL,
    locked boolean NOT NULL DEFAULT true,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT lightning_latch_pkey PRIMARY KEY (id),
    CONSTRAINT unique_statechain_sender_batch UNIQUE (statechain_id, batch_id)
);

CREATE TABLE public.statechain_transfer (
    id serial4 NOT NULL,
    statechain_id varchar NULL UNIQUE,
    new_user_auth_public_key bytea NULL,
    x1 bytea NULL,
    encrypted_transfer_msg bytea NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    key_updated boolean DEFAULT false,
    batch_id varchar NULL,
    batch_time TIMESTAMPTZ NULL,
    locked boolean NOT NULL DEFAULT false,
    locked2 boolean NOT NULL DEFAULT false,
    CONSTRAINT statechain_transfer_pkey PRIMARY KEY (id)
);

CREATE TABLE public.tokens (
    id serial4 PRIMARY KEY,
    token_id varchar NULL UNIQUE,
    onchain_address varchar NULL,
    confirmed boolean DEFAULT false,
    spent boolean DEFAULT false
);

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

CREATE TABLE public.signing_nonce_leases (
    statechain_id varchar NOT NULL,
    signing_id varchar NOT NULL,
    lease_token varchar NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT signing_nonce_leases_pkey PRIMARY KEY (statechain_id),
    CONSTRAINT signing_nonce_leases_signing_id_check CHECK (signing_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT signing_nonce_leases_lease_token_check CHECK (lease_token ~ '^[0-9a-f]{32}$')
);

CREATE UNIQUE INDEX bip448_signature_data_one_incomplete_per_statechain_idx
ON public.bip448_signature_data (statechain_id)
WHERE server_partial_sig IS NULL;
