CREATE TABLE deposit_initialization (
    token_id varchar PRIMARY KEY,
    auth_xonly_public_key bytea NOT NULL,
    statechain_id varchar NOT NULL UNIQUE,
    enclave_index integer NOT NULL,
    server_public_key bytea NULL,
    status varchar NOT NULL DEFAULT 'pending',
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    CONSTRAINT deposit_initialization_token_id_fkey
        FOREIGN KEY (token_id) REFERENCES tokens(token_id),
    CONSTRAINT deposit_initialization_auth_key_length
        CHECK (octet_length(auth_xonly_public_key) = 32),
    CONSTRAINT deposit_initialization_server_key_length
        CHECK (server_public_key IS NULL OR octet_length(server_public_key) = 33),
    CONSTRAINT deposit_initialization_enclave_index_nonnegative
        CHECK (enclave_index >= 0),
    CONSTRAINT deposit_initialization_status_key_check CHECK (
        (status = 'pending' AND server_public_key IS NULL)
        OR (status = 'completed' AND server_public_key IS NOT NULL)
    )
);
