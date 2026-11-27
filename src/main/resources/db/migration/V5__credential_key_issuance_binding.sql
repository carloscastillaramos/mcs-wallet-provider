-- MTC · Entrega 03.16. PostgreSQL 16, schema wallet_provider administrado por Flyway.
-- Solo huellas cryptograficas publicas; NO almacenar DNI, clave privada, nonce en claro.
-- NO borrar ni cambiar V1-V4. Registro bajo transaccion de atestacion.
CREATE TABLE wp_credential_key_binding (
    id uuid PRIMARY KEY,
    installation_id varchar(36) NOT NULL REFERENCES wp_installation(id) ON DELETE RESTRICT,
    credential_key_thumbprint varchar(43) NOT NULL
        CHECK (credential_key_thumbprint ~ '^[A-Za-z0-9_-]{43}$'),
    issuer_nonce_sha256 bytea NOT NULL CHECK (octet_length(issuer_nonce_sha256)=32),
    issued_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamptz NOT NULL,
    CONSTRAINT wp_credential_key_binding_ttl_ck CHECK (expires_at > issued_at),
    CONSTRAINT wp_credential_key_binding_nonce_key_uq
        UNIQUE (credential_key_thumbprint, issuer_nonce_sha256)
);
CREATE INDEX wp_credential_key_binding_installation_idx
    ON wp_credential_key_binding (installation_id,expires_at DESC);
CREATE INDEX wp_credential_key_binding_expiry_idx
    ON wp_credential_key_binding (expires_at);
-- La comprobacion de titular/sesion es una consulta transaccional en vivo,
-- no un booleano almacenado que sobreviva a la revocacion.
