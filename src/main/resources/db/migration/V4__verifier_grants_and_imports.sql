-- MTC-BD-ESP-ENR-001, entrega 01 - padron y autorizacion institucional (schema aditivo).
-- Las entidades externas NO administran el portal ni reciben cuentas MTC.
-- No se crea ni reactiva automaticamente un vinculo revocado.

CREATE TABLE wp_verifier_grant (
    id uuid PRIMARY KEY,
    entity_id uuid NOT NULL REFERENCES wp_entity(id) ON DELETE RESTRICT,
    document_type varchar(8) NOT NULL CHECK (document_type IN ('DNI')),
    dni_hmac bytea NOT NULL CHECK (octet_length(dni_hmac) = 32),
    dni_cipher bytea NOT NULL CHECK (octet_length(dni_cipher) > 0),
    key_version smallint NOT NULL CHECK (key_version > 0),
    holder_id uuid REFERENCES wp_holder(id) ON DELETE RESTRICT,
    profile varchar(32) NOT NULL CHECK (profile = 'VERIFICADOR'),
    status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED')),
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    institutional_code varchar(64),
    unit varchar(120),
    reason varchar(300),
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT wp_grant_identity_profile_uq UNIQUE (entity_id, document_type, dni_hmac, profile),
    CONSTRAINT wp_grant_dates_ck CHECK (valid_until IS NULL OR valid_until > valid_from)
);
CREATE INDEX wp_verifier_grant_entity_state_expiry_idx ON wp_verifier_grant (entity_id, status, valid_until);
CREATE INDEX wp_verifier_grant_dni_hmac_idx ON wp_verifier_grant (dni_hmac);
CREATE INDEX wp_verifier_grant_holder_idx ON wp_verifier_grant (holder_id);

CREATE TABLE wp_verifier_installation (
    grant_id uuid NOT NULL REFERENCES wp_verifier_grant(id) ON DELETE RESTRICT,
    installation_id varchar(36) NOT NULL REFERENCES wp_installation(id) ON DELETE RESTRICT,
    status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
    linked_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at timestamptz,
    reason varchar(300),
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    PRIMARY KEY (grant_id, installation_id),
    CONSTRAINT wp_verifier_installation_revocation_ck CHECK (status <> 'REVOKED' OR revoked_at IS NOT NULL)
);
CREATE INDEX wp_verifier_installation_installation_state_idx ON wp_verifier_installation (installation_id, status);

CREATE TABLE wp_import_batch (
    id uuid PRIMARY KEY,
    entity_id uuid NOT NULL REFERENCES wp_entity(id) ON DELETE RESTRICT,
    actor_issuer varchar(255) NOT NULL,
    actor_sub varchar(255) NOT NULL,
    mode varchar(16) NOT NULL CHECK (mode IN ('ALTA','NOVEDADES')),
    schema_version varchar(8) NOT NULL,
    file_hash bytea NOT NULL CHECK (octet_length(file_hash) = 32),
    idempotency_key varchar(128) NOT NULL,
    defaults_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    official_ref varchar(128),
    status varchar(20) NOT NULL CHECK (status IN ('UPLOADED','VALIDATED','INVALID','PROCESSING','APPLIED','FAILED')),
    summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT wp_import_batch_idempotency_uq UNIQUE (entity_id, idempotency_key)
);
CREATE INDEX wp_import_batch_entity_created_idx ON wp_import_batch (entity_id, created_at DESC);

CREATE TABLE wp_import_row (
    batch_id uuid NOT NULL REFERENCES wp_import_batch(id) ON DELETE RESTRICT,
    row_no integer NOT NULL CHECK (row_no > 0),
    dni_hmac bytea CHECK (dni_hmac IS NULL OR octet_length(dni_hmac) = 32),
    encrypted_payload bytea,
    expected_grant_version bigint CHECK (expected_grant_version IS NULL OR expected_grant_version >= 0),
    action varchar(16) CHECK (action IS NULL OR action IN ('ALTA','ACTUALIZAR','SUSPENDER','REACTIVAR','BAJA')),
    result varchar(24),
    error_code varchar(48),
    PRIMARY KEY (batch_id, row_no)
);

CREATE TABLE wp_admin_audit (
    id uuid PRIMARY KEY,
    actor_issuer varchar(255) NOT NULL,
    actor_sub varchar(255) NOT NULL,
    entity_id uuid REFERENCES wp_entity(id) ON DELETE RESTRICT,
    action varchar(48) NOT NULL,
    resource_id varchar(64),
    reason varchar(300),
    before_safe jsonb NOT NULL DEFAULT '{}'::jsonb,
    after_safe jsonb NOT NULL DEFAULT '{}'::jsonb,
    result varchar(24) NOT NULL,
    correlation_id varchar(64),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX wp_admin_audit_entity_created_idx ON wp_admin_audit (entity_id, created_at DESC);
CREATE INDEX wp_admin_audit_actor_created_idx ON wp_admin_audit (actor_issuer, actor_sub, created_at DESC);
-- El servicio debe escribir solo referencias y atributos sanitizados en before_safe/after_safe.
