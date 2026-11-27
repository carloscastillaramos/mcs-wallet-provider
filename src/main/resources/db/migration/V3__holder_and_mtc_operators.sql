-- MTC-BD-ESP-ENR-001, entrega 01 - modelo aditivo de identidad y operadores MTC.
-- PostgreSQL 16+, ejecutado por Flyway con default-schema=wallet_provider.
-- NO asigna DNI a instalaciones existentes y NO habilita por si solo la acreditacion biometrica.
-- DNI: almacenar exclusivamente HMAC-SHA-256 con clave separada y ciphertext generado fuera de SQL.
-- Cambios a V1/V2: NINGUNO.

CREATE TABLE wp_holder (
    id uuid PRIMARY KEY,
    document_type varchar(8) NOT NULL CHECK (document_type IN ('DNI')),
    dni_hmac bytea NOT NULL CHECK (octet_length(dni_hmac) = 32),
    dni_cipher bytea NOT NULL CHECK (octet_length(dni_cipher) > 0),
    key_version smallint NOT NULL CHECK (key_version > 0),
    issuer varchar(255) NOT NULL,
    subject varchar(255),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT wp_holder_document_hmac_uq UNIQUE (document_type, dni_hmac)
);

CREATE TABLE wp_identity_session (
    id uuid PRIMARY KEY,
    installation_id varchar(36) NOT NULL REFERENCES wp_installation(id) ON DELETE RESTRICT,
    nonce_hash bytea NOT NULL CHECK (octet_length(nonce_hash) = 32),
    purpose varchar(32) NOT NULL CHECK (purpose = 'HOLDER_ENROLLMENT'),
    external_ref varchar(128) UNIQUE,
    status varchar(20) NOT NULL CHECK (status IN ('PENDING','COMPLETED','FAILED','EXPIRED','CANCELLED')),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    evidence_digest bytea CHECK (evidence_digest IS NULL OR octet_length(evidence_digest) = 32),
    requested_dni_hmac bytea CHECK (requested_dni_hmac IS NULL OR octet_length(requested_dni_hmac) = 32),
    CONSTRAINT wp_identity_session_expiry_ck CHECK (expires_at > created_at),
    CONSTRAINT wp_identity_session_completion_ck CHECK (status <> 'COMPLETED' OR (consumed_at IS NOT NULL AND evidence_digest IS NOT NULL)),
    CONSTRAINT wp_identity_session_installation_uq UNIQUE (id, installation_id)
);
CREATE INDEX wp_identity_session_installation_state_idx ON wp_identity_session (installation_id, status);
CREATE INDEX wp_identity_session_expiry_idx ON wp_identity_session (expires_at);

CREATE TABLE wp_installation_holder (
    installation_id varchar(36) PRIMARY KEY REFERENCES wp_installation(id) ON DELETE RESTRICT,
    holder_id uuid NOT NULL REFERENCES wp_holder(id) ON DELETE RESTRICT,
    identity_session_id uuid NOT NULL UNIQUE,
    verified_at timestamptz NOT NULL,
    status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','BLOCKED')),
    CONSTRAINT wp_installation_holder_same_session_fk FOREIGN KEY (identity_session_id, installation_id)
        REFERENCES wp_identity_session(id, installation_id) ON DELETE RESTRICT
);
CREATE INDEX wp_installation_holder_holder_idx ON wp_installation_holder (holder_id);

CREATE TABLE wp_entity (
    id uuid PRIMARY KEY,
    code varchar(32) NOT NULL UNIQUE,
    name varchar(160) NOT NULL,
    status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED')),
    max_devices smallint NOT NULL DEFAULT 1 CHECK (max_devices > 0),
    default_validity_days int CHECK (default_validity_days IS NULL OR default_validity_days > 0),
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- DECISION MTC 24/11/2026: portal administrado exclusivamente por personal MTC.
-- No se crea wp_operator_entity de la propuesta anterior: los operadores NO
-- pertenecen a entidades externas; estas solo figuran en el catalogo wp_entity.
CREATE TABLE wp_mtc_operator (
    id uuid PRIMARY KEY,
    issuer varchar(255) NOT NULL,
    subject varchar(255) NOT NULL,
    role varchar(32) NOT NULL CHECK (role IN ('SUPER_ADMIN','MESA_DE_PARTES')),
    status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED')),
    valid_until timestamptz,
    version bigint NOT NULL DEFAULT 0 CHECK (version >= 0),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT wp_mtc_operator_identity_uq UNIQUE (issuer, subject)
);
CREATE INDEX wp_mtc_operator_identity_status_idx ON wp_mtc_operator (issuer, subject, status);
-- El primer SUPER_ADMIN se provisiona por proceso auditado de bootstrap, nunca por registro publico.
