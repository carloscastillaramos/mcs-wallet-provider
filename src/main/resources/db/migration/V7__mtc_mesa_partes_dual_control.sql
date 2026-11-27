-- MTC Portal: Mesa de Partes con registro y aprobacion independientes (acumulables).
-- Migration additive. No modifica datos efectivos de verificadores o instalaciones.
CREATE TABLE wp_mtc_operator_role (
    operator_id uuid NOT NULL REFERENCES wp_mtc_operator(id) ON DELETE RESTRICT,
    role varchar(40) NOT NULL CHECK (role IN ('SUPER_ADMIN','MESA_PARTES_REGISTRADOR','MESA_PARTES_APROBADOR')),
    assigned_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (operator_id, role)
);
-- Backfill conservador: operadores antiguos de Mesa de Partes NO ganan capacidad de aprobar.
INSERT INTO wp_mtc_operator_role (operator_id, role)
SELECT id, CASE role WHEN 'SUPER_ADMIN' THEN 'SUPER_ADMIN' ELSE 'MESA_PARTES_REGISTRADOR' END
FROM wp_mtc_operator WHERE role IN ('SUPER_ADMIN', 'MESA_DE_PARTES');

CREATE TABLE wp_mtc_work_request (
    id uuid PRIMARY KEY,
    entity_id uuid REFERENCES wp_entity(id) ON DELETE RESTRICT,
    action varchar(40) NOT NULL CHECK (action IN (
        'GRANT_CREATE', 'GRANT_REVOKE', 'INSTALLATION_LINK', 'INSTALLATION_UNLINK', 'INSTALLATION_REVOKE')),
    resource_id varchar(36),
    payload_cipher bytea NOT NULL CHECK (octet_length(payload_cipher) > 28),
    status varchar(16) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING','APPROVED','REJECTED')),
    requested_by uuid NOT NULL REFERENCES wp_mtc_operator(id) ON DELETE RESTRICT,
    request_key varchar(100) NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    decided_by uuid REFERENCES wp_mtc_operator(id) ON DELETE RESTRICT,
    decided_at timestamptz,
    decision_reason varchar(300),
    applied_resource_id varchar(36),
    CONSTRAINT wp_mtc_request_key_uq UNIQUE(requested_by, request_key),
    CONSTRAINT wp_mtc_request_decision_ck CHECK (
        (status = 'PENDING' AND decided_by IS NULL AND decided_at IS NULL) OR
        (status <> 'PENDING' AND decided_by IS NOT NULL AND decided_at IS NOT NULL)),
    CONSTRAINT wp_mtc_request_entity_ck CHECK (
        (action = 'INSTALLATION_REVOKE' AND entity_id IS NULL) OR
        (action <> 'INSTALLATION_REVOKE' AND entity_id IS NOT NULL))
);
CREATE INDEX wp_mtc_request_pending_idx ON wp_mtc_work_request (status, requested_at DESC);
CREATE INDEX wp_mtc_request_entity_idx ON wp_mtc_work_request (entity_id, requested_at DESC);

-- Los lotes Excel existentes ya estaban en staging VALIDATED; anadir rechazo y decision auditada.
ALTER TABLE wp_import_batch DROP CONSTRAINT IF EXISTS wp_import_batch_status_check;
ALTER TABLE wp_import_batch ADD CONSTRAINT wp_import_batch_status_check CHECK (
    status IN ('UPLOADED','VALIDATED','INVALID','PROCESSING','APPLIED','FAILED','REJECTED'));
ALTER TABLE wp_import_batch ADD COLUMN decided_by uuid REFERENCES wp_mtc_operator(id) ON DELETE RESTRICT;
ALTER TABLE wp_import_batch ADD COLUMN decided_at timestamptz;
ALTER TABLE wp_import_batch ADD COLUMN decision_reason varchar(300);
