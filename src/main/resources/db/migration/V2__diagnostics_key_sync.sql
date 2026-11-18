-- Dedicated diagnostics signing keys, bound to a provider installation.
CREATE TABLE wp_diagnostics_key (
    installation_id varchar(36) NOT NULL REFERENCES wp_installation(id),
    key_id varchar(64) NOT NULL,
    public_key_spki_b64 varchar(2048) NOT NULL,
    status varchar(16) NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at timestamptz,
    PRIMARY KEY (installation_id,key_id)
);
CREATE INDEX wp_diagnostics_key_status_idx ON wp_diagnostics_key (installation_id,status);

-- Changes are committed atomically with key binding/revocation; HTTP only after commit.
CREATE TABLE wp_diagnostics_outbox (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    installation_id varchar(36) NOT NULL,
    key_id varchar(64) NOT NULL,
    platform varchar(10) NOT NULL,
    public_key_spki_b64 varchar(2048),
    action varchar(12) NOT NULL CHECK (action IN ('REGISTER','REVOKE')),
    state varchar(12) NOT NULL DEFAULT 'PENDING'
        CHECK (state IN ('PENDING','IN_FLIGHT','DONE')),
    attempts integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lease_id uuid,
    leased_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at timestamptz
);
CREATE INDEX wp_diagnostics_outbox_pending_idx
    ON wp_diagnostics_outbox (available_at,id) WHERE state <> 'DONE';
