-- PostgreSQL 16+; Flyway runs with current schema wallet_provider.
-- Use a dedicated migration role in production; runtime should have DML only.
CREATE TABLE wp_challenge (
    id          varchar(36) PRIMARY KEY,
    platform    varchar(10) NOT NULL CHECK (platform IN ('ANDROID', 'IOS')),
    nonce       varchar(128) NOT NULL,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at  timestamptz NOT NULL
);
CREATE INDEX wp_challenge_expires_idx ON wp_challenge (expires_at);

CREATE TABLE wp_installation (
    id              varchar(36) PRIMARY KEY,
    platform        varchar(10) NOT NULL CHECK (platform IN ('ANDROID', 'IOS')),
    key_id          varchar(255) NOT NULL,
    public_key      text NOT NULL,
    status          varchar(16) NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    assurance       varchar(48) NOT NULL,
    app_identifier  varchar(255) NOT NULL,
    counter_value   bigint DEFAULT 0 NOT NULL,
    created_at      timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    CONSTRAINT wp_installation_key_uq UNIQUE (platform, key_id)
);
CREATE INDEX wp_installation_status_idx ON wp_installation (status);
CREATE INDEX wp_installation_created_idx ON wp_installation (created_at DESC, id);

-- PostgreSQL requires partition key created_at in every partitioned UNIQUE/PK.
CREATE TABLE wp_audit (
    id              varchar(36) NOT NULL,
    installation_id varchar(36),
    action          varchar(40) NOT NULL,
    result          varchar(24) NOT NULL,
    correlation_id  varchar(64),
    created_at      timestamptz NOT NULL,
    CONSTRAINT wp_audit_pk PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);
CREATE INDEX wp_audit_installation_created_idx ON wp_audit (installation_id, created_at DESC);
CREATE INDEX wp_audit_action_created_idx ON wp_audit (action, created_at DESC);

-- Initial rolling horizon: previous month plus 18 future months, UTC boundaries.
-- DBA must execute sql/maintenance/ensure_partitions.sql monthly BEFORE horizon ends.
DO $block$
DECLARE
    month_start date := (date_trunc('month', CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date - INTERVAL '1 month')::date;
    partition_start date;
BEGIN
    FOR i IN 0..19 LOOP
        partition_start := (month_start + make_interval(months => i))::date;
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF wp_audit FOR VALUES FROM (%L) TO (%L)',
            'wp_audit_' || to_char(partition_start, 'YYYY_MM'),
            to_char(partition_start, 'YYYY-MM-DD') || ' 00:00:00+00',
            to_char((partition_start + interval '1 month')::date, 'YYYY-MM-DD') || ' 00:00:00+00'
        );
    END LOOP;
END
$block$;
