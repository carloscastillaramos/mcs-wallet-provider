-- DBA/maintenance job: execute monthly with the correct search_path.
-- psql -v ON_ERROR_STOP=1 -c 'SET search_path TO wallet_provider;' -f sql/maintenance/ensure_partitions.sql
SET search_path TO wallet_provider;
DO $block$
DECLARE
    month_start date := (date_trunc('month', CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date - INTERVAL '1 month')::date;
    partition_start date;
BEGIN
    FOR i IN 0..7 LOOP
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
