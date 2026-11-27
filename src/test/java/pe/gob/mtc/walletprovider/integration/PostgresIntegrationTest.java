package pe.gob.mtc.walletprovider.integration;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/** Test optativo contra PostgreSQL real. No inicia la aplicacion ni emplea H2. */
@EnabledIfEnvironmentVariable(named = "WALLET_PG_IT", matches = "true")
class PostgresIntegrationTest {
    @Test
    void flywayRealPostgresqlAndAuditPartitions() throws Exception {
        // Abortamos ANTES de Flyway, migraciones o INSERT/DELETE.
        LabPostgresGuard.Target target = LabPostgresGuard.verify();
        String url = target.url();
        String user = target.user();
        String password = target.password();

        Flyway flyway = Flyway.configure()
                .dataSource(url, user, password)
                .defaultSchema("wallet_provider")
                .schemas("wallet_provider")
                .createSchemas(false)
                .table("flyway_schema_history")
                .locations("classpath:db/migration")
                .load();
        flyway.migrate();
        flyway.validate();

        try (Connection connection = DriverManager.getConnection(url, user, password)) {
            assertTrue(scalarLong(connection, "SELECT count(*) FROM wallet_provider.flyway_schema_history "
                    + "WHERE version='1' AND success") >= 1);
            assertEquals(1, scalarLong(connection, "SELECT count(*) FROM pg_partitioned_table "
                    + "WHERE partrelid='wallet_provider.wp_audit'::regclass"));
            assertTrue(scalarLong(connection, "SELECT count(*) FROM pg_inherits "
                    + "WHERE inhparent='wallet_provider.wp_audit'::regclass") >= 2);

            String auditId = UUID.randomUUID().toString();
            try (PreparedStatement insert = connection.prepareStatement(
                    "INSERT INTO wallet_provider.wp_audit "
                            + "(id,installation_id,action,result,correlation_id,created_at) "
                            + "VALUES (?,NULL,'ENROLL_TEST','SUCCESS',NULL,?)")) {
                insert.setString(1, auditId);
                insert.setObject(2, OffsetDateTime.now(ZoneOffset.UTC));
                assertEquals(1, insert.executeUpdate());
            }
            try (PreparedStatement query = connection.prepareStatement(
                    "SELECT tableoid::regclass::text FROM wallet_provider.wp_audit WHERE id=?")) {
                query.setString(1, auditId);
                try (ResultSet rs = query.executeQuery()) {
                    assertTrue(rs.next());
                    assertTrue(rs.getString(1).contains("wp_audit_"));
                }
            }
            try (PreparedStatement delete = connection.prepareStatement(
                    "DELETE FROM wallet_provider.wp_audit WHERE id=?")) {
                delete.setString(1, auditId);
                assertEquals(1, delete.executeUpdate());
            }
        }
    }

    private static long scalarLong(Connection connection, String sql) throws Exception {
        try (PreparedStatement ps = connection.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            assertTrue(rs.next());
            return rs.getLong(1);
        }
    }
}
