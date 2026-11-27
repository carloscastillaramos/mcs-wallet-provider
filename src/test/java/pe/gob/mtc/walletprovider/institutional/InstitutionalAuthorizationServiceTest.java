package pe.gob.mtc.walletprovider.institutional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

/** Prueba de la consulta de autorizaciones, no de criptografía ni PostgreSQL. */
class InstitutionalAuthorizationServiceTest {
    private JdbcTemplate jdbc;
    private InstitutionalAuthorizationService service;
    private final String holderId = UUID.randomUUID().toString();
    private final String installationId = UUID.randomUUID().toString();
    private final String sessionId = UUID.randomUUID().toString();
    private final String grantId = UUID.randomUUID().toString();
    private final String entityId = UUID.randomUUID().toString();

    @BeforeEach
    void setup() {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setDriverClassName("org.h2.Driver");
        ds.setUrl("jdbc:h2:mem:mtc_auth_" + UUID.randomUUID().toString().replace("-", "") + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1");
        ds.setUsername("sa");
        ds.setPassword("");
        jdbc = new JdbcTemplate(ds);
        service = new InstitutionalAuthorizationService(jdbc);
        jdbc.execute("CREATE SCHEMA wallet_provider");
        jdbc.execute("CREATE TABLE wallet_provider.wp_installation (id varchar(36), status varchar(16))");
        jdbc.execute("CREATE TABLE wallet_provider.wp_holder (id varchar(36), document_type varchar(8), dni_hmac varbinary(32))");
        jdbc.execute("CREATE TABLE wallet_provider.wp_identity_session (id varchar(36), installation_id varchar(36), status varchar(20), consumed_at timestamp)");
        jdbc.execute("CREATE TABLE wallet_provider.wp_installation_holder (installation_id varchar(36), holder_id varchar(36), identity_session_id varchar(36), status varchar(16))");
        jdbc.execute("CREATE TABLE wallet_provider.wp_entity (id varchar(36), code varchar(32), status varchar(16))");
        jdbc.execute("CREATE TABLE wallet_provider.wp_verifier_grant (id varchar(36), holder_id varchar(36), document_type varchar(8), dni_hmac varbinary(32), entity_id varchar(36), profile varchar(32), status varchar(16), valid_from timestamp, valid_until timestamp)");
        jdbc.execute("CREATE TABLE wallet_provider.wp_verifier_installation (grant_id varchar(36), installation_id varchar(36), status varchar(16))");
        // Values exclusively fictional; DNI is never stored in this test or in application logs.
        byte[] hmac = new byte[32];
        java.util.Arrays.fill(hmac, (byte) 0x42);
        jdbc.update("INSERT INTO wallet_provider.wp_installation VALUES (?, 'ACTIVE')", installationId);
        jdbc.update("INSERT INTO wallet_provider.wp_holder VALUES (?, 'DNI', ?)", holderId, hmac);
        jdbc.update("INSERT INTO wallet_provider.wp_identity_session VALUES (?, ?, 'COMPLETED', CURRENT_TIMESTAMP)", sessionId, installationId);
        jdbc.update("INSERT INTO wallet_provider.wp_installation_holder VALUES (?, ?, ?, 'ACTIVE')", installationId, holderId, sessionId);
        jdbc.update("INSERT INTO wallet_provider.wp_entity VALUES (?, 'PNP', 'ACTIVE')", entityId);
        jdbc.update("INSERT INTO wallet_provider.wp_verifier_grant VALUES (?, ?, 'DNI', ?, ?, 'VERIFICADOR', 'ACTIVE', DATEADD('DAY', -1, CURRENT_TIMESTAMP), DATEADD('DAY', 1, CURRENT_TIMESTAMP))", grantId, holderId, hmac, entityId);
        jdbc.update("INSERT INTO wallet_provider.wp_verifier_installation VALUES (?, ?, 'ACTIVE')", grantId, installationId);
    }

    private void deny() {
        assertEquals(InstitutionalAuthorizationService.Decision.DENY,
            service.checkVerifiedInstallation(installationId, "PNP"));
    }

    @Test void permitsOnlyMatchingActiveAccreditedInstallation() {
        assertEquals(InstitutionalAuthorizationService.Decision.ALLOW,
            service.checkVerifiedInstallation(installationId, "PNP"));
    }
    @Test void rejectsUnknownEntityWithoutCrossEntityDisclosure() {
        assertEquals(InstitutionalAuthorizationService.Decision.DENY,
            service.checkVerifiedInstallation(installationId, "SUNARP"));
    }
    @Test void rejectsRevokedInstallation() {
        jdbc.update("UPDATE wallet_provider.wp_installation SET status='REVOKED'"); deny();
    }
    @Test void rejectsIdentityWithoutCompletedSession() {
        jdbc.update("UPDATE wallet_provider.wp_identity_session SET status='PENDING', consumed_at=NULL"); deny();
    }
    @Test void rejectsSessionForDifferentInstallation() {
        jdbc.update("UPDATE wallet_provider.wp_identity_session SET installation_id=?", UUID.randomUUID().toString());
        deny();
    }
    @Test void rejectsBackendFailureRatherThanGrantingAccess() {
        jdbc.execute("DROP TABLE wallet_provider.wp_verifier_installation");
        assertThrows(IllegalStateException.class,
            () -> service.checkVerifiedInstallation(installationId, "PNP"));
    }
    @Test void rejectsBlockedHolderBinding() {
        jdbc.update("UPDATE wallet_provider.wp_installation_holder SET status='BLOCKED'"); deny();
    }
    @Test void rejectsSuspendedEntity() {
        jdbc.update("UPDATE wallet_provider.wp_entity SET status='SUSPENDED'"); deny();
    }
    @Test void rejectsSuspendedGrant() {
        jdbc.update("UPDATE wallet_provider.wp_verifier_grant SET status='SUSPENDED'"); deny();
    }
    @Test void rejectsRevokedLink() {
        jdbc.update("UPDATE wallet_provider.wp_verifier_installation SET status='REVOKED'"); deny();
    }
    @Test void rejectsExpiredGrant() {
        jdbc.update("UPDATE wallet_provider.wp_verifier_grant SET valid_until=DATEADD('DAY', -1, CURRENT_TIMESTAMP)"); deny();
    }
    @Test void rejectsFutureGrant() {
        jdbc.update("UPDATE wallet_provider.wp_verifier_grant SET valid_from=DATEADD('DAY', 1, CURRENT_TIMESTAMP), valid_until=DATEADD('DAY', 2, CURRENT_TIMESTAMP)"); deny();
    }
    @Test void rejectsUnresolvedGrantWithoutHolder() {
        jdbc.update("UPDATE wallet_provider.wp_verifier_grant SET holder_id=NULL"); deny();
    }
    @Test void rejectsMismatchedProtectedIdentity() {
        jdbc.update("UPDATE wallet_provider.wp_verifier_grant SET dni_hmac=?", new byte[32]); deny();
    }
    @Test void rejectsMissingRequestParameters() {
        assertEquals(InstitutionalAuthorizationService.Decision.DENY, service.checkVerifiedInstallation(null, "PNP"));
        assertEquals(InstitutionalAuthorizationService.Decision.DENY, service.checkVerifiedInstallation(installationId, ""));
    }
}
