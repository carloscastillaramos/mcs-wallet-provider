package pe.gob.mtc.walletprovider.integration;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Controles de destino ejecutables sin PostgreSQL ni secretos. */
class LabPostgresGuardPolicyTest {
    private static final String URL = "jdbc:postgresql://127.0.0.1:55432/wallet_provider_it";
    private static final String USER = "wallet_provider_it";
    private static final String ACK = "I_CONFIRM_DISPOSABLE_DB_ONLY";
    private static final String MARKER = "a0bd9cbf-97ae-41d3-bad0-aeb82bb23090";

    private void check(String ack, String url, String user, String marker,
                       String kubernetes, String profiles, String environment) {
        LabPostgresGuard.validateTarget(ack, url, user, marker,
                kubernetes, profiles, environment);
    }

    @Test void denyWithoutLaboratoryAcknowledgement() {
        assertThrows(IllegalStateException.class,
                () -> check(null, URL, USER, MARKER, null, null, null));
    }

    @Test void denyNonLocalOrDisguisedJdbcTarget() {
        assertThrows(IllegalStateException.class,
                () -> check(ACK, "jdbc:postgresql://db-prd:5432/wallet_provider_it", USER, MARKER, null, null, null));
        assertThrows(IllegalStateException.class,
                () -> check(ACK, URL + "?options=-csearch_path%3Dpublic", USER, MARKER, null, null, null));
        assertThrows(IllegalStateException.class,
                () -> check(ACK, "jdbc:postgresql://localhost:55432/postgres", USER, MARKER, null, null, null));
    }

    @Test void denyApplicationIdentityOrWeakMarker() {
        assertThrows(IllegalStateException.class,
                () -> check(ACK, URL, "postgres", MARKER, null, null, null));
        assertThrows(IllegalStateException.class,
                () -> check(ACK, URL, USER, "test", null, null, null));
    }

    @Test void denyKubernetesAndInstitutionalEnvironments() {
        assertThrows(IllegalStateException.class,
                () -> check(ACK, URL, USER, MARKER, "10.20.0.1", null, null));
        assertThrows(IllegalStateException.class,
                () -> check(ACK, URL, USER, MARKER, null, "prd", null));
        assertThrows(IllegalStateException.class,
                () -> check(ACK, URL, USER, MARKER, null, null, "qa"));
    }

    @Test void allowOnlyStructuralPreflightForLocalDisposableTarget() {
        assertDoesNotThrow(() -> check(ACK, URL, USER, MARKER, null, "test", "local"));
    }
}
