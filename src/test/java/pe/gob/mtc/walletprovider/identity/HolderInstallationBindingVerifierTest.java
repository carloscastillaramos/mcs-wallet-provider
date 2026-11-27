package pe.gob.mtc.walletprovider.identity;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import pe.gob.mtc.walletprovider.security.ProofVerifier;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.sql.ResultSet;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class HolderInstallationBindingVerifierTest {
    private static final Instant NOW = Instant.parse("2026-11-24T20:00:00Z");
    private static final UUID SESSION = UUID.fromString("c3de0eab-2409-494a-b4ad-6b0f749df580");
    private static final String INSTALLATION = "58d30b2d-e2ce-4dcc-b91a-720c270365c7";
    private static final String NONCE = "A".repeat(43);

    private static KeyPair key() throws Exception {
        var gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return gen.generateKeyPair();
    }

    private static String pem(KeyPair pair) {
        return "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder(64, new byte[]{'\n'})
                .encodeToString(pair.getPublic().getEncoded()) + "\n-----END PUBLIC KEY-----";
    }

    private static String thumbprint(KeyPair pair) throws Exception {
        return new ECKey.Builder(Curve.P_256, (ECPublicKey) pair.getPublic())
                .build().computeThumbprint().toString();
    }

    private static byte[] hash(String s) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.US_ASCII));
    }

    private HolderInstallationBindingVerifier verifier(JdbcTemplate jdbc) {
        return new HolderInstallationBindingVerifier(jdbc, new ProofVerifier(), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void startAllowsOnlyExactKeyOfActiveUnaccreditedInstallation() throws Exception {
        KeyPair own = key();
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        stubStart(jdbc, "ACTIVE", pem(own), false);
        assertDoesNotThrow(() -> verifier(jdbc).verifyActiveInstallationForStart(INSTALLATION, thumbprint(own)));
    }
    @Test
    void startRejectsOtherInstallationKey() throws Exception {
        KeyPair own = key();
        KeyPair wrong = key();
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        stubStart(jdbc, "ACTIVE", pem(own), false);
        assertThrows(SecurityException.class, () ->
            verifier(jdbc).verifyActiveInstallationForStart(INSTALLATION, thumbprint(wrong)));
    }
    @Test
    void startRejectsRevokedOrLinkedInstallations() throws Exception {
        KeyPair own = key();
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        stubStart(jdbc, "REVOKED", pem(own), false);
        assertThrows(SecurityException.class, () ->
            verifier(jdbc).verifyActiveInstallationForStart(INSTALLATION, thumbprint(own)));
        stubStart(jdbc, "ACTIVE", pem(own), true);
        assertThrows(SecurityException.class, () ->
            verifier(jdbc).verifyActiveInstallationForStart(INSTALLATION, thumbprint(own)));
    }
    @Test
    void startRejectsMissingOrMalformedInstallation() throws Exception {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        assertThrows(SecurityException.class, () ->
            verifier(jdbc).verifyActiveInstallationForStart("bad", "A".repeat(43)));
        verifyNoInteractions(jdbc);
        when(jdbc.query(anyString(), any(RowMapper.class), eq(INSTALLATION))).thenReturn(List.of());
        assertThrows(SecurityException.class, () ->
            verifier(jdbc).verifyActiveInstallationForStart(INSTALLATION, "A".repeat(43)));
    }

    @Test
    void rejectsMalformedInputBeforeDatabaseAccess() {
        JdbcTemplate db = mock(JdbcTemplate.class);
        var service = verifier(db);
        assertThrows(SecurityException.class, () -> service.verifyPendingSession(null, INSTALLATION, NONCE, "B".repeat(43)));
        assertThrows(SecurityException.class, () -> service.verifyPendingSession(SESSION, "bad", NONCE, "B".repeat(43)));
        assertThrows(SecurityException.class, () -> service.verifyPendingSession(SESSION, INSTALLATION, "bad", "B".repeat(43)));
        assertThrows(SecurityException.class, () -> service.verifyPendingSession(SESSION, INSTALLATION, NONCE, "bad"));
        verifyNoInteractions(db);
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void validPendingSessionAcceptsExactInstalledKey() throws Exception {
        KeyPair pair = key();
        JdbcTemplate db = mock(JdbcTemplate.class);
        stubRow(db, "ACTIVE", pem(pair), "PENDING", "HOLDER_ENROLLMENT", NOW.plusSeconds(300), hash(NONCE), false);
        var result = verifier(db).verifyPendingSession(SESSION, INSTALLATION, NONCE, thumbprint(pair));
        assertEquals(SESSION, result.identitySessionId());
        assertEquals(INSTALLATION, result.installationId());
        assertEquals(thumbprint(pair), result.publicKeyThumbprint());
    }

    @Test
    void rejectsOtherInstallationKey() throws Exception {
        KeyPair original = key();
        KeyPair attacker = key();
        JdbcTemplate db = mock(JdbcTemplate.class);
        stubRow(db, "ACTIVE", pem(original), "PENDING", "HOLDER_ENROLLMENT", NOW.plusSeconds(300), hash(NONCE), false);
        assertThrows(SecurityException.class, () -> verifier(db).verifyPendingSession(SESSION, INSTALLATION, NONCE, thumbprint(attacker)));
    }

    @Test
    void rejectsWrongNonce() throws Exception {
        KeyPair pair = key();
        JdbcTemplate db = mock(JdbcTemplate.class);
        stubRow(db, "ACTIVE", pem(pair), "PENDING", "HOLDER_ENROLLMENT", NOW.plusSeconds(300), hash(NONCE), false);
        assertThrows(SecurityException.class, () -> verifier(db).verifyPendingSession(SESSION, INSTALLATION, "C".repeat(43), thumbprint(pair)));
    }

    @Test
    void rejectsInactiveInstallation() throws Exception {
        KeyPair pair = key();
        JdbcTemplate db = mock(JdbcTemplate.class);
        stubRow(db, "REVOKED", pem(pair), "PENDING", "HOLDER_ENROLLMENT", NOW.plusSeconds(300), hash(NONCE), false);
        assertThrows(SecurityException.class, () -> verifier(db).verifyPendingSession(SESSION, INSTALLATION, NONCE, thumbprint(pair)));
    }

    @Test
    void rejectsExpiredAndCompletedSession() throws Exception {
        KeyPair pair = key();
        JdbcTemplate db = mock(JdbcTemplate.class);
        stubRow(db, "ACTIVE", pem(pair), "PENDING", "HOLDER_ENROLLMENT", NOW, hash(NONCE), false);
        assertThrows(SecurityException.class, () -> verifier(db).verifyPendingSession(SESSION, INSTALLATION, NONCE, thumbprint(pair)));
        stubRow(db, "ACTIVE", pem(pair), "COMPLETED", "HOLDER_ENROLLMENT", NOW.plusSeconds(300), hash(NONCE), false);
        assertThrows(SecurityException.class, () -> verifier(db).verifyPendingSession(SESSION, INSTALLATION, NONCE, thumbprint(pair)));
    }

    @Test
    void rejectsWrongPurposeOrAlreadyAccredited() throws Exception {
        KeyPair pair = key();
        JdbcTemplate db = mock(JdbcTemplate.class);
        stubRow(db, "ACTIVE", pem(pair), "PENDING", "OTHER", NOW.plusSeconds(300), hash(NONCE), false);
        assertThrows(SecurityException.class, () -> verifier(db).verifyPendingSession(SESSION, INSTALLATION, NONCE, thumbprint(pair)));
        stubRow(db, "ACTIVE", pem(pair), "PENDING", "HOLDER_ENROLLMENT", NOW.plusSeconds(300), hash(NONCE), true);
        assertThrows(SecurityException.class, () -> verifier(db).verifyPendingSession(SESSION, INSTALLATION, NONCE, thumbprint(pair)));
    }

    @Test
    @SuppressWarnings("unchecked")
    void rejectsMissingSession() {
        JdbcTemplate db = mock(JdbcTemplate.class);
        when(db.query(anyString(), any(RowMapper.class), eq(SESSION), eq(INSTALLATION))).thenReturn(List.of());
        assertThrows(SecurityException.class, () -> verifier(db).verifyPendingSession(SESSION, INSTALLATION, NONCE, "B".repeat(43)));
    }

    @Test
    void rejectsMalformedStoredInstallationKey() throws Exception {
        KeyPair pair = key();
        JdbcTemplate db = mock(JdbcTemplate.class);
        stubRow(db, "ACTIVE", "invalid pem", "PENDING", "HOLDER_ENROLLMENT", NOW.plusSeconds(300), hash(NONCE), false);
        assertThrows(SecurityException.class, () -> verifier(db).verifyPendingSession(SESSION, INSTALLATION, NONCE, thumbprint(pair)));
    }

    @SuppressWarnings("unchecked")
    private static void stubStart(JdbcTemplate db, String status, String pem,
                                  boolean hasHolder) throws Exception {
        ResultSet rs = mock(ResultSet.class);
        when(rs.getString("status")).thenReturn(status);
        when(rs.getString("public_key")).thenReturn(pem);
        when(rs.getBoolean("has_holder")).thenReturn(hasHolder);
        when(db.query(anyString(), any(RowMapper.class), eq(INSTALLATION)))
            .thenAnswer(inv -> {
                RowMapper<?> mapper = inv.getArgument(1);
                return List.of(mapper.mapRow(rs, 0));
            });
    }

    @SuppressWarnings("unchecked")
    private static void stubRow(JdbcTemplate db, String installationStatus, String pem, String sessionStatus,
                                String purpose, Instant expiresAt, byte[] nonceHash, boolean hasHolder) throws Exception {
        ResultSet rs = mock(ResultSet.class);
        when(rs.getString("installation_status")).thenReturn(installationStatus);
        when(rs.getString("public_key")).thenReturn(pem);
        when(rs.getString("session_status")).thenReturn(sessionStatus);
        when(rs.getString("purpose")).thenReturn(purpose);
        when(rs.getObject("expires_at", OffsetDateTime.class)).thenReturn(OffsetDateTime.ofInstant(expiresAt, ZoneOffset.UTC));
        when(rs.getBytes("nonce_hash")).thenReturn(nonceHash);
        when(rs.getBoolean("has_holder")).thenReturn(hasHolder);
        when(db.query(anyString(), any(RowMapper.class), eq(SESSION), eq(INSTALLATION)))
                .thenAnswer(invocation -> {
                    RowMapper<?> mapper = invocation.getArgument(1);
                    return List.of(mapper.mapRow(rs, 0));
                });
    }
}
