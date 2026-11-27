package pe.gob.mtc.walletprovider.identity;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Orquestacion INTERNA de acreditacion. Este lote NO publica rutas HTTP.
 * begin: llamar solo tras verificar criptograficamente posesion de instalacion.
 * complete: solo con evidencia confiable validada por adaptador M2M RENIEC/MiMoto.
 * Ambas operaciones requieren transaccion y se niegan ante inconsistencias.
 */
public class IdentityAccreditationService {
    private static final int TTL_SECONDS = 600;
    private static final int MAX_EVIDENCE_CHARS = 16384;
    private final JdbcTemplate jdbc;
    private final HolderIdentityCrypto crypto;
    private final TrustedReniecEvidenceVerifier verifier;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    public IdentityAccreditationService(JdbcTemplate jdbc, HolderIdentityCrypto crypto,
                                        TrustedReniecEvidenceVerifier verifier, Clock clock) {
        this.jdbc = Objects.requireNonNull(jdbc);
        this.crypto = Objects.requireNonNull(crypto);
        this.verifier = Objects.requireNonNull(verifier);
        this.clock = Objects.requireNonNull(clock);
    }

    public record Started(UUID sessionId, String nonce, Instant expiresAt) { }
    public record Completed(String installationId, UUID holderId, Instant verifiedAt) { }

    @Transactional
    public Started beginForProvenInstallation(String installationId) {
        if (installationId == null || !installationId.matches("[0-9a-fA-F-]{36}"))
            throw new SecurityException("Installation unavailable");
        ensureActiveInstallationLocked(installationId);
        if (jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM wallet_provider.wp_installation_holder WHERE installation_id = ?)",
                Boolean.class, installationId).equals(Boolean.TRUE))
            throw new SecurityException("Installation already accredited");
        OffsetDateTime now = OffsetDateTime.ofInstant(clock.instant(), ZoneOffset.UTC);
        jdbc.update("UPDATE wallet_provider.wp_identity_session SET status = 'EXPIRED' " +
            "WHERE installation_id = ? AND status = 'PENDING' AND expires_at <= ?", installationId, now);
        Boolean pending = jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM wallet_provider.wp_identity_session " +
            "WHERE installation_id = ? AND status = 'PENDING')", Boolean.class, installationId);
        if (Boolean.TRUE.equals(pending)) throw new SecurityException("Identity session already pending");
        byte[] nonceBytes = new byte[32];
        random.nextBytes(nonceBytes);
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
        UUID sessionId = UUID.randomUUID();
        Instant expires = now.toInstant().plusSeconds(TTL_SECONDS);
        jdbc.update("INSERT INTO wallet_provider.wp_identity_session " +
            "(id, installation_id, nonce_hash, purpose, status, expires_at, created_at) " +
            "VALUES (?, ?, ?, 'HOLDER_ENROLLMENT', 'PENDING', ?, ?)",
            sessionId, installationId, digest(nonce), OffsetDateTime.ofInstant(expires, ZoneOffset.UTC), now);
        return new Started(sessionId, nonce, expires);
    }

    @Transactional
    public Completed completeFromTrustedEvidence(UUID sessionId, String nonce, String evidence) {
        if (sessionId == null || nonce == null || !nonce.matches("[A-Za-z0-9_-]{43}") ||
            evidence == null || evidence.isBlank() || evidence.length() > MAX_EVIDENCE_CHARS)
            throw new SecurityException("Identity evidence invalid");
        // Obtener instalacion antes de bloquear filas; mantiene orden de bloqueos consistente con begin().
        List<String> installations = jdbc.query("SELECT installation_id FROM wallet_provider.wp_identity_session " +
            "WHERE id = ?", (rs, n) -> rs.getString(1), sessionId);
        if (installations.size() != 1) throw new SecurityException("Identity session unavailable");
        String installationId = installations.getFirst();
        ensureActiveInstallationLocked(installationId);
        List<PendingSession> sessions = jdbc.query("SELECT installation_id, nonce_hash, expires_at, status, purpose " +
            "FROM wallet_provider.wp_identity_session WHERE id = ? FOR UPDATE", (rs, n) ->
                new PendingSession(rs.getString(1), rs.getBytes(2),
                    rs.getObject(3, OffsetDateTime.class).toInstant(), rs.getString(4), rs.getString(5)), sessionId);
        if (sessions.size() != 1) throw new SecurityException("Identity session unavailable");
        PendingSession session = sessions.getFirst();
        Instant now = clock.instant();
        if (!installationId.equals(session.installationId) || !"PENDING".equals(session.status) ||
            !"HOLDER_ENROLLMENT".equals(session.purpose) || !session.expiresAt.isAfter(now) ||
            !MessageDigest.isEqual(session.nonceHash, digest(nonce)))
            throw new SecurityException("Identity session invalid or expired");
        Boolean linked = jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM wallet_provider.wp_installation_holder " +
            "WHERE installation_id = ?)", Boolean.class, installationId);
        if (Boolean.TRUE.equals(linked)) throw new SecurityException("Installation already accredited");

        TrustedReniecEvidenceVerifier.Challenge challenge =
            new TrustedReniecEvidenceVerifier.Challenge(sessionId, installationId, nonce, session.expiresAt);
        TrustedReniecEvidenceVerifier.VerifiedIdentity identity = verifier.verify(evidence, challenge);
        verifyIdentity(identity, challenge, now);
        byte[] hmac = crypto.indexDni(identity.dni());
        byte[] cipher = crypto.encryptDni(identity.dni());
        UUID holderId = UUID.randomUUID();
        jdbc.update("INSERT INTO wallet_provider.wp_holder " +
            "(id, document_type, dni_hmac, dni_cipher, key_version, issuer, subject) " +
            "VALUES (?, 'DNI', ?, ?, ?, ?, ?) ON CONFLICT (document_type, dni_hmac) DO NOTHING",
            holderId, hmac, cipher, crypto.keyVersion(), identity.issuer(), identity.subject());
        List<UUID> holders = jdbc.query("SELECT id FROM wallet_provider.wp_holder " +
            "WHERE document_type = 'DNI' AND dni_hmac = ? FOR UPDATE",
            (rs, n) -> (UUID) rs.getObject(1), hmac);
        if (holders.size() != 1) throw new SecurityException("Holder unavailable");
        holderId = holders.getFirst();
        OffsetDateTime at = OffsetDateTime.ofInstant(now, ZoneOffset.UTC);
        int completed = jdbc.update("UPDATE wallet_provider.wp_identity_session " +
            "SET status = 'COMPLETED', consumed_at = ?, evidence_digest = ?, external_ref = ? " +
            "WHERE id = ? AND status = 'PENDING'", at, digest(evidence), identity.externalReference(), sessionId);
        if (completed != 1) throw new SecurityException("Identity replay rejected");
        jdbc.update("INSERT INTO wallet_provider.wp_installation_holder " +
            "(installation_id, holder_id, identity_session_id, verified_at, status) " +
            "VALUES (?, ?, ?, ?, 'ACTIVE')", installationId, holderId, sessionId, at);
        // Vincula permisos previamente cargados por el MTC, pero NO crea autorizaciones
        // de dispositivo ni reactiva vinculos institucionales revocados.
        jdbc.update("UPDATE wallet_provider.wp_verifier_grant SET holder_id = ?, updated_at = ? " +
            "WHERE document_type = 'DNI' AND dni_hmac = ? AND holder_id IS NULL",
            holderId, at, hmac);
        return new Completed(installationId, holderId, now);
    }

    private void ensureActiveInstallationLocked(String installationId) {
        List<String> states = jdbc.query("SELECT status FROM wallet_provider.wp_installation " +
            "WHERE id = ? FOR UPDATE", (rs, n) -> rs.getString(1), installationId);
        if (states.size() != 1 || !"ACTIVE".equals(states.getFirst()))
            throw new SecurityException("Installation unavailable");
    }

    private static void verifyIdentity(TrustedReniecEvidenceVerifier.VerifiedIdentity value,
                                       TrustedReniecEvidenceVerifier.Challenge context, Instant now) {
        if (value == null || !"RENIEC_ID_PERU".equals(value.issuer()) ||
            !context.sessionId().equals(value.sessionId()) ||
            !context.installationId().equals(value.installationId()) ||
            !context.nonce().equals(value.nonce()) ||
            value.externalReference() == null || value.externalReference().isBlank() ||
            value.externalReference().length() > 128 ||
            value.authenticatedAt() == null || value.authenticatedAt().isAfter(now.plusSeconds(30)) ||
            Duration.between(value.authenticatedAt(), now).compareTo(Duration.ofMinutes(5)) > 0)
            throw new SecurityException("Authenticated identity not bound to session");
        HolderIdentityCrypto.validateDni(value.dni());
    }

    private static byte[] digest(String value) {
        try { return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)); }
        catch (NoSuchAlgorithmException ex) { throw new IllegalStateException("SHA256 unavailable", ex); }
    }

    private record PendingSession(String installationId, byte[] nonceHash, Instant expiresAt,
                                  String status, String purpose) { }
}
