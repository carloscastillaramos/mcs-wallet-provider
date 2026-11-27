package pe.gob.mtc.walletprovider.identity;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pe.gob.mtc.walletprovider.security.ProofVerifier;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Comprobacion de correlacion Provider para el futuro adaptador MiMoto M2M.
 * No expone endpoint, no autentica al cliente M2M ni consume sesiones biométricas.
 * El thumbprint que se pasa aqui DEBE provenir de una sesion MiMoto ya validada
 * por MtcWalletSessionGate y de un canal backend-to-backend autenticado.
 */
@Service
public class HolderInstallationBindingVerifier {
    private static final String SQL = "SELECT i.status AS installation_status, i.public_key, " +
        "s.status AS session_status, s.purpose, s.expires_at, s.nonce_hash, " +
        "EXISTS (SELECT 1 FROM wallet_provider.wp_installation_holder h " +
        "WHERE h.installation_id = i.id) AS has_holder " +
        "FROM wallet_provider.wp_identity_session s " +
        "JOIN wallet_provider.wp_installation i ON i.id = s.installation_id " +
        "WHERE s.id = ? AND i.id = ?";

    private final JdbcTemplate jdbc;
    private final ProofVerifier proof;
    private final Clock clock;

    @Autowired
    public HolderInstallationBindingVerifier(JdbcTemplate jdbc, ProofVerifier proof) {
        this(jdbc, proof, Clock.systemUTC());
    }

    // Reloj inyectable para pruebas deterministas.
    HolderInstallationBindingVerifier(JdbcTemplate jdbc, ProofVerifier proof, Clock clock) {
        this.jdbc = Objects.requireNonNull(jdbc);
        this.proof = Objects.requireNonNull(proof);
        this.clock = Objects.requireNonNull(clock);
    }

    public record VerifiedBinding(UUID identitySessionId, String installationId,
                                  String nonce, String publicKeyThumbprint) { }

    /**
     * Se niega ante sesion inexistente, caducada, consumida, clave distinta
     * o instalacion previamente vinculada a un titular.
     * No es una autorizacion: antes de su uso externo se necesita autenticacion
     * del llamador MiMoto, verificacion de posesion y verificacion del resultado RENIEC.
     */
    @Transactional(readOnly = true)
    public VerifiedBinding verifyPendingSession(UUID identitySessionId,
                                                 String installationId,
                                                 String nonce,
                                                 String attestedKeyThumbprint) {
        if (identitySessionId == null || !validUuid(installationId) ||
                nonce == null || !nonce.matches("[A-Za-z0-9_-]{43}") ||
                attestedKeyThumbprint == null || !attestedKeyThumbprint.matches("[A-Za-z0-9_-]{43}")) {
            throw rejected();
        }
        List<DatabaseBinding> found = jdbc.query(SQL, (rs, row) -> new DatabaseBinding(
                rs.getString("installation_status"), rs.getString("public_key"),
                rs.getString("session_status"), rs.getString("purpose"),
                rs.getObject("expires_at", OffsetDateTime.class).toInstant(),
                rs.getBytes("nonce_hash"), rs.getBoolean("has_holder")),
                identitySessionId, installationId);
        if (found.size() != 1) throw rejected();
        DatabaseBinding b = found.getFirst();
        Instant now = clock.instant();
        if (!"ACTIVE".equals(b.installationStatus) ||
                !"PENDING".equals(b.sessionStatus) ||
                !"HOLDER_ENROLLMENT".equals(b.purpose) ||
                b.hasHolder || b.expiresAt == null || !b.expiresAt.isAfter(now) ||
                b.nonceHash == null || b.nonceHash.length != 32 ||
                !constantTimeEquals(b.nonceHash, sha256(nonce))) {
            throw rejected();
        }
        String storedThumbprint = thumbprintFromStoredPem(b.publicKey);
        if (!constantTimeEquals(storedThumbprint.getBytes(StandardCharsets.US_ASCII),
                attestedKeyThumbprint.getBytes(StandardCharsets.US_ASCII))) throw rejected();
        return new VerifiedBinding(identitySessionId, installationId, nonce, storedThumbprint);
    }

    /**
     * Inicio desde MiMoto ya autenticado M2M. El thumbprint DEBE provenir de
     * MtcWalletSessionGate.authorize(attestation, PoP), no del cliente movil.
     * No crea sesiones: solo verifica la instalacion y su clave persistida.
     */
    @Transactional(readOnly = true)
    public void verifyActiveInstallationForStart(String installationId, String attestedKeyThumbprint) {
        if (!validUuid(installationId) || attestedKeyThumbprint == null ||
                !attestedKeyThumbprint.matches("[A-Za-z0-9_-]{43}")) throw rejected();
        List<StartState> rows = jdbc.query("SELECT i.status, i.public_key, " +
                "EXISTS (SELECT 1 FROM wallet_provider.wp_installation_holder h " +
                "WHERE h.installation_id = i.id) AS has_holder " +
                "FROM wallet_provider.wp_installation i WHERE i.id = ?",
                (rs, row) -> new StartState(rs.getString("status"),
                    rs.getString("public_key"), rs.getBoolean("has_holder")), installationId);
        if (rows.size() != 1 || !"ACTIVE".equals(rows.getFirst().status()) ||
                rows.getFirst().hasHolder()) throw rejected();
        String storedThumbprint = thumbprintFromStoredPem(rows.getFirst().publicKey());
        if (!constantTimeEquals(storedThumbprint.getBytes(StandardCharsets.US_ASCII),
                attestedKeyThumbprint.getBytes(StandardCharsets.US_ASCII))) throw rejected();
    }

    // Visible al paquete para probar la equivalencia JWK de Provider y MiMoto.
    String thumbprintFromStoredPem(String pem) {
        try {
            if (pem == null || pem.length() > 8192) throw rejected();
            var key = proof.decodePem(pem);
            if (!(key instanceof ECPublicKey ec)) throw rejected();
            return new ECKey.Builder(Curve.P_256, ec).build().computeThumbprint().toString();
        } catch (Exception ex) {
            throw rejected();
        }
    }

    private static byte[] sha256(String nonce) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(nonce.getBytes(StandardCharsets.US_ASCII));
        } catch (Exception ex) { throw new IllegalStateException("SHA-256 unavailable"); }
    }

    private static boolean validUuid(String value) {
        if (value == null || !value.matches("[0-9a-fA-F-]{36}")) return false;
        try { return UUID.fromString(value).toString().equalsIgnoreCase(value); }
        catch (IllegalArgumentException ex) { return false; }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    private static SecurityException rejected() {
        return new SecurityException("Holder installation binding rejected");
    }

    private record StartState(String status, String publicKey, boolean hasHolder) { }

    private record DatabaseBinding(String installationStatus, String publicKey,
                                   String sessionStatus, String purpose, Instant expiresAt,
                                   byte[] nonceHash, boolean hasHolder) { }
}
