package pe.gob.mtc.walletprovider.identity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Estado privado de acreditacion para MiMoto autenticado por Cognito M2M.
 * NO es un permiso institucional de verificacion ni una autorizacion con vigencia
 * propia: Wallet debe reconsultarlo y el servidor debe validar otras operaciones.
 * No devuelve DNI, holderId, nonce ni evidencia RENIEC.
 *
 * El keyThumbprint DEBE proceder de MtcWalletSessionGate.authorize con PoP
 * validado para la peticion movil; nunca de un parametro confiado sin prueba.
 */
@Service
public class HolderIdentityStatusService {
    private static final String SQL = """
        SELECT i.status AS installation_status, i.public_key,
               h.status AS holder_status,
               s.status AS session_status, s.purpose AS session_purpose,
               s.consumed_at AS session_consumed_at,
               s.evidence_digest AS session_evidence_digest,
               EXISTS (SELECT 1 FROM wallet_provider.wp_identity_session p
                       WHERE p.installation_id = i.id AND p.purpose = 'HOLDER_ENROLLMENT'
                         AND p.status = 'PENDING' AND p.expires_at > ?) AS has_pending
        FROM wallet_provider.wp_installation i
        LEFT JOIN wallet_provider.wp_installation_holder h ON h.installation_id = i.id
        LEFT JOIN wallet_provider.wp_identity_session s ON s.id = h.identity_session_id
        WHERE i.id = ?
        """;

    public enum State {
        ACCREDITED, IDENTITY_REQUIRED, IDENTITY_PENDING,
        IDENTITY_BLOCKED, INSTALLATION_INACTIVE
    }
    public record Status(State state, boolean walletAccessAllowed, Instant checkedAt) { }

    private final JdbcTemplate jdbc;
    private final HolderInstallationBindingVerifier installationVerifier;
    private final Clock clock;

    @Autowired
    public HolderIdentityStatusService(JdbcTemplate jdbc,
                                       HolderInstallationBindingVerifier installationVerifier) {
        this(jdbc, installationVerifier, Clock.systemUTC());
    }

    HolderIdentityStatusService(JdbcTemplate jdbc,
                                HolderInstallationBindingVerifier installationVerifier,
                                Clock clock) {
        this.jdbc = Objects.requireNonNull(jdbc);
        this.installationVerifier = Objects.requireNonNull(installationVerifier);
        this.clock = Objects.requireNonNull(clock);
    }

    /** La lectura nunca realiza cambios; el controlador exige Cognito M2M. */
    @Transactional(readOnly = true)
    public Status get(String installationId, String provenKeyThumbprint) {
        if (!validUuid(installationId) || !validThumbprint(provenKeyThumbprint)) throw denied();
        Instant now = clock.instant();
        List<Row> rows = jdbc.query(SQL, (rs, row) -> new Row(
                rs.getString("installation_status"), rs.getString("public_key"),
                rs.getString("holder_status"), rs.getString("session_status"),
                rs.getString("session_purpose"),
                rs.getObject("session_consumed_at", OffsetDateTime.class),
                rs.getBytes("session_evidence_digest"),
                rs.getBoolean("has_pending")),
            OffsetDateTime.ofInstant(now, java.time.ZoneOffset.UTC), installationId);
        if (rows.size() != 1) throw denied();
        Row row = rows.getFirst();
        // Obligatorio incluso al consultar instalaciones revocadas o sin titular.
        String registeredThumbprint = installationVerifier.thumbprintFromStoredPem(row.publicKey());
        if (!MessageDigest.isEqual(registeredThumbprint.getBytes(StandardCharsets.US_ASCII),
                                   provenKeyThumbprint.getBytes(StandardCharsets.US_ASCII))) {
            throw denied();
        }
        State state;
        if (!"ACTIVE".equals(row.installationStatus())) {
            state = State.INSTALLATION_INACTIVE;
        } else if (row.holderStatus() != null) {
            // Fail closed ante inconsistencia de datos o estado de titular bloqueado.
            boolean goodEvidence = "ACTIVE".equals(row.holderStatus())
                && "COMPLETED".equals(row.sessionStatus())
                && "HOLDER_ENROLLMENT".equals(row.sessionPurpose())
                && row.sessionConsumedAt() != null
                && row.sessionEvidenceDigest() != null
                && row.sessionEvidenceDigest().length == 32;
            state = goodEvidence ? State.ACCREDITED : State.IDENTITY_BLOCKED;
        } else {
            state = row.hasPending() ? State.IDENTITY_PENDING : State.IDENTITY_REQUIRED;
        }
        return new Status(state, state == State.ACCREDITED, now);
    }

    private static boolean validUuid(String value) {
        if (value == null || !value.matches("[0-9a-fA-F-]{36}")) return false;
        try { return UUID.fromString(value).toString().equalsIgnoreCase(value); }
        catch (IllegalArgumentException ex) { return false; }
    }
    private static boolean validThumbprint(String value) {
        return value != null && value.matches("[A-Za-z0-9_-]{43}");
    }
    private static SecurityException denied() {
        return new SecurityException("Holder installation status denied");
    }
    private record Row(String installationStatus, String publicKey, String holderStatus,
                       String sessionStatus, String sessionPurpose,
                       OffsetDateTime sessionConsumedAt, byte[] sessionEvidenceDigest,
                       boolean hasPending) { }
}
