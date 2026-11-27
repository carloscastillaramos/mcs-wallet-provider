package pe.gob.mtc.walletprovider.institutional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import pe.gob.mtc.walletprovider.identity.HolderIdentityCrypto;
import pe.gob.mtc.walletprovider.service.EnrollmentService;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Operaciones administrativas MTC sobre el padrón; transaccionales y con auditoría sanitizada. */
@Service
@ConditionalOnProperty(prefix = "wallet-provider.portal", name = "enabled", havingValue = "true")
public class MtcPortalAdministration {
    private final JdbcTemplate jdbc;
    private final HolderIdentityCrypto crypto;
    private final EnrollmentService enrollments;

    public MtcPortalAdministration(JdbcTemplate jdbc, HolderIdentityCrypto crypto, EnrollmentService enrollments) {
        this.jdbc = jdbc; this.crypto = crypto; this.enrollments = enrollments;
    }

    public record Entity(UUID id, String code, String name) { }
    public record Grant(UUID id, String institutionalCode, String unit, String status,
                        OffsetDateTime validFrom, OffsetDateTime validUntil, long version) { }
    public record CreateGrant(String dni, String institutionalCode, String unit, LocalDate validUntil) { }

    @Transactional(readOnly = true)
    public List<Entity> entities() {
        return jdbc.query("""
            SELECT id, code, name FROM wallet_provider.wp_entity
            ORDER BY code LIMIT 200
            """, (rs, n) -> new Entity(rs.getObject("id", UUID.class),
                rs.getString("code"), rs.getString("name")));
    }

    public Entity activeEntity(String code) {
        if (code == null || !code.matches("[A-Za-z0-9_-]{2,32}")) throw bad();
        List<Entity> found = jdbc.query("""
            SELECT id, code, name FROM wallet_provider.wp_entity
            WHERE code = ? AND status = 'ACTIVE'
            """, (rs, n) -> new Entity(rs.getObject("id", UUID.class),
                rs.getString("code"), rs.getString("name")), code);
        if (found.size() != 1) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        return found.getFirst();
    }

    @Transactional(readOnly = true)
    public List<Grant> grants(String code) {
        UUID entity = activeEntity(code).id();
        // Never return DNI, ciphertext, hashes or holder identifiers to the browser.
        return jdbc.query("""
            SELECT id, institutional_code, unit, status, valid_from, valid_until, version
            FROM wallet_provider.wp_verifier_grant WHERE entity_id = ?
            ORDER BY updated_at DESC, id LIMIT 200
            """, (rs, n) -> new Grant(rs.getObject("id", UUID.class),
                rs.getString("institutional_code"), rs.getString("unit"), rs.getString("status"),
                rs.getObject("valid_from", OffsetDateTime.class),
                rs.getObject("valid_until", OffsetDateTime.class), rs.getLong("version")), entity);
    }

    @Transactional
    public UUID create(String code, CreateGrant request, MtcOperatorAccess.Operator actor) {
        UUID entity = activeEntity(code).id();
        validate(request);
        UUID grantId = add(entity, request);
        if (grantId == null) throw new ResponseStatusException(HttpStatus.CONFLICT, "Grant already exists");
        audit(actor, entity, "GRANT_CREATE", grantId.toString(), "CREATED", null);
        return grantId;
    }

    /** Inserts only NEW grants; never overwrites or silently reactivates revoked records. */
    UUID add(UUID entity, CreateGrant request) {
        validate(request);
        byte[] index = crypto.indexDni(request.dni());
        byte[] cipher = crypto.encryptDni(request.dni());
        List<UUID> holders = jdbc.query("""
            SELECT id FROM wallet_provider.wp_holder
            WHERE document_type = 'DNI' AND dni_hmac = ?
            """, (rs,n) -> rs.getObject(1, UUID.class), index);
        UUID id = UUID.randomUUID();
        int inserted = jdbc.update("""
            INSERT INTO wallet_provider.wp_verifier_grant
                (id, entity_id, document_type, dni_hmac, dni_cipher, key_version,
                 holder_id, profile, status, valid_from, valid_until, institutional_code, unit)
            VALUES (?, ?, 'DNI', ?, ?, ?, ?, 'VERIFICADOR', 'ACTIVE', CURRENT_TIMESTAMP, ?, ?, ?)
            ON CONFLICT (entity_id, document_type, dni_hmac, profile) DO NOTHING
            """, id, entity, index, cipher, crypto.keyVersion(),
            holders.isEmpty() ? null : holders.getFirst(),
            request.validUntil().plusDays(1).atStartOfDay().atOffset(ZoneOffset.UTC),
            request.institutionalCode().trim(), request.unit() == null ? null : request.unit().trim());
        return inserted == 1 ? id : null;
    }

    static void validate(CreateGrant request) {
        if (request == null) throw bad();
        HolderIdentityCrypto.validateDni(request.dni());
        if (request.institutionalCode() == null ||
            !request.institutionalCode().matches("[A-Za-z0-9_.-]{1,64}")) throw bad();
        if (request.unit() != null &&
            !request.unit().matches("[\\p{L}\\p{N} ._/-]{0,120}")) throw bad();
        if (request.validUntil() == null ||
            !request.validUntil().isAfter(LocalDate.now(ZoneOffset.UTC)) ||
            request.validUntil().isAfter(LocalDate.now(ZoneOffset.UTC).plusYears(2))) throw bad();
    }

    @Transactional
    public void revoke(String code, UUID grantId, long version, String reason,
                       MtcOperatorAccess.Operator actor) {
        UUID entity = activeEntity(code).id();
        if (grantId == null || version < 0 || reason == null || reason.isBlank() || reason.length() > 300)
            throw bad();
        int updated = jdbc.update("""
            UPDATE wallet_provider.wp_verifier_grant
            SET status = 'REVOKED', reason = ?, version = version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND entity_id = ? AND version = ? AND status <> 'REVOKED'
            """, reason, grantId, entity, version);
        if (updated != 1) throw new ResponseStatusException(HttpStatus.CONFLICT, "Grant not current");
        jdbc.update("""
            UPDATE wallet_provider.wp_verifier_installation SET status = 'REVOKED',
                revoked_at = CURRENT_TIMESTAMP, reason = ?, version = version + 1
            WHERE grant_id = ? AND status = 'ACTIVE'
            """, reason, grantId);
        audit(actor, entity, "GRANT_REVOKE", grantId.toString(), "REVOKED", reason);
    }

    /**
     * Institutional device enrollment: MTC SUPER_ADMIN only, explicitly approved,
     * identity already accredited in Provider and same holder as the grant.
     * Revoked links are immutable: the operator must investigate before a new grant.
     */
    @Transactional
    public void linkInstallation(String code, UUID grantId, UUID installationId,
                                 MtcOperatorAccess.Operator actor) {
        UUID entity = activeEntity(code).id();
        if (grantId == null || installationId == null) throw bad();
        record Eligibility(UUID holder, int maxDevices) { }
        List<Eligibility> eligible = jdbc.query("""
            SELECT g.holder_id, e.max_devices
            FROM wallet_provider.wp_verifier_grant g
            JOIN wallet_provider.wp_entity e ON e.id = g.entity_id
            WHERE g.id = ? AND g.entity_id = ? AND g.status = 'ACTIVE'
              AND e.status = 'ACTIVE' AND g.holder_id IS NOT NULL
              AND g.valid_from <= CURRENT_TIMESTAMP
              AND (g.valid_until IS NULL OR g.valid_until > CURRENT_TIMESTAMP)
            FOR UPDATE OF g
            """, (rs, n) -> new Eligibility(rs.getObject(1, UUID.class), rs.getInt(2)), grantId, entity);
        if (eligible.size() != 1) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        UUID holder = eligible.getFirst().holder();
        Boolean accredited = jdbc.queryForObject("""
            SELECT EXISTS (
              SELECT 1 FROM wallet_provider.wp_installation i
              JOIN wallet_provider.wp_installation_holder ih ON ih.installation_id = i.id
              JOIN wallet_provider.wp_identity_session ids ON ids.id = ih.identity_session_id
              WHERE i.id = ? AND i.status = 'ACTIVE'
                AND ih.holder_id = ? AND ih.status = 'ACTIVE'
                AND ids.status = 'COMPLETED' AND ids.consumed_at IS NOT NULL
            )
            """, Boolean.class, installationId.toString(), holder);
        if (!Boolean.TRUE.equals(accredited)) throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        Integer active = jdbc.queryForObject("""
            SELECT count(*) FROM wallet_provider.wp_verifier_installation
            WHERE grant_id = ? AND status = 'ACTIVE'
            """, Integer.class, grantId);
        if (active == null || active >= eligible.getFirst().maxDevices())
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Institutional device limit reached");
        int inserted = jdbc.update("""
            INSERT INTO wallet_provider.wp_verifier_installation
              (grant_id, installation_id, status)
            VALUES (?, ?, 'ACTIVE') ON CONFLICT (grant_id, installation_id) DO NOTHING
            """, grantId, installationId.toString());
        if (inserted != 1) throw new ResponseStatusException(HttpStatus.CONFLICT,
            "Device link exists, including previously revoked links");
        audit(actor, entity, "VERIFIER_INSTALLATION_LINK", grantId.toString(), "ACTIVE", null);
    }

    /** Revocacion SOLO del vinculo institucional de un verificador; NO revoca la Wallet ciudadana. */
    @Transactional
    public void revokeVerifierInstallation(String code, UUID grantId, UUID installationId,
                                            String reason, MtcOperatorAccess.Operator actor) {
        UUID entity = activeEntity(code).id();
        if (grantId == null || installationId == null || reason == null ||
            reason.isBlank() || reason.length() > 300) throw bad();
        int updated = jdbc.update("""
            UPDATE wallet_provider.wp_verifier_installation vi
            SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP,
                reason = ?, version = vi.version + 1
            FROM wallet_provider.wp_verifier_grant g
            WHERE vi.grant_id = g.id AND g.id = ? AND g.entity_id = ?
              AND vi.installation_id = ? AND vi.status = 'ACTIVE'
            """, reason.trim(), grantId, entity, installationId.toString());
        if (updated != 1) throw new ResponseStatusException(HttpStatus.CONFLICT,
            "Vínculo institucional ya no se encuentra activo");
        audit(actor, entity, "VERIFIER_INSTALLATION_REVOKE", grantId.toString(), "REVOKED", reason.trim());
    }

    /** Global device revocation is reserved exclusively for MTC SUPER_ADMIN. */
    @Transactional
    public void revokeInstallation(UUID id, String reason, MtcOperatorAccess.Operator actor) {
        if (id == null || reason == null || reason.isBlank() || reason.length() > 300) throw bad();
        // Lock + diagnostics outbox happen in the legacy service within the SAME TX.
        enrollments.revoke(id.toString(), reason);
        audit(actor, null, "INSTALLATION_REVOKE_GLOBAL", id.toString(), "REVOKED", reason);
    }

    void audit(MtcOperatorAccess.Operator actor, UUID entity, String action,
               String resource, String result, String reason) {
        jdbc.update("""
            INSERT INTO wallet_provider.wp_admin_audit
            (id, actor_issuer, actor_sub, entity_id, action, resource_id, reason, result, correlation_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, UUID.randomUUID(), actor.issuer(), actor.subject(), entity,
            action, resource, reason, result, UUID.randomUUID().toString());
    }

    private static ResponseStatusException bad() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid institutional request");
    }
}
