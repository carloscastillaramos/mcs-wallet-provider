package pe.gob.mtc.walletprovider.institutional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import pe.gob.mtc.walletprovider.identity.HolderIdentityCrypto;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

/**
 * Mesa de Partes: registrador solo crea solicitudes; aprobador aplica o rechaza.
 * La decision, escritura efectiva y auditoria se ejecutan en una sola transaccion.
 * Ningun payload sensible (DNI, motivos) se devuelve al navegador.
 */
@Service
@ConditionalOnProperty(prefix = "wallet-provider.portal", name = "enabled", havingValue = "true")
public class MtcWorkRequestService {
    public static final String GRANT_CREATE = "GRANT_CREATE";
    public static final String GRANT_REVOKE = "GRANT_REVOKE";
    public static final String INSTALLATION_LINK = "INSTALLATION_LINK";
    public static final String INSTALLATION_UNLINK = "INSTALLATION_UNLINK";
    public static final String INSTALLATION_REVOKE = "INSTALLATION_REVOKE";

    private final JdbcTemplate jdbc;
    private final HolderIdentityCrypto crypto;
    private final MtcPortalAdministration admin;
    private final ObjectMapper mapper;

    public MtcWorkRequestService(JdbcTemplate jdbc, HolderIdentityCrypto crypto,
                                 MtcPortalAdministration admin, ObjectMapper mapper) {
        this.jdbc = jdbc; this.crypto = crypto; this.admin = admin; this.mapper = mapper;
    }

    public record GrantRevoke(long version, String reason) { }
    public record InstallationLink(UUID installationId) { }
    public record InstallationRevoke(String reason) { }
    public record InstallationUnlink(UUID installationId, String reason) { }
    public record Decision(String reason) { }

    public record WorkRequest(UUID id, String entityCode, String action, String resourceId,
                              String status, String requestedBy, OffsetDateTime requestedAt,
                              String decidedBy, OffsetDateTime decidedAt,
                              String decisionReason, String appliedResourceId) { }
    private record Locked(UUID id, UUID entityId, String action, String resourceId,
                          byte[] payload, String status) { }

    @Transactional
    public UUID registerGrant(String code, MtcPortalAdministration.CreateGrant grant,
                              String key, MtcOperatorAccess.Operator actor) {
        MtcPortalAdministration.validate(grant);
        return register(admin.activeEntity(code).id(), GRANT_CREATE, null, grant, key, actor);
    }
    @Transactional
    public UUID registerGrantRevoke(String code, UUID grantId, GrantRevoke revoke,
                                    String key, MtcOperatorAccess.Operator actor) {
        UUID entity = admin.activeEntity(code).id();
        if (grantId == null || revoke == null || revoke.version() < 0) throw bad();
        validateReason(revoke.reason());
        Integer count = jdbc.queryForObject("""
            SELECT count(*) FROM wallet_provider.wp_verifier_grant
            WHERE entity_id = ? AND id = ? AND version = ? AND status <> 'REVOKED'
            """, Integer.class, entity, grantId, revoke.version());
        if (count == null || count != 1) throw conflict();
        return register(entity, GRANT_REVOKE, grantId.toString(), revoke, key, actor);
    }
    @Transactional
    public UUID registerInstallationLink(String code, UUID grantId, InstallationLink link,
                                         String key, MtcOperatorAccess.Operator actor) {
        UUID entity = admin.activeEntity(code).id();
        if (grantId == null || link == null || link.installationId() == null) throw bad();
        Integer count = jdbc.queryForObject("""
            SELECT count(*) FROM wallet_provider.wp_verifier_grant
            WHERE entity_id = ? AND id = ? AND status = 'ACTIVE'
            """, Integer.class, entity, grantId);
        if (count == null || count != 1) throw conflict();
        return register(entity, INSTALLATION_LINK, grantId.toString(), link, key, actor);
    }
    @Transactional
    public UUID registerInstitutionalUnlink(String code, UUID grantId, InstallationUnlink unlink,
                                            String key, MtcOperatorAccess.Operator actor) {
        UUID entity = admin.activeEntity(code).id();
        if (grantId == null || unlink == null || unlink.installationId() == null) throw bad();
        validateReason(unlink.reason());
        Integer current = jdbc.queryForObject("""
            SELECT count(*) FROM wallet_provider.wp_verifier_installation vi
            JOIN wallet_provider.wp_verifier_grant g ON g.id = vi.grant_id
            WHERE g.entity_id = ? AND g.id = ? AND vi.installation_id = ?
              AND vi.status = 'ACTIVE'
            """, Integer.class, entity, grantId, unlink.installationId().toString());
        if (current == null || current != 1) throw conflict();
        return register(entity, INSTALLATION_UNLINK, grantId.toString(), unlink, key, actor);
    }

    @Transactional
    public UUID registerInstallationRevoke(UUID installationId, InstallationRevoke revoke,
                                           String key, MtcOperatorAccess.Operator actor) {
        if (!actor.isSuperAdmin()) throw MtcOperatorAccess.forbidden();
        if (installationId == null || revoke == null) throw bad();
        validateReason(revoke.reason());
        return register(null, INSTALLATION_REVOKE, installationId.toString(), revoke, key, actor);
    }

    private UUID register(UUID entity, String action, String resourceId, Object payload,
                          String key, MtcOperatorAccess.Operator actor) {
        if (key == null || !key.matches("[A-Za-z0-9_.-]{12,100}")) throw bad();
        final byte[] cipher = crypto.encryptImportRow(json(payload));
        UUID id = UUID.randomUUID();
        try {
            jdbc.update("""
                INSERT INTO wallet_provider.wp_mtc_work_request
                (id, entity_id, action, resource_id, payload_cipher, requested_by, request_key)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, id, entity, action, resourceId, cipher, actor.id(), key);
        } catch (DuplicateKeyException ex) {
            throw conflict();
        }
        admin.audit(actor, entity, "REQUEST_REGISTER", id.toString(), "PENDING", null);
        return id;
    }

    @Transactional(readOnly = true)
    public List<WorkRequest> list(String entityCode) {
        if (entityCode != null && !entityCode.isBlank()) admin.activeEntity(entityCode);
        String sql = """
            SELECT r.id, e.code AS entity_code, r.action, r.resource_id, r.status,
                   o.subject AS requested_by, r.requested_at, reviewer.subject AS decided_by,
                   r.decided_at, r.decision_reason, r.applied_resource_id
            FROM wallet_provider.wp_mtc_work_request r
            LEFT JOIN wallet_provider.wp_entity e ON e.id = r.entity_id
            JOIN wallet_provider.wp_mtc_operator o ON o.id = r.requested_by
            LEFT JOIN wallet_provider.wp_mtc_operator reviewer ON reviewer.id = r.decided_by
            """;
        var rowMapper = (org.springframework.jdbc.core.RowMapper<WorkRequest>) (rs, n) ->
            new WorkRequest(rs.getObject("id", UUID.class), rs.getString("entity_code"),
                rs.getString("action"), rs.getString("resource_id"), rs.getString("status"),
                rs.getString("requested_by"), rs.getObject("requested_at", OffsetDateTime.class),
                rs.getString("decided_by"), rs.getObject("decided_at", OffsetDateTime.class),
                rs.getString("decision_reason"), rs.getString("applied_resource_id"));
        if (entityCode == null || entityCode.isBlank()) {
            return jdbc.query(sql + " ORDER BY CASE WHEN r.status = 'PENDING' THEN 0 ELSE 1 END, r.requested_at DESC, r.id DESC LIMIT 200", rowMapper);
        }
        return jdbc.query(sql + " WHERE e.code = ? ORDER BY CASE WHEN r.status = 'PENDING' THEN 0 ELSE 1 END, r.requested_at DESC, r.id DESC LIMIT 200",
            rowMapper, entityCode);
    }

    @Transactional
    public void approve(UUID id, MtcOperatorAccess.Operator actor) {
        Locked work = lock(id);
        String entityCode = null;
        if (work.entityId() != null) {
            List<String> codes = jdbc.query("""
                SELECT code FROM wallet_provider.wp_entity
                WHERE id = ? AND status = 'ACTIVE'
                """, (rs, n) -> rs.getString(1), work.entityId());
            if (codes.size() != 1) throw conflict();
            entityCode = codes.getFirst();
        }
        String appliedId;
        switch (work.action()) {
            case GRANT_CREATE -> appliedId = admin.create(entityCode,
                read(work.payload(), MtcPortalAdministration.CreateGrant.class), actor).toString();
            case GRANT_REVOKE -> {
                GrantRevoke payload = read(work.payload(), GrantRevoke.class);
                admin.revoke(entityCode, UUID.fromString(work.resourceId()),
                    payload.version(), payload.reason(), actor);
                appliedId = work.resourceId();
            }
            case INSTALLATION_LINK -> {
                InstallationLink payload = read(work.payload(), InstallationLink.class);
                admin.linkInstallation(entityCode, UUID.fromString(work.resourceId()),
                    payload.installationId(), actor);
                appliedId = payload.installationId().toString();
            }
            case INSTALLATION_UNLINK -> {
                InstallationUnlink payload = read(work.payload(), InstallationUnlink.class);
                admin.revokeVerifierInstallation(entityCode, UUID.fromString(work.resourceId()),
                    payload.installationId(), payload.reason(), actor);
                appliedId = payload.installationId().toString();
            }
            case INSTALLATION_REVOKE -> {
                if (!actor.isSuperAdmin()) throw MtcOperatorAccess.forbidden();
                InstallationRevoke payload = read(work.payload(), InstallationRevoke.class);
                admin.revokeInstallation(UUID.fromString(work.resourceId()), payload.reason(), actor);
                appliedId = work.resourceId();
            }
            default -> throw conflict();
        }
        int updated = jdbc.update("""
            UPDATE wallet_provider.wp_mtc_work_request
            SET status = 'APPROVED', decided_by = ?, decided_at = CURRENT_TIMESTAMP,
                applied_resource_id = ?
            WHERE id = ? AND status = 'PENDING'
            """, actor.id(), appliedId, id);
        if (updated != 1) throw conflict();
        admin.audit(actor, work.entityId(), "REQUEST_APPROVE", id.toString(), "APPROVED", null);
    }

    @Transactional
    public void reject(UUID id, Decision decision, MtcOperatorAccess.Operator actor) {
        if (decision == null) throw bad();
        validateReason(decision.reason());
        Locked work = lock(id);
        if (INSTALLATION_REVOKE.equals(work.action()) && !actor.isSuperAdmin())
            throw MtcOperatorAccess.forbidden();
        int updated = jdbc.update("""
            UPDATE wallet_provider.wp_mtc_work_request
            SET status = 'REJECTED', decided_by = ?, decided_at = CURRENT_TIMESTAMP,
                decision_reason = ?
            WHERE id = ? AND status = 'PENDING'
            """, actor.id(), decision.reason().trim(), id);
        if (updated != 1) throw conflict();
        admin.audit(actor, work.entityId(), "REQUEST_REJECT", id.toString(),
            "REJECTED", decision.reason().trim());
    }

    private Locked lock(UUID id) {
        if (id == null) throw bad();
        List<Locked> found = jdbc.query("""
            SELECT id, entity_id, action, resource_id, payload_cipher, status
            FROM wallet_provider.wp_mtc_work_request WHERE id = ? FOR UPDATE
            """, (rs, n) -> new Locked(rs.getObject("id", UUID.class),
                rs.getObject("entity_id", UUID.class), rs.getString("action"),
                rs.getString("resource_id"), rs.getBytes("payload_cipher"),
                rs.getString("status")), id);
        if (found.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        if (!"PENDING".equals(found.getFirst().status())) throw conflict();
        return found.getFirst();
    }
    private String json(Object payload) {
        try { return mapper.writeValueAsString(payload); }
        catch (JsonProcessingException ex) { throw bad(); }
    }
    private <T> T read(byte[] cipher, Class<T> type) {
        try { return mapper.readValue(crypto.decryptImportRow(cipher), type); }
        catch (JsonProcessingException ex) { throw new IllegalStateException("Invalid sealed request", ex); }
    }
    static void validateReason(String reason) {
        if (reason == null || reason.isBlank() || reason.trim().length() > 300) throw bad();
    }
    private static ResponseStatusException bad() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Solicitud institucional inválida");
    }
    private static ResponseStatusException conflict() {
        return new ResponseStatusException(HttpStatus.CONFLICT, "La solicitud o el registro ya cambió de estado");
    }
}
