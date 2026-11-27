package pe.gob.mtc.walletprovider.institutional;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/** El SUPER_ADMIN gestiona operadores MTC; el issuer es siempre el de su propia sesion. */
@Service
@ConditionalOnProperty(prefix = "wallet-provider.portal", name = "enabled", havingValue = "true")
public class MtcOperatorDirectory {
    private static final Set<String> ALLOWED = Set.of(MtcOperatorAccess.SUPER_ADMIN,
        MtcOperatorAccess.REGISTRADOR, MtcOperatorAccess.APROBADOR);
    private final JdbcTemplate jdbc;
    private final MtcPortalAdministration admin;

    public MtcOperatorDirectory(JdbcTemplate jdbc, MtcPortalAdministration admin) {
        this.jdbc = jdbc; this.admin = admin;
    }
    public record OperatorRecord(UUID id, String subject, String status, Set<String> roles) { }
    public record CreateOperator(String subject, Set<String> roles) { }
    public record UpdateRoles(Set<String> roles) { }

    @Transactional(readOnly = true)
    public List<OperatorRecord> list(MtcOperatorAccess.Operator actor) {
        return jdbc.query("""
            SELECT o.id, o.subject, o.status,
                   COALESCE(string_agg(r.role, ',' ORDER BY r.role), '') AS role_names
            FROM wallet_provider.wp_mtc_operator o
            LEFT JOIN wallet_provider.wp_mtc_operator_role r ON r.operator_id = o.id
            WHERE o.issuer = ?
            GROUP BY o.id, o.subject, o.status
            ORDER BY o.subject LIMIT 200
            """, (rs, n) -> new OperatorRecord(rs.getObject("id", UUID.class),
                rs.getString("subject"), rs.getString("status"), parse(rs.getString("role_names"))),
            actor.issuer());
    }

    @Transactional
    public UUID create(CreateOperator request, MtcOperatorAccess.Operator actor) {
        if (request == null || request.subject() == null ||
            !request.subject().matches("[A-Za-z0-9_@./:+\\-=]{1,255}")) throw bad();
        validateRoles(request.roles());
        UUID id = UUID.randomUUID();
        try {
            jdbc.update("""
                INSERT INTO wallet_provider.wp_mtc_operator
                (id, issuer, subject, role, status)
                VALUES (?, ?, ?, ?, 'ACTIVE')
                """, id, actor.issuer(), request.subject(),
                request.roles().contains(MtcOperatorAccess.SUPER_ADMIN) ? "SUPER_ADMIN" : "MESA_DE_PARTES");
        } catch (DuplicateKeyException ex) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Operador MTC ya existe");
        }
        assign(id, request.roles());
        admin.audit(actor, null, "OPERATOR_CREATE", id.toString(), "ACTIVE", null);
        return id;
    }

    @Transactional
    public void updateRoles(UUID id, UpdateRoles request, MtcOperatorAccess.Operator actor) {
        if (id == null || request == null) throw bad();
        validateRoles(request.roles());
        // Serializar cambios de roles de un mismo issuer para no retirar simultaneamente
        // el ultimo SUPER_ADMIN en dos transacciones concurrentes.
        jdbc.query("""
            SELECT id FROM wallet_provider.wp_mtc_operator
            WHERE issuer = ? AND status = 'ACTIVE' ORDER BY id FOR UPDATE
            """, (rs, n) -> rs.getObject(1, UUID.class), actor.issuer());
        List<String> identities = jdbc.query("""
            SELECT subject FROM wallet_provider.wp_mtc_operator
            WHERE id = ? AND issuer = ? AND status = 'ACTIVE' FOR UPDATE
            """, (rs, n) -> rs.getString(1), id, actor.issuer());
        if (identities.size() != 1) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        if (actor.id().equals(id) && !request.roles().contains(MtcOperatorAccess.SUPER_ADMIN))
            throw new ResponseStatusException(HttpStatus.CONFLICT, "No puede quitarse su propio SUPER_ADMIN");
        if (!request.roles().contains(MtcOperatorAccess.SUPER_ADMIN)) {
            // Evitar retirar el ultimo SUPER_ADMIN de la institucion.
            Integer count = jdbc.queryForObject("""
                SELECT count(*) FROM wallet_provider.wp_mtc_operator o
                JOIN wallet_provider.wp_mtc_operator_role r ON r.operator_id = o.id
                WHERE o.issuer = ? AND o.status = 'ACTIVE' AND r.role = 'SUPER_ADMIN'
                """, Integer.class, actor.issuer());
            if (count != null && count <= 1 && currentSuperAdmin(id))
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Debe existir un SUPER_ADMIN");
        }
        jdbc.update("DELETE FROM wallet_provider.wp_mtc_operator_role WHERE operator_id = ?", id);
        assign(id, request.roles());
        // La columna legada se mantiene coherente; nunca se usa como fuente de autorizacion.
        jdbc.update("""
            UPDATE wallet_provider.wp_mtc_operator SET role = ?, version = version + 1,
                updated_at = CURRENT_TIMESTAMP WHERE id = ? AND issuer = ?
            """, request.roles().contains(MtcOperatorAccess.SUPER_ADMIN) ? "SUPER_ADMIN" : "MESA_DE_PARTES",
            id, actor.issuer());
        admin.audit(actor, null, "OPERATOR_ROLES_CHANGE", id.toString(), "UPDATED", null);
    }

    private boolean currentSuperAdmin(UUID id) {
        Boolean exists = jdbc.queryForObject("""
            SELECT EXISTS(SELECT 1 FROM wallet_provider.wp_mtc_operator_role
              WHERE operator_id = ? AND role = 'SUPER_ADMIN')
            """, Boolean.class, id);
        return Boolean.TRUE.equals(exists);
    }
    private void assign(UUID id, Set<String> roles) {
        for (String role : roles) {
            jdbc.update("""
                INSERT INTO wallet_provider.wp_mtc_operator_role(operator_id, role) VALUES (?, ?)
                """, id, role);
        }
    }
    private static Set<String> parse(String raw) {
        if (raw == null || raw.isBlank()) return Set.of();
        return Arrays.stream(raw.split(",")).collect(Collectors.toUnmodifiableSet());
    }
    private static void validateRoles(Set<String> roles) {
        if (roles == null || roles.isEmpty() || !ALLOWED.containsAll(roles)) throw bad();
    }
    private static ResponseStatusException bad() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Roles de operador inválidos");
    }
}
