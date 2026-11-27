package pe.gob.mtc.walletprovider.institutional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Los roles provienen de PostgreSQL (nunca del navegador ni de claims manipulables). */
@Service
public final class MtcOperatorAccess {
    public static final String SUPER_ADMIN = "SUPER_ADMIN";
    public static final String REGISTRADOR = "MESA_PARTES_REGISTRADOR";
    public static final String APROBADOR = "MESA_PARTES_APROBADOR";

    private final JdbcTemplate jdbc;
    public MtcOperatorAccess(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    public record Operator(UUID id, String issuer, String subject, Set<String> roles) {
        public boolean isSuperAdmin() { return roles.contains(SUPER_ADMIN); }
        public boolean canRegister() { return isSuperAdmin() || roles.contains(REGISTRADOR); }
        public boolean canApprove() { return isSuperAdmin() || roles.contains(APROBADOR); }
    }

    public Operator require(JwtAuthenticationToken jwt) {
        if (jwt == null || !jwt.isAuthenticated() || jwt.getToken().getIssuer() == null)
            throw forbidden();
        String issuer = jwt.getToken().getIssuer().toString();
        String subject = jwt.getToken().getSubject();
        if (subject == null || subject.isBlank()) throw forbidden();
        List<Operator> users = jdbc.query("""
            SELECT id, issuer, subject FROM wallet_provider.wp_mtc_operator
            WHERE issuer = ? AND subject = ? AND status = 'ACTIVE'
              AND (valid_until IS NULL OR valid_until > CURRENT_TIMESTAMP)
            """, (rs, n) -> new Operator(rs.getObject("id", UUID.class),
                rs.getString("issuer"), rs.getString("subject"), Set.of()), issuer, subject);
        if (users.size() != 1) throw forbidden();
        Operator user = users.getFirst();
        Set<String> roles = Set.copyOf(jdbc.query("""
            SELECT role FROM wallet_provider.wp_mtc_operator_role WHERE operator_id = ?
            """, (rs, n) -> rs.getString(1), user.id()));
        if (roles.isEmpty()) throw forbidden();
        return new Operator(user.id(), issuer, subject, roles);
    }

    public Operator requireRegister(JwtAuthenticationToken jwt) {
        Operator op = require(jwt);
        if (!op.canRegister()) throw forbidden();
        return op;
    }
    public Operator requireApprove(JwtAuthenticationToken jwt) {
        Operator op = require(jwt);
        if (!op.canApprove()) throw forbidden();
        return op;
    }
    public Operator requireSuperAdmin(JwtAuthenticationToken jwt) {
        Operator op = require(jwt);
        if (!op.isSuperAdmin()) throw forbidden();
        return op;
    }
    public static ResponseStatusException forbidden() {
        return new ResponseStatusException(HttpStatus.FORBIDDEN, "Operación institucional no autorizada");
    }
}
