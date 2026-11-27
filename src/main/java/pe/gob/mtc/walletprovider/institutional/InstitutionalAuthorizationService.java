package pe.gob.mtc.walletprovider.institutional;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Consulta interna de autorización institucional (no controlador HTTP).
 * PRECONDICION: el servicio que invoque este método YA debe haber autenticado
 * al solicitante, validado posesión de la clave enrolada y ligado la solicitud
 * a installationId. Un ID o un entityCode enviados por el móvil no son prueba.
 *
 * Rechazo implícito para vínculos no creados, vencidos, revocados o sin identidad.
 * No crea vínculos ni realiza acreditación biométrica; esas operaciones son fases
 * posteriores y deben ser transaccionales con evidencia MiMoto/RENIEC confiable.
 */
@Service
public class InstitutionalAuthorizationService {
    private static final String SQL = """
        SELECT EXISTS (
            SELECT 1
              FROM wallet_provider.wp_installation i
              JOIN wallet_provider.wp_installation_holder ih
                ON ih.installation_id = i.id
              JOIN wallet_provider.wp_holder h
                ON h.id = ih.holder_id
              JOIN wallet_provider.wp_identity_session ids
                ON ids.id = ih.identity_session_id
               AND ids.installation_id = i.id
              JOIN wallet_provider.wp_verifier_installation vi
                ON vi.installation_id = i.id
              JOIN wallet_provider.wp_verifier_grant g
                ON g.id = vi.grant_id
               AND g.holder_id = h.id
               AND g.document_type = h.document_type
               AND g.dni_hmac = h.dni_hmac
              JOIN wallet_provider.wp_entity e
                ON e.id = g.entity_id
             WHERE i.id = ? AND e.code = ?
               AND i.status = 'ACTIVE'
               AND ih.status = 'ACTIVE'
               AND ids.status = 'COMPLETED' AND ids.consumed_at IS NOT NULL
               AND e.status = 'ACTIVE'
               AND g.profile = 'VERIFICADOR' AND g.status = 'ACTIVE'
               AND g.valid_from <= CURRENT_TIMESTAMP
               AND (g.valid_until IS NULL OR g.valid_until > CURRENT_TIMESTAMP)
               AND vi.status = 'ACTIVE'
        )
        """;

    private final JdbcTemplate jdbc;

    public InstitutionalAuthorizationService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Transactional(readOnly = true)
    public Decision checkVerifiedInstallation(String installationId, String entityCode) {
        if (installationId == null || installationId.isBlank() ||
            entityCode == null || entityCode.isBlank()) {
            return Decision.DENY;
        }
        try {
            Boolean allowed = jdbc.queryForObject(SQL, Boolean.class, installationId, entityCode);
            return Boolean.TRUE.equals(allowed) ? Decision.ALLOW : Decision.DENY;
        } catch (DataAccessException ex) {
            // No cache positiva ni fallback a ALLOW. El consumidor debe tratar
            // indisponibilidad de Provider como rechazo de operación.
            throw new IllegalStateException("Institutional authorization unavailable", ex);
        }
    }

    public enum Decision { ALLOW, DENY }
}
