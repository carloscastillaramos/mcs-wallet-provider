package pe.gob.mtc.walletprovider.identity;

import java.time.Instant;
import java.util.UUID;

/**
 * Contrato de seguridad SIN implementacion en el presente lote.
 * Implementar solo en adaptador M2M MiMoto autenticado y que valide firma/issuer,
 * audiencia, proposito HOLDER_ENROLLMENT, nonce, installationId, sessionId,
 * expiracion y unicidad del resultado RENIEC/ID Peru.
 * Nunca aceptar una respuesta arbitraria del movil como evidencia.
 */
public interface TrustedReniecEvidenceVerifier {
    VerifiedIdentity verify(String evidence, Challenge challenge);

    record Challenge(UUID sessionId, String installationId, String nonce, Instant expiresAt) { }

    record VerifiedIdentity(String dni, String issuer, String subject,
                            String externalReference, UUID sessionId,
                            String installationId, String nonce, Instant authenticatedAt) { }
}
