package pe.gob.mtc.walletprovider.identity;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import java.time.Clock;
import java.nio.file.Path;

/**
 * Fail-closed: las identidades no se habilitan por defecto. Si se activa el flag
 * sin claves o sin adaptador de evidencia RENIEC confiable, falla el arranque.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "wallet-provider.identity", name = "enabled", havingValue = "true")
public class IdentityAccreditationConfig {
    @Bean
    TrustedReniecEvidenceVerifier trustedReniecEvidenceVerifier(
        @Value("${wallet-provider.identity.mimoto-evidence-issuer:}") String issuer,
        @Value("${wallet-provider.identity.mimoto-evidence-audience:}") String audience,
        @Value("${wallet-provider.identity.mimoto-evidence-signer-cert-path:}") String certificatePath) {
        if (certificatePath == null || certificatePath.isBlank())
            throw new IllegalArgumentException("Mimoto evidence signer certificate missing");
        return new SignedMimotoReniecEvidenceVerifier(
            Path.of(certificatePath), issuer, audience, Clock.systemUTC());
    }

    @Bean
    IdentityAccreditationService identityAccreditationService(
        JdbcTemplate jdbc, HolderIdentityCrypto crypto, TrustedReniecEvidenceVerifier verifier) {
        return new IdentityAccreditationService(jdbc, crypto, verifier, Clock.systemUTC());
    }
}
