package pe.gob.mtc.walletprovider.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.util.Arrays;

/**
 * Only for the disposable, loopback-only MTC Ubuntu lab.
 * Verifies RS256 signatures against the lab's local JWKS (never accepts unsigned JWTs).
 * The institutional Cognito configuration is a separate bean behind the inverse profile.
 * This class must not be enabled by generic `local`, `dev`, `qa` or `prod` profiles.
 */
@Configuration(proxyBeanMethods = false)
@Profile("mtc-lab-v076")
@ConditionalOnProperty(prefix = "wallet.cognito", name = "enabled", havingValue = "true")
public class MtcLabJwtConfig {
    static final String LAB_ISSUER = "http://127.0.0.1:18090";
    static final String LAB_JWKS = LAB_ISSUER + "/.well-known/jwks.json";
    static final String LAB_CLIENT = "mtc-lab-portal";
    static final String LAB_AUDIENCE = "mtc-lab-admin";
    static final String LAB_SCOPE = "mtc-wallet-provider/wallet.portal";

    static final String M2M_CLIENT = "mtc-lab-certify-m2m";
    static final String M2M_AUDIENCE = "mtc-lab-certify-m2m";
    static final String M2M_SCOPE = "mtc-wallet-provider/wallet.issuance.certify";

    static final String VERIFIER_CLIENT = "mtc-lab-verifier-m2m";
    static final String VERIFIER_SCOPE = "mtc-wallet-provider/wallet.verifier.authorize";

    @Bean
    JwtDecoder mtcLabJwtDecoder(
        @Value("${wallet.cognito.issuer-uri:}") String issuer,
        @Value("${MTC_LAB_LOCAL_ONLY:false}") boolean privateLab,
        @Value("${wallet-provider.portal.enabled:false}") boolean portalEnabled,
        @Value("${wallet-provider.portal.client-ids:}") String portalClientIds,
        @Value("${server.address:}") String bindAddress,
        @Value("${MTC_LAB_CERTIFY_M2M_ENABLED:false}") boolean m2m,
        @Value("${wallet-provider.identity.certify-m2m.enabled:false}") boolean endpointEnabled,
        @Value("${wallet-provider.identity.certify-m2m.client-ids:}") String m2mClientIds,
        @Value("${MTC_LAB_VERIFIER_M2M_ENABLED:false}") boolean verifier,
        @Value("${wallet-provider.verifier-m2m.enabled:false}") boolean verifierEndpoint,
        @Value("${wallet-provider.verifier-m2m.client-ids:}") String verifierClients) {
        if (!privateLab || !portalEnabled || !LAB_ISSUER.equals(issuer) ||
            !LAB_CLIENT.equals(portalClientIds) || !"127.0.0.1".equals(bindAddress)) {
            throw new IllegalStateException("Disposable local lab JWT configuration is not isolated");
        }

        if (m2m != endpointEnabled || (m2m && !M2M_CLIENT.equals(m2mClientIds))) {
            throw new IllegalStateException("Disposable M2M configuration mismatch");
        }
        if (verifier != verifierEndpoint || (verifier && !VERIFIER_CLIENT.equals(verifierClients))) {
            throw new IllegalStateException("Disposable verifier M2M configuration mismatch");
        }
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(LAB_JWKS)
            .jwsAlgorithm(SignatureAlgorithm.RS256)
            .build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
            JwtValidators.createDefaultWithIssuer(LAB_ISSUER), labAccessValidator(m2m, verifier)));
        return decoder;
    }

    static OAuth2TokenValidator<Jwt> labAccessValidator() {
        return labAccessValidator(false);
    }

    static OAuth2TokenValidator<Jwt> labAccessValidator(boolean m2m) {
        return labAccessValidator(m2m, false);
    }

    static OAuth2TokenValidator<Jwt> labAccessValidator(boolean m2m, boolean verifier) {
        return jwt -> {
            String scope = jwt.getClaimAsString("scope");
            boolean allowed = "access".equals(jwt.getClaimAsString("token_use"))
                && LAB_CLIENT.equals(jwt.getClaimAsString("client_id"))
                && jwt.getAudience().contains(LAB_AUDIENCE)
                && scope != null && Arrays.asList(scope.split("\\s+")).contains(LAB_SCOPE);
            boolean machine = m2m && "access".equals(jwt.getClaimAsString("token_use"))
                && M2M_CLIENT.equals(jwt.getClaimAsString("client_id"))
                && java.util.List.of(M2M_AUDIENCE).equals(jwt.getAudience())
                && M2M_CLIENT.equals(jwt.getSubject()) && M2M_SCOPE.equals(scope)
                && jwt.getIssuedAt() != null && jwt.getExpiresAt() != null
                && jwt.getExpiresAt().isAfter(jwt.getIssuedAt())
                && !jwt.getExpiresAt().isAfter(jwt.getIssuedAt().plusSeconds(300));
            boolean verifierMachine = verifier && "access".equals(jwt.getClaimAsString("token_use"))
                && VERIFIER_CLIENT.equals(jwt.getClaimAsString("client_id"))
                && java.util.List.of(VERIFIER_CLIENT).equals(jwt.getAudience())
                && VERIFIER_CLIENT.equals(jwt.getSubject()) && VERIFIER_SCOPE.equals(scope)
                && jwt.getIssuedAt() != null && jwt.getExpiresAt() != null
                && jwt.getExpiresAt().isAfter(jwt.getIssuedAt())
                && !jwt.getExpiresAt().isAfter(jwt.getIssuedAt().plusSeconds(300));
            return (allowed || machine || verifierMachine)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token", "Lab portal access token required", null));
        };
    }
}
