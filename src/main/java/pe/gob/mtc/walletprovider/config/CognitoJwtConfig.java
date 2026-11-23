package pe.gob.mtc.walletprovider.config;

import java.net.URI;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/** Active only when infrastructure has provisioned the institutional Cognito User Pool. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "wallet.cognito", name = "enabled", havingValue = "true")
public class CognitoJwtConfig {
    @Bean
    JwtDecoder cognitoJwtDecoder(@Value("${wallet.cognito.issuer-uri:}") String issuer) {
        if (issuer.isBlank() || !issuer.matches("https://cognito-idp\\.[A-Za-z0-9-]+\\.amazonaws\\.com(?:\\.cn)?/[A-Za-z0-9_-]+")) {
            throw new IllegalStateException("Wallet Provider Cognito issuer must be an HTTPS User Pool issuer");
        }
        String jwks = issuer + "/.well-known/jwks.json";
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwks).build();
        OAuth2TokenValidator<Jwt> accessOnly = jwt ->
            "access".equals(jwt.getClaimAsString("token_use")) &&
                jwt.getClaimAsString("client_id") != null &&
                !jwt.getClaimAsString("client_id").isBlank()
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Access token required", null));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
            JwtValidators.createDefaultWithIssuer(issuer), accessOnly));
        return decoder;
    }
}
