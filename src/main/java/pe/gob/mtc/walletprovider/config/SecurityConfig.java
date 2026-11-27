package pe.gob.mtc.walletprovider.config;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

@Configuration
public class SecurityConfig {
    private static final String SCOPE_PREFIX = "mtc-wallet-provider/";

    @Value("${wallet.cognito.enabled:false}")
    private boolean cognitoEnabled;
    @Value("${wallet.cognito.trust-client-ids:}")
    private String trustClientIds;
    @Value("${wallet.cognito.admin-client-ids:}")
    private String adminClientIds;
    @Value("${wallet-provider.identity.enabled:false}")
    private boolean identityEnabled;
    @Value("${wallet-provider.identity.mimoto-m2m.enabled:false}")
    private boolean mimotoM2mEnabled;
    @Value("${wallet-provider.identity.mimoto-m2m.client-ids:}")
    private String mimotoM2mClientIds;

    // Exclusive client_credentials identity for Certify issuance authorization.
    @Value("${wallet-provider.identity.certify-m2m.enabled:false}")
    private boolean certifyM2mEnabled;
    @Value("${wallet-provider.identity.certify-m2m.client-ids:}")
    private String certifyM2mClientIds;
    @Value("${wallet-provider.identity.credential-binding.enabled:false}")
    private boolean credentialBindingEnabled;
    @Value("${WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED:false}")
    private boolean credentialAttestationRequired;

    @Value("${wallet-provider.verifier-m2m.enabled:false}")
    private boolean verifierM2mEnabled;
    @Value("${wallet-provider.verifier-m2m.client-ids:}")
    private String verifierM2mClientIds;
    @Value("${wallet-provider.portal.enabled:false}")
    private boolean portalEnabled;
    @Value("${wallet-provider.portal.origins:}")
    private String portalOrigins;
    @Value("${wallet-provider.portal.client-ids:}")
    private String portalClientIds;

    /** Never use wildcard browser origins with institutional bearer credentials. */
    // Spring Security .cors(withDefaults()) discovers the bean by this exact name.
    // Keep portal-only paths and pinned HTTPS origins; do not enable wildcard CORS.
    @Bean("corsConfigurationSource")
    @ConditionalOnProperty(prefix = "wallet-provider.portal", name = "enabled", havingValue = "true")
    CorsConfigurationSource portalCors() {
        Set<String> origins = parseClientIds(portalOrigins);
        if (origins.isEmpty() || origins.stream().anyMatch(
                origin -> !origin.matches("https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?"))) {
            throw new IllegalStateException("Portal CORS origins must be pinned HTTPS hosts");
        }
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(origins.stream().toList());
        config.setAllowedMethods(java.util.List.of("GET", "POST", "PUT", "OPTIONS"));
        config.setAllowedHeaders(java.util.List.of("Authorization", "Content-Type", "Idempotency-Key"));
        config.setAllowCredentials(false);
        config.setMaxAge(600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/v1/mtc/portal/**", config);
        return source;
    }

    @Bean
    SecurityFilterChain security(HttpSecurity http) throws Exception {
        return http.csrf(csrf -> csrf.disable()).cors(Customizer.withDefaults())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(a -> a
                .requestMatchers("/actuator/health/**", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/api/v1/.well-known/jwks.json").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/v1/enrollments/challenge", "/api/v1/enrollments/android", "/api/v1/enrollments/ios").permitAll()
                // Public binding still requires its two independent cryptographic proofs and one-time challenge.
                .requestMatchers(HttpMethod.POST, "/api/v1/installations/*/diagnostics-keys").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/v1/installations/*/trust")
                    .access(scopeAndClient("SCOPE_wallet.trust.read", trustClientIds))
                .requestMatchers(HttpMethod.POST, "/api/v1/installations/*/revoke")
                    .access(scopeAndClient("SCOPE_wallet.admin", adminClientIds))
                .requestMatchers(HttpMethod.POST, "/api/v1/attestations/wallet/android", "/api/v1/attestations/wallet/ios",
                    "/api/v1/attestations/keys/android", "/api/v1/attestations/keys/ios",
                    "/api/v1/attestations/credential-keys/android").permitAll()
                // Solo MiMoto con JWT access de Cognito, scope dedicado y client_id allowlisted.
                // Nunca heredar la excepcion legacy cuando Cognito se encuentra deshabilitado.
                .requestMatchers(HttpMethod.POST,
                    "/api/v1/internal/identity/mimoto/start",
                    "/api/v1/internal/identity/mimoto/status",
                    "/api/v1/internal/identity/mimoto/verifier-eligible",
                    "/api/v1/internal/identity/mimoto/verify-binding",
                    "/api/v1/internal/identity/mimoto/complete")
                    .access(mimotoIdentityM2m())
                // Separate Cognito scope and app-client from MiMoto and human operators.
                .requestMatchers(HttpMethod.POST,
                    "/api/v1/internal/identity/certify/authorize-issuance")
                    .access(certifyIssuanceM2m())
                .requestMatchers(HttpMethod.POST,
                    "/api/v1/internal/verifier/challenge", "/api/v1/internal/verifier/authorize")
                    .access(verifierM2m())
                // MTC-only operator portal: independent client and scopes; no external entity access.
                .requestMatchers("/api/v1/mtc/portal/**")
                    .access(portalAccess())
                .anyRequest().denyAll())
            .oauth2ResourceServer(o -> o.jwt(jwt -> {
                if (cognitoEnabled) jwt.jwtAuthenticationConverter(cognitoScopes());
            })).build();
    }

    /** Cognito mode requires both scope and a specific approved OAuth client (fail closed). */
    private AuthorizationManager<RequestAuthorizationContext> scopeAndClient(String authority, String permittedClientIds) {
        final Set<String> allowed = parseClientIds(permittedClientIds);
        return (authentication, context) -> {
            Authentication principal = authentication.get();
            if (principal == null || !principal.isAuthenticated() ||
                    principal.getAuthorities().stream().noneMatch(a -> authority.equals(a.getAuthority()))) {
                return new AuthorizationDecision(false);
            }
            if (!cognitoEnabled) return new AuthorizationDecision(true);
            if (!(principal instanceof JwtAuthenticationToken jwt) || allowed.isEmpty()) {
                return new AuthorizationDecision(false);
            }
            return new AuthorizationDecision(allowed.contains(jwt.getToken().getClaimAsString("client_id")));
        };
    }

    /** Esta autorizacion es siempre fail-closed, incluso con Cognito deshabilitado. */
    private AuthorizationManager<RequestAuthorizationContext> mimotoIdentityM2m() {
        final Set<String> allowed = parseClientIds(mimotoM2mClientIds);
        return (authentication, context) -> {
            if (!identityEnabled || !mimotoM2mEnabled || !cognitoEnabled || allowed.isEmpty()) {
                return new AuthorizationDecision(false);
            }
            Authentication principal = authentication.get();
            if (!(principal instanceof JwtAuthenticationToken jwt) || !principal.isAuthenticated()) {
                return new AuthorizationDecision(false);
            }
            Jwt token = jwt.getToken();
            boolean authorized = "access".equals(token.getClaimAsString("token_use"))
                && allowed.contains(token.getClaimAsString("client_id"))
                && principal.getAuthorities().stream().anyMatch(
                    a -> "SCOPE_wallet.identity.mimoto".equals(a.getAuthority()));
            return new AuthorizationDecision(authorized);
        };
    }

    /** Distinct from MiMoto: NO bearer token from the mobile app may authorize issuance. */
    private AuthorizationManager<RequestAuthorizationContext> certifyIssuanceM2m() {
        final Set<String> allowed = parseClientIds(certifyM2mClientIds);
        return (authentication, context) -> {
            if (!identityEnabled || !credentialBindingEnabled ||
                    !credentialAttestationRequired || !certifyM2mEnabled ||
                    !cognitoEnabled || allowed.isEmpty()) {
                return new AuthorizationDecision(false);
            }
            Authentication principal = authentication.get();
            if (!(principal instanceof JwtAuthenticationToken jwt) || !principal.isAuthenticated()) {
                return new AuthorizationDecision(false);
            }
            Jwt token = jwt.getToken();
            boolean authorized = "access".equals(token.getClaimAsString("token_use"))
                && allowed.contains(token.getClaimAsString("client_id"))
                && principal.getAuthorities().stream().anyMatch(
                    a -> "SCOPE_wallet.issuance.certify".equals(a.getAuthority()));
            return new AuthorizationDecision(authorized);
        };
    }

    private AuthorizationManager<RequestAuthorizationContext> verifierM2m() {
        final Set<String> allowed = parseClientIds(verifierM2mClientIds);
        return (authentication, context) -> {
            if (!identityEnabled || !verifierM2mEnabled || !cognitoEnabled || allowed.isEmpty())
                return new AuthorizationDecision(false);
            Authentication principal = authentication.get();
            if (!(principal instanceof JwtAuthenticationToken jwt) || !principal.isAuthenticated())
                return new AuthorizationDecision(false);
            Jwt token = jwt.getToken();
            return new AuthorizationDecision(
                "access".equals(token.getClaimAsString("token_use"))
                && allowed.contains(token.getClaimAsString("client_id"))
                && principal.getAuthorities().stream().anyMatch(a ->
                    "SCOPE_wallet.verifier.authorize".equals(a.getAuthority())));
        };
    }

    private AuthorizationManager<RequestAuthorizationContext> portalAccess() {
        final Set<String> allowed = parseClientIds(portalClientIds);
        return (authentication, context) -> {
            if (!portalEnabled || !cognitoEnabled || allowed.isEmpty()) return new AuthorizationDecision(false);
            Authentication principal = authentication.get();
            if (!(principal instanceof JwtAuthenticationToken jwt) || !principal.isAuthenticated())
                return new AuthorizationDecision(false);
            Jwt token = jwt.getToken();
            boolean hasScope = principal.getAuthorities().stream().anyMatch(
                a -> "SCOPE_wallet.portal".equals(a.getAuthority()));
            return new AuthorizationDecision(hasScope
                && "access".equals(token.getClaimAsString("token_use"))
                && allowed.contains(token.getClaimAsString("client_id")));
        };
    }

    private static Set<String> parseClientIds(String ids) {
        return Arrays.stream((ids == null ? "" : ids).split(",")).map(String::trim).filter(s -> !s.isBlank())
            .collect(Collectors.toUnmodifiableSet());
    }

    private JwtAuthenticationConverter cognitoScopes() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        JwtGrantedAuthoritiesConverter delegate = new JwtGrantedAuthoritiesConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            var result = new java.util.HashSet<GrantedAuthority>();
            result.addAll(delegate.convert(jwt));
            String raw = jwt.getClaimAsString("scope");
            if (raw == null) return result;
            for (String fullScope : raw.split("\\s+")) {
                if (fullScope.startsWith(SCOPE_PREFIX)) {
                    String suffix = fullScope.substring(SCOPE_PREFIX.length());
                    // Map only recognized MTC scopes, not arbitrary Cognito scopes.
                    if (Set.of("wallet.trust.read", "wallet.admin", "wallet.identity.mimoto", "wallet.issuance.certify", "wallet.portal", "wallet.verifier.authorize").contains(suffix)) {
                        result.add(new SimpleGrantedAuthority("SCOPE_" + suffix));
                    }
                }
            }
            return result;
        });
        return converter;
    }
}
