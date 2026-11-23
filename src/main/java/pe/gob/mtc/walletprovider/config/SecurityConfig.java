package pe.gob.mtc.walletprovider.config;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
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

    @Bean
    SecurityFilterChain security(HttpSecurity http) throws Exception {
        return http.csrf(csrf -> csrf.disable())
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

    private static Set<String> parseClientIds(String ids) {
        return Arrays.stream(ids.split(",")).map(String::trim).filter(s -> !s.isBlank())
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
                    if (Set.of("wallet.trust.read", "wallet.admin").contains(suffix)) {
                        result.add(new SimpleGrantedAuthority("SCOPE_" + suffix));
                    }
                }
            }
            return result;
        });
        return converter;
    }
}
