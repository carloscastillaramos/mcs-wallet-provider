package pe.gob.mtc.walletprovider.config;

import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.test.util.ReflectionTestUtils;
import static org.junit.jupiter.api.Assertions.*;

/** Contratos de autorización Cognito sin red, sin claves reales y sin activar Cognito. */
class CognitoAuthorizationContractTest {
    private SecurityConfig config;

    @BeforeEach
    void setUp() {
        config = new SecurityConfig();
        ReflectionTestUtils.setField(config, "cognitoEnabled", true);
        ReflectionTestUtils.setField(config, "trustClientIds", "trust-client-qa");
        ReflectionTestUtils.setField(config, "adminClientIds", "admin-client-qa");
    }

    @Test
    void mapsOnlyRecognizedNamespacedTrustAndAdminScopes() {
        var converter = converter();
        var trust = converter.convert(jwt("trust-client-qa", "mtc-wallet-provider/wallet.trust.read"));
        assertNotNull(trust);
        assertTrue(hasAuthority(trust, "SCOPE_wallet.trust.read"));
        assertFalse(hasAuthority(trust, "SCOPE_wallet.admin"));

        var admin = converter.convert(jwt("admin-client-qa", "mtc-wallet-provider/wallet.admin"));
        assertNotNull(admin);
        assertTrue(hasAuthority(admin, "SCOPE_wallet.admin"));
        assertFalse(hasAuthority(admin, "SCOPE_wallet.trust.read"));
    }

    @Test
    void unknownOrOtherResourceServerScopesDoNotBecomeMtcAuthorities() {
        var auth = converter().convert(jwt("trust-client-qa",
            "other-resource/wallet.admin mtc-wallet-provider/nonexistent"));
        assertNotNull(auth);
        assertFalse(hasAuthority(auth, "SCOPE_wallet.admin"));
        assertFalse(hasAuthority(auth, "SCOPE_wallet.trust.read"));
    }

    @Test
    void matchingScopeAndAllowlistedClientAreBothRequired() {
        var correct = new JwtAuthenticationToken(
            jwt("trust-client-qa", "mtc-wallet-provider/wallet.trust.read"),
            Set.of(new SimpleGrantedAuthority("SCOPE_wallet.trust.read")));
        assertTrue(allowed("SCOPE_wallet.trust.read", "trust-client-qa", correct));
        assertFalse(allowed("SCOPE_wallet.trust.read", "another-client", correct));
        assertFalse(allowed("SCOPE_wallet.trust.read", "", correct));

        var wrongClient = new JwtAuthenticationToken(
            jwt("unknown-client", "mtc-wallet-provider/wallet.trust.read"),
            Set.of(new SimpleGrantedAuthority("SCOPE_wallet.trust.read")));
        assertFalse(allowed("SCOPE_wallet.trust.read", "trust-client-qa", wrongClient));

        var wrongScope = new JwtAuthenticationToken(
            jwt("trust-client-qa", "mtc-wallet-provider/wallet.admin"),
            Set.of(new SimpleGrantedAuthority("SCOPE_wallet.admin")));
        assertFalse(allowed("SCOPE_wallet.trust.read", "trust-client-qa", wrongScope));
    }

    @Test
    void nonJwtAuthenticatedPrincipalsCannotBypassCognitoMode() {
        var principal = new UsernamePasswordAuthenticationToken("test-user", "not-a-secret",
            Set.of(new SimpleGrantedAuthority("SCOPE_wallet.admin")));
        assertFalse(allowed("SCOPE_wallet.admin", "admin-client-qa", principal));
    }

    @Test
    void invalidCognitoIssuerFailsClosedBeforeNetworkAccess() {
        var cognito = new CognitoJwtConfig();
        assertThrows(IllegalStateException.class,
            () -> cognito.cognitoJwtDecoder("http://cognito-idp.us-east-1.amazonaws.com/us-east-1_qa"));
        assertThrows(IllegalStateException.class,
            () -> cognito.cognitoJwtDecoder("https://example.com/us-east-1_qa"));
        assertThrows(IllegalStateException.class,
            () -> cognito.cognitoJwtDecoder(""));
    }

    private JwtAuthenticationConverter converter() {
        JwtAuthenticationConverter converter = ReflectionTestUtils.invokeMethod(config, "cognitoScopes");
        assertNotNull(converter);
        return converter;
    }

    @SuppressWarnings("unchecked")
    private boolean allowed(String scope, String clients, Authentication auth) {
        AuthorizationManager<RequestAuthorizationContext> manager =
            ReflectionTestUtils.invokeMethod(config, "scopeAndClient", scope, clients);
        assertNotNull(manager);
        var decision = manager.check(() -> auth,
            new RequestAuthorizationContext(new MockHttpServletRequest("GET", "/api/v1/installations/x/trust")));
        assertNotNull(decision);
        return decision.isGranted();
    }

    private static boolean hasAuthority(Authentication authentication, String authority) {
        return authentication.getAuthorities().stream().anyMatch(a -> authority.equals(a.getAuthority()));
    }

    private static Jwt jwt(String clientId, String scope) {
        return Jwt.withTokenValue("synthetic-not-signed")
            .header("alg", "RS256")
            .issuedAt(Instant.parse("2026-11-24T00:00:00Z"))
            .expiresAt(Instant.parse("2026-11-24T01:00:00Z"))
            .claim("iss", "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_qa")
            .claim("token_use", "access")
            .claim("client_id", clientId)
            .claim("scope", scope)
            .build();
    }
}
