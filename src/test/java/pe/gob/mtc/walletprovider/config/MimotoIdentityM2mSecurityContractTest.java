package pe.gob.mtc.walletprovider.config;

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

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Pruebas sin llamadas a Cognito y sin tocar databases. */
class MimotoIdentityM2mSecurityContractTest {
    private SecurityConfig cfg;
    @BeforeEach void setUp() {
        cfg = new SecurityConfig();
        ReflectionTestUtils.setField(cfg, "identityEnabled", true);
        ReflectionTestUtils.setField(cfg, "mimotoM2mEnabled", true);
        ReflectionTestUtils.setField(cfg, "cognitoEnabled", true);
        ReflectionTestUtils.setField(cfg, "mimotoM2mClientIds", "mimoto-qa");
    }

    @Test void validClientScopeAndAccessTokenPass() {
        assertTrue(allow(jwtAuth("mimoto-qa", "mtc-wallet-provider/wallet.identity.mimoto", "access")));
    }
    @Test void otherClientDenied() {
        assertFalse(allow(jwtAuth("untrusted", "mtc-wallet-provider/wallet.identity.mimoto", "access")));
    }
    @Test void otherScopeDenied() {
        assertFalse(allow(jwtAuth("mimoto-qa", "mtc-wallet-provider/wallet.admin", "access")));
    }
    @Test void idTokenDeniedEvenIfScopePresent() {
        assertFalse(allow(jwtAuth("mimoto-qa", "mtc-wallet-provider/wallet.identity.mimoto", "id")));
    }
    @Test void disabledM2mDenied() {
        ReflectionTestUtils.setField(cfg, "mimotoM2mEnabled", false);
        assertFalse(allow(jwtAuth("mimoto-qa", "mtc-wallet-provider/wallet.identity.mimoto", "access")));
    }
    @Test void disabledIdentityDenied() {
        ReflectionTestUtils.setField(cfg, "identityEnabled", false);
        assertFalse(allow(jwtAuth("mimoto-qa", "mtc-wallet-provider/wallet.identity.mimoto", "access")));
    }
    @Test void cognitoOffAlwaysDenied() {
        ReflectionTestUtils.setField(cfg, "cognitoEnabled", false);
        assertFalse(allow(jwtAuth("mimoto-qa", "mtc-wallet-provider/wallet.identity.mimoto", "access")));
    }
    @Test void blankAllowlistDenied() {
        ReflectionTestUtils.setField(cfg, "mimotoM2mClientIds", " ");
        assertFalse(allow(jwtAuth("mimoto-qa", "mtc-wallet-provider/wallet.identity.mimoto", "access")));
    }
    @Test void nonJwtPrincipalDenied() {
        Authentication auth = new UsernamePasswordAuthenticationToken("fake", "none",
            Set.of(new SimpleGrantedAuthority("SCOPE_wallet.identity.mimoto")));
        assertFalse(allow(auth));
    }
    @Test void startUsesSameDedicatedM2mAuthorization() {
        assertTrue(allowPath(jwtAuth("mimoto-qa", "mtc-wallet-provider/wallet.identity.mimoto", "access"),
            "/api/v1/internal/identity/mimoto/start"));
        assertFalse(allowPath(jwtAuth("unknown", "mtc-wallet-provider/wallet.identity.mimoto", "access"),
            "/api/v1/internal/identity/mimoto/start"));
    }

    @Test void statusUsesSameDedicatedM2mAuthorization() {
        assertTrue(allowPath(jwtAuth("mimoto-qa", "mtc-wallet-provider/wallet.identity.mimoto", "access"),
            "/api/v1/internal/identity/mimoto/status"));
        assertFalse(allowPath(jwtAuth("unknown", "mtc-wallet-provider/wallet.identity.mimoto", "access"),
            "/api/v1/internal/identity/mimoto/status"));
        ReflectionTestUtils.setField(cfg, "cognitoEnabled", false);
        assertFalse(allowPath(jwtAuth("mimoto-qa", "mtc-wallet-provider/wallet.identity.mimoto", "access"),
            "/api/v1/internal/identity/mimoto/status"));
    }

    @Test void mapsOnlyDedicatedNamespaceScope() {
        JwtAuthenticationConverter converter = ReflectionTestUtils.invokeMethod(cfg, "cognitoScopes");
        assertNotNull(converter);
        var recognized = converter.convert(jwt("mimoto-qa", "mtc-wallet-provider/wallet.identity.mimoto", "access"));
        var foreign = converter.convert(jwt("mimoto-qa", "other-resource/wallet.identity.mimoto", "access"));
        assertTrue(recognized.getAuthorities().stream().anyMatch(a -> "SCOPE_wallet.identity.mimoto".equals(a.getAuthority())));
        assertFalse(foreign.getAuthorities().stream().anyMatch(a -> "SCOPE_wallet.identity.mimoto".equals(a.getAuthority())));
    }

    private boolean allow(Authentication auth) {
        AuthorizationManager<RequestAuthorizationContext> access =
            ReflectionTestUtils.invokeMethod(cfg, "mimotoIdentityM2m");
        assertNotNull(access);
        var result = access.check(() -> auth, new RequestAuthorizationContext(
            new MockHttpServletRequest("POST", "/api/v1/internal/identity/mimoto/complete")));
        assertNotNull(result);
        return result.isGranted();
    }
    private boolean allowPath(Authentication auth, String path) {
        AuthorizationManager<RequestAuthorizationContext> access =
            ReflectionTestUtils.invokeMethod(cfg, "mimotoIdentityM2m");
        assertNotNull(access);
        var result = access.check(() -> auth,
            new RequestAuthorizationContext(new MockHttpServletRequest("POST", path)));
        assertNotNull(result);
        return result.isGranted();
    }
    private Authentication jwtAuth(String clientId, String scope, String tokenUse) {
        JwtAuthenticationConverter converter = ReflectionTestUtils.invokeMethod(cfg, "cognitoScopes");
        return converter.convert(jwt(clientId, scope, tokenUse));
    }
    private static Jwt jwt(String clientId, String scope, String tokenUse) {
        return Jwt.withTokenValue("synthetic-test-not-signed")
            .header("alg", "RS256")
            .issuedAt(Instant.parse("2026-11-24T00:00:00Z"))
            .expiresAt(Instant.parse("2026-11-24T01:00:00Z"))
            .claim("iss", "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_qa")
            .claim("client_id", clientId)
            .claim("token_use", tokenUse)
            .claim("scope", scope)
            .build();
    }
}
