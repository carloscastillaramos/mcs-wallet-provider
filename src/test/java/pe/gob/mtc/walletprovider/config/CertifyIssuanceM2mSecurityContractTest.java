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
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.test.util.ReflectionTestUtils;
import java.time.Instant;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class CertifyIssuanceM2mSecurityContractTest {
    private SecurityConfig config;
    @BeforeEach void setUp() {
        config = new SecurityConfig();
        set("cognitoEnabled",true);
        set("identityEnabled",true);
        set("credentialBindingEnabled",true);
        set("credentialAttestationRequired",true);
        set("certifyM2mEnabled",true);
        set("certifyM2mClientIds","certify-qa");
    }
    private void set(String field,Object value) { ReflectionTestUtils.setField(config,field,value); }
    @Test void dedicatedCertifyAccessTokenAllowed() { assertTrue(allow("certify-qa", "mtc-wallet-provider/wallet.issuance.certify", "access")); }
    @Test void wrongClientDenied() { assertFalse(allow("mimoto-qa", "mtc-wallet-provider/wallet.issuance.certify", "access")); }
    @Test void onlyMiMotoScopeDenied() { assertFalse(allow("certify-qa", "mtc-wallet-provider/wallet.identity.mimoto", "access")); }
    @Test void onlyAdminScopeDenied() { assertFalse(allow("certify-qa", "mtc-wallet-provider/wallet.admin", "access")); }
    @Test void foreignResourceServerScopeDenied() { assertFalse(allow("certify-qa", "other/wallet.issuance.certify", "access")); }
    @Test void idTokenDenied() { assertFalse(allow("certify-qa", "mtc-wallet-provider/wallet.issuance.certify", "id")); }
    @Test void disabledCognitoDenied() { set("cognitoEnabled",false); assertFalse(valid()); }
    @Test void disabledIdentityDenied() { set("identityEnabled",false); assertFalse(valid()); }
    @Test void disabledLedgerDenied() { set("credentialBindingEnabled",false); assertFalse(valid()); }
    @Test void disabledKeyAttestationDenied() { set("credentialAttestationRequired",false); assertFalse(valid()); }
    @Test void disabledM2mDenied() { set("certifyM2mEnabled",false); assertFalse(valid()); }
    @Test void noClientAllowlistDenied() { set("certifyM2mClientIds",""); assertFalse(valid()); }
    @Test void nonJwtAuthenticationDenied() {
        Authentication forged = new UsernamePasswordAuthenticationToken("forged", "password",
            Set.of(new SimpleGrantedAuthority("SCOPE_wallet.issuance.certify")));
        assertFalse(access(forged));
    }
    @Test void onlyRecognizesExactScopeNamespace() {
        JwtAuthenticationConverter converter=ReflectionTestUtils.invokeMethod(config,"cognitoScopes");
        assertNotNull(converter);
        var valid=converter.convert(jwt("certify-qa","mtc-wallet-provider/wallet.issuance.certify","access"));
        var other=converter.convert(jwt("certify-qa","other/wallet.issuance.certify","access"));
        assertTrue(valid.getAuthorities().stream().anyMatch(a -> "SCOPE_wallet.issuance.certify".equals(a.getAuthority())));
        assertFalse(other.getAuthorities().stream().anyMatch(a -> "SCOPE_wallet.issuance.certify".equals(a.getAuthority())));
    }
    @Test void mimotoAuthorizationCannotBeUsedForCertify() {
        set("mimotoM2mEnabled", true); set("mimotoM2mClientIds", "mimoto-qa");
        JwtAuthenticationConverter conv=ReflectionTestUtils.invokeMethod(config,"cognitoScopes");
        var principal=conv.convert(jwt("mimoto-qa","mtc-wallet-provider/wallet.identity.mimoto","access"));
        assertFalse(access(principal));
    }
    private boolean valid(){return allow("certify-qa","mtc-wallet-provider/wallet.issuance.certify","access");}
    private boolean allow(String client,String scope,String type){
        JwtAuthenticationConverter converter=ReflectionTestUtils.invokeMethod(config,"cognitoScopes");
        return access(converter.convert(jwt(client,scope,type)));
    }
    private boolean access(Authentication principal) {
        AuthorizationManager<RequestAuthorizationContext> manager=ReflectionTestUtils.invokeMethod(config,"certifyIssuanceM2m");
        assertNotNull(manager);
        var decision=manager.check(() -> principal,new RequestAuthorizationContext(
            new MockHttpServletRequest("POST","/api/v1/internal/identity/certify/authorize-issuance")));
        assertNotNull(decision);
        return decision.isGranted();
    }
    private static Jwt jwt(String client,String scope,String tokenUse){
        return Jwt.withTokenValue("test-only-unsigned").header("alg","RS256")
            .issuedAt(Instant.parse("2026-11-24T00:00:00Z"))
            .expiresAt(Instant.parse("2026-11-24T01:00:00Z"))
            .claim("iss","https://cognito-idp.us-east-1.amazonaws.com/us-east-1_qa")
            .claim("client_id",client).claim("scope",scope).claim("token_use",tokenUse).build();
    }
}
