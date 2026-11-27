package pe.gob.mtc.walletprovider.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Offline-only context contract; no PostgreSQL, Spring network discovery or AWS. */
class MtcLabJwtConfigTest {
    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
            .withInitializer(ctx -> ctx.getEnvironment().setActiveProfiles("mtc-lab-v076"))
            .withUserConfiguration(CognitoJwtConfig.class, MtcLabJwtConfig.class)
            .withPropertyValues(
                "wallet.cognito.enabled=true",
                "wallet.cognito.issuer-uri=http://127.0.0.1:18090",
                "wallet-provider.portal.enabled=true",
                "wallet-provider.portal.client-ids=mtc-lab-portal",
                "server.address=127.0.0.1",
                "MTC_LAB_LOCAL_ONLY=true");
    }

    @Test void createsExactlyOneJwtDecoderWithExclusiveLabProfile() {
        runner().run(ctx -> {
            assertNull(ctx.getStartupFailure());
            assertEquals(1, ctx.getBeansOfType(JwtDecoder.class).size());
            assertTrue(ctx.containsBean("mtcLabJwtDecoder"));
            assertFalse(ctx.containsBean("cognitoJwtDecoder"));
        });
    }

    @Test void refusesMissingExplicitLabMarker() {
        runner().withPropertyValues("MTC_LAB_LOCAL_ONLY=false")
            .run(ctx -> assertNotNull(ctx.getStartupFailure()));
    }

    @Test void refusesExternalIssuer() {
        runner().withPropertyValues("wallet.cognito.issuer-uri=https://cognito-idp.us-east-1.amazonaws.com/us-east-1_prod")
            .run(ctx -> assertNotNull(ctx.getStartupFailure()));
    }

    @Test void refusesNonLoopbackServer() {
        runner().withPropertyValues("server.address=0.0.0.0")
            .run(ctx -> assertNotNull(ctx.getStartupFailure()));
    }

    @Test void refusesNonLabClient() {
        runner().withPropertyValues("wallet-provider.portal.client-ids=production-client")
            .run(ctx -> assertNotNull(ctx.getStartupFailure()));
    }

    @Test void refusesDisabledPortal() {
        runner().withPropertyValues("wallet-provider.portal.enabled=false")
            .run(ctx -> assertNotNull(ctx.getStartupFailure()));
    }

    @Test void normalLocalProfileKeepsInstitutionalIssuerRestriction() {
        new ApplicationContextRunner()
            .withInitializer(ctx -> ctx.getEnvironment().setActiveProfiles("local"))
            .withUserConfiguration(CognitoJwtConfig.class, MtcLabJwtConfig.class)
            .withPropertyValues("wallet.cognito.enabled=true", "wallet.cognito.issuer-uri=http://127.0.0.1:18090")
            .run(ctx -> assertNotNull(ctx.getStartupFailure()));
    }

    @Test void decodedClaimsMustBeLabPortalAccessOnly() {
        var validator=MtcLabJwtConfig.labAccessValidator();
        assertFalse(validator.validate(token("mtc-lab-portal", "access", "mtc-wallet-provider/wallet.portal", "mtc-lab-admin")).hasErrors());
        assertTrue(validator.validate(token("other", "access", "mtc-wallet-provider/wallet.portal", "mtc-lab-admin")).hasErrors());
        assertTrue(validator.validate(token("mtc-lab-portal", "id", "mtc-wallet-provider/wallet.portal", "mtc-lab-admin")).hasErrors());
        assertTrue(validator.validate(token("mtc-lab-portal", "access", "mtc-wallet-provider/wallet.admin", "mtc-lab-admin")).hasErrors());
        assertTrue(validator.validate(token("mtc-lab-portal", "access", "mtc-wallet-provider/wallet.portal", "other-audience")).hasErrors());
    }

    @Test void requiresIndependentExplicitM2mConfiguration() {
        runner().withPropertyValues("MTC_LAB_CERTIFY_M2M_ENABLED=true")
            .run(ctx -> assertNotNull(ctx.getStartupFailure()));
        runner().withPropertyValues("wallet-provider.identity.certify-m2m.enabled=true")
            .run(ctx -> assertNotNull(ctx.getStartupFailure()));
        runner().withPropertyValues("MTC_LAB_CERTIFY_M2M_ENABLED=true",
            "wallet-provider.identity.certify-m2m.enabled=true",
            "wallet-provider.identity.certify-m2m.client-ids=mtc-lab-portal")
            .run(ctx -> assertNotNull(ctx.getStartupFailure()));
        runner().withPropertyValues("MTC_LAB_CERTIFY_M2M_ENABLED=true",
            "wallet-provider.identity.certify-m2m.enabled=true",
            "wallet-provider.identity.certify-m2m.client-ids=mtc-lab-certify-m2m")
            .run(ctx -> assertNull(ctx.getStartupFailure()));
    }

    @Test void machineClaimsAreExactAndOptIn() {
        var client="mtc-lab-certify-m2m";
        var scope="mtc-wallet-provider/wallet.issuance.certify";
        var base=Instant.now();
        var valid=Jwt.withTokenValue("synthetic-only").header("alg","RS256").subject(client)
            .claim("iss","http://127.0.0.1:18090").claim("aud",List.of(client))
            .claim("client_id",client).claim("token_use","access").claim("scope",scope)
            .issuedAt(base).expiresAt(base.plusSeconds(120)).build();
        assertTrue(MtcLabJwtConfig.labAccessValidator().validate(valid).hasErrors());
        assertFalse(MtcLabJwtConfig.labAccessValidator(true).validate(valid).hasErrors());
        assertTrue(MtcLabJwtConfig.labAccessValidator(true).validate(token(client,"access",scope,client)).hasErrors());
        assertFalse(MtcLabJwtConfig.labAccessValidator(true).validate(token("mtc-lab-portal","access","mtc-wallet-provider/wallet.portal","mtc-lab-admin")).hasErrors());
    }

    @Test void verifierM2mRequiresIndependentOptInAndPinnedClient() {
        runner().withPropertyValues("MTC_LAB_VERIFIER_M2M_ENABLED=true")
            .run(ctx -> assertNotNull(ctx.getStartupFailure()));
        runner().withPropertyValues("wallet-provider.verifier-m2m.enabled=true")
            .run(ctx -> assertNotNull(ctx.getStartupFailure()));
        runner().withPropertyValues("MTC_LAB_VERIFIER_M2M_ENABLED=true",
            "wallet-provider.verifier-m2m.enabled=true",
            "wallet-provider.verifier-m2m.client-ids=other")
            .run(ctx -> assertNotNull(ctx.getStartupFailure()));
        runner().withPropertyValues("MTC_LAB_VERIFIER_M2M_ENABLED=true",
            "wallet-provider.verifier-m2m.enabled=true",
            "wallet-provider.verifier-m2m.client-ids=mtc-lab-verifier-m2m")
            .run(ctx -> assertNull(ctx.getStartupFailure()));
    }

    @Test void verifierM2mClaimsAreExactAndDoNotAuthorizeCertify() {
        String client="mtc-lab-verifier-m2m", scope="mtc-wallet-provider/wallet.verifier.authorize";
        Instant now=Instant.now();
        Jwt jwt=Jwt.withTokenValue("synthetic-only").header("alg","RS256").subject(client)
            .claim("iss","http://127.0.0.1:18090").claim("aud",List.of(client))
            .claim("client_id",client).claim("token_use","access").claim("scope",scope)
            .issuedAt(now).expiresAt(now.plusSeconds(120)).build();
        assertTrue(MtcLabJwtConfig.labAccessValidator(true,false).validate(jwt).hasErrors());
        assertFalse(MtcLabJwtConfig.labAccessValidator(false,true).validate(jwt).hasErrors());
        assertTrue(MtcLabJwtConfig.labAccessValidator(false,true).validate(token(client,"access",scope,client)).hasErrors());
    }

    private static Jwt token(String client, String use, String scope, String aud) {
        return Jwt.withTokenValue("synthetic-not-signed-never-accepted-by-decoder")
            .header("alg", "RS256")
            .claim("iss", "http://127.0.0.1:18090")
            .subject("mtc-lab-registrador")
            .claim("aud", List.of(aud))
            .issuedAt(Instant.parse("2026-11-25T00:00:00Z"))
            .expiresAt(Instant.parse("2026-11-26T00:00:00Z"))
            .claim("client_id", client)
            .claim("token_use", use)
            .claim("scope", scope)
            .build();
    }
}
