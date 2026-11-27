package pe.gob.mtc.walletprovider.identity;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.Base64;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/** No datasource, Docker, RENIEC or network; verifies feature boundaries. */
class HolderIdentityCryptoConfigurationTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
        .withUserConfiguration(HolderIdentityCryptoConfig.class, IdentityAccreditationConfig.class);

    private static String key(int n) {
        byte[] bytes = new byte[32];
        Arrays.fill(bytes, (byte)n);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private ApplicationContextRunner withTestKeys() {
        return runner.withPropertyValues(
            "wallet-provider.identity.hmac-key-b64=" + key(17),
            "wallet-provider.identity.encryption-key-b64=" + key(29),
            "wallet-provider.identity.key-version=1");
    }

    @Test
    void portalOnlyRegistersCryptoButNeverIdentityAccreditationOrReniecVerifier() {
        withTestKeys().withPropertyValues(
            "wallet-provider.portal.enabled=true", "wallet-provider.identity.enabled=false")
            .run(context -> {
                assertNull(context.getStartupFailure());
                assertEquals(1, context.getBeansOfType(HolderIdentityCrypto.class).size());
                assertTrue(context.getBeansOfType(TrustedReniecEvidenceVerifier.class).isEmpty());
                assertTrue(context.getBeansOfType(IdentityAccreditationService.class).isEmpty());
            });
    }

    @Test
    void disabledFeaturesDoNotRequireKeysOrExposeCryptoBean() {
        runner.withPropertyValues(
            "wallet-provider.portal.enabled=false", "wallet-provider.identity.enabled=false")
            .run(context -> {
                assertNull(context.getStartupFailure());
                assertTrue(context.getBeansOfType(HolderIdentityCrypto.class).isEmpty());
            });
    }

    @Test
    void portalEnabledWithoutKeysMustFailClosed() {
        runner.withPropertyValues(
            "wallet-provider.portal.enabled=true", "wallet-provider.identity.enabled=false")
            .run(context -> assertNotNull(context.getStartupFailure()));
    }

    @Test
    void portalEnabledWithEqualKeysMustFailClosed() {
        runner.withPropertyValues(
            "wallet-provider.portal.enabled=true", "wallet-provider.identity.enabled=false",
            "wallet-provider.identity.hmac-key-b64=" + key(17),
            "wallet-provider.identity.encryption-key-b64=" + key(17))
            .run(context -> assertNotNull(context.getStartupFailure()));
    }
}
