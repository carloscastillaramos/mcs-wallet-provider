package pe.gob.mtc.walletprovider.identity;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.AnyNestedCondition;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ConfigurationCondition.ConfigurationPhase;

/**
 * DNI protection is shared by Portal MTC and the identity-accreditation flow.
 * It must be present when EITHER feature is enabled. Identity enrollment and
 * RENIEC evidence verification remain disabled unless identity.enabled=true.
 *
 * Missing/malformed keys deliberately prevent startup; no hardcoded defaults.
 */
@Configuration(proxyBeanMethods = false)
@Conditional(HolderIdentityCryptoConfig.CryptoRequired.class)
public class HolderIdentityCryptoConfig {

    @Bean
    HolderIdentityCrypto holderIdentityCrypto(
        @Value("${wallet-provider.identity.hmac-key-b64:}") String hmacKey,
        @Value("${wallet-provider.identity.encryption-key-b64:}") String encryptionKey,
        @Value("${wallet-provider.identity.key-version:1}") int keyVersion) {
        return new HolderIdentityCrypto(hmacKey, encryptionKey, keyVersion);
    }

    static class CryptoRequired extends AnyNestedCondition {
        CryptoRequired() {
            super(ConfigurationPhase.PARSE_CONFIGURATION);
        }

        @ConditionalOnProperty(prefix = "wallet-provider.portal", name = "enabled", havingValue = "true")
        static class PortalEnabled { }

        @ConditionalOnProperty(prefix = "wallet-provider.identity", name = "enabled", havingValue = "true")
        static class IdentityEnabled { }
    }
}
