package pe.gob.mtc.walletprovider.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "wallet-provider")
public record ProviderProperties(Signing signing, Android android, Ios ios, Policy policy) {
    public record Signing(String keyStore, String password, String alias, String keyId, String issuer, String walletClientId) {}
    public record Android(String packageName, String certificateSha256, String cloudProjectNumber, String keyAttestationRoots) {}
    public record Ios(String appId, String appAttestRoot, boolean production) {}
    public record Policy(long challengeSeconds, long attestationSeconds, long maximumEvidenceAgeSeconds) {}
}
