package pe.gob.mtc.walletprovider.sync;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix="wallet-provider.diagnostics-sync")
public record DiagnosticsSyncProperties(boolean enabled,String baseUrl,String tokenUrl,
                                       String clientId,String clientSecret,String scope,boolean allowHttpInMesh) {}
