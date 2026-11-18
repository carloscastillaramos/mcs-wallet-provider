package pe.gob.mtc.walletprovider.sync;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

@Component
@ConditionalOnProperty(prefix="wallet-provider.diagnostics-sync",name="enabled",havingValue="true")
public class DiagnosticsSyncWorker {
    private static final Logger log=LoggerFactory.getLogger(DiagnosticsSyncWorker.class);
    private final DiagnosticsOutbox outbox;
    private final DiagnosticsSyncProperties props;
    private final RestClient client;
    private String token;
    private Instant tokenExpiry=Instant.EPOCH;
    public record TokenResponse(@JsonProperty("access_token") String accessToken,
                                @JsonProperty("expires_in") Long expiresIn) {}

    public DiagnosticsSyncWorker(DiagnosticsOutbox outbox,DiagnosticsSyncProperties props) {
        this.outbox=outbox;this.props=props;
        URI base=URI.create(required(props.baseUrl(),"baseUrl"));
        URI issuer=URI.create(required(props.tokenUrl(),"tokenUrl"));
        verifyUrl(base,props.allowHttpInMesh());
        verifyUrl(issuer,props.allowHttpInMesh());
        required(props.clientId(),"clientId");required(props.clientSecret(),"clientSecret");
        var factory=new JdkClientHttpRequestFactory(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build());
        factory.setReadTimeout(Duration.ofSeconds(4));
        client=RestClient.builder().requestFactory(factory).build();
    }
    private static String required(String v,String name) {
        if(v==null || v.isBlank()) throw new IllegalArgumentException("Missing diagnostics sync "+name);
        return v;
    }
    private static void verifyUrl(URI uri,boolean allowMeshHttp) {
        if(uri.getHost()==null || uri.getUserInfo()!=null || uri.getFragment()!=null ||
            !("https".equalsIgnoreCase(uri.getScheme()) || (allowMeshHttp && "http".equalsIgnoreCase(uri.getScheme()))))
            throw new IllegalArgumentException("Diagnostics URLs require HTTPS (or explicit Istio mTLS HTTP opt-in)");
    }
    private synchronized String accessToken() {
        if(token!=null && tokenExpiry.isAfter(Instant.now().plusSeconds(30))) return token;
        // OAuth2 client_credentials. Client secret never travels to Diagnostics.
        var form=new LinkedMultiValueMap<String,String>();
        form.add("grant_type","client_credentials");
        form.add("scope","diagnostics.device.sync");
        TokenResponse result=client.post().uri(props.tokenUrl())
                .headers(h->h.setBasicAuth(props.clientId(),props.clientSecret()))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve().body(TokenResponse.class);
        if(result==null || result.accessToken()==null || result.accessToken().isBlank() ||
                result.expiresIn()==null || result.expiresIn()<1)
            throw new IllegalStateException("Identity provider did not issue a valid access token");
        token=result.accessToken();tokenExpiry=Instant.now().plusSeconds(result.expiresIn());
        return token;
    }
    @Scheduled(fixedDelayString="${WALLET_DIAG_SYNC_INTERVAL_MS:5000}",initialDelayString="${WALLET_DIAG_SYNC_INITIAL_DELAY_MS:5000}")
    public void syncPending() {
        for(var work:outbox.claim(3)) {
            try {
                String url=props.baseUrl().replaceAll("/+$", "")
                    +"/api/v1/internal/devices/"+work.installationId()+"/keys/"+work.keyId();
                if("REGISTER".equals(work.action())) {
                    client.put().uri(url).headers(h->h.setBearerAuth(accessToken()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(Map.of("platform",work.platform(),"publicKeySpkiBase64",work.spki()))
                        .retrieve().toBodilessEntity();
                } else {
                    client.delete().uri(url).headers(h->h.setBearerAuth(accessToken()))
                        .retrieve().toBodilessEntity();
                }
                outbox.complete(work);
            } catch(Exception failure) {
                // Never print credentials, payloads, tokens, exception messages or URLs.
                log.warn("DIAGNOSTICS_SYNC_RETRY action={} outboxId={} attempt={} httpStatus={}",
                    work.action(),work.id(),work.attempts(),
                    failure instanceof RestClientResponseException ex ? ex.getStatusCode().value() : "TRANSPORT");
                outbox.retry(work);
            }
        }
    }
}
