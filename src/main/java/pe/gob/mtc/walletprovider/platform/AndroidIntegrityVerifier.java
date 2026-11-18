package pe.gob.mtc.walletprovider.platform;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auth.oauth2.GoogleCredentials;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import pe.gob.mtc.walletprovider.config.ProviderProperties;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

@Component
public class AndroidIntegrityVerifier {
    private final ProviderProperties config;
    private final RestClient client=RestClient.create();
    private final ObjectMapper mapper;
    public AndroidIntegrityVerifier(ProviderProperties config,ObjectMapper mapper) { this.config=config; this.mapper=mapper; }

    /** Standard Play Integrity requestHash: BASE64URL(SHA-256(exact UTF-8 message)). */
    public static String requestHash(String challengeId,String nonce,String keyId,String pem) {
        try {
            byte[] keyHash=MessageDigest.getInstance("SHA-256").digest(pem.getBytes(StandardCharsets.UTF_8));
            String message="wp-enroll:"+challengeId+":"+nonce+":"+keyId+":"+
                Base64.getUrlEncoder().withoutPadding().encodeToString(keyHash);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(message.getBytes(StandardCharsets.UTF_8)));
        } catch(Exception e) { throw new IllegalStateException(e); }
    }
    public void verify(String token,String requestHash) throws Exception {
        var p=config.android();
        if(p.packageName()==null || p.packageName().isBlank() || p.certificateSha256()==null || p.certificateSha256().isBlank()
                || p.cloudProjectNumber()==null || p.cloudProjectNumber().isBlank())
            throw new SecurityException("Play Integrity settings incomplete");
        GoogleCredentials credentials=GoogleCredentials.getApplicationDefault()
            .createScoped("https://www.googleapis.com/auth/playintegrity");
        credentials.refreshIfExpired();
        if(credentials.getAccessToken()==null) credentials.refresh();
        String endpoint="https://playintegrity.googleapis.com/v1/"+p.packageName()+":decodeIntegrityToken";
        String json=client.post().uri(endpoint)
            .header(HttpHeaders.AUTHORIZATION,"Bearer "+credentials.getAccessToken().getTokenValue())
            .contentType(MediaType.APPLICATION_JSON).body(Map.of("integrity_token",token))
            .retrieve().body(String.class);
        JsonNode payload=mapper.readTree(json).path("tokenPayloadExternal");
        JsonNode request=payload.path("requestDetails");
        JsonNode app=payload.path("appIntegrity");
        JsonNode device=payload.path("deviceIntegrity").path("deviceRecognitionVerdict");
        if(!requestHash.equals(request.path("requestHash").asText()) || !p.packageName().equals(request.path("requestPackageName").asText()))
            throw new SecurityException("Integrity token request binding invalid");
        long timestamp=request.path("timestampMillis").asLong(0);
        long now=System.currentTimeMillis();
        if(timestamp<=0 || timestamp>now+30_000 || now-timestamp>config.policy().maximumEvidenceAgeSeconds()*1000)
            throw new SecurityException("Integrity verdict expired");
        if(!"PLAY_RECOGNIZED".equals(app.path("appRecognitionVerdict").asText()) ||
                !p.packageName().equals(app.path("packageName").asText()))
            throw new SecurityException("Unrecognized Android application");
        boolean expectedCert=false;
        for(JsonNode digest:app.path("certificateSha256Digest")) {
            if(p.certificateSha256().equals(digest.asText())) expectedCert=true;
        }
        if(!expectedCert) throw new SecurityException("Unexpected APK signing certificate");
        boolean integrity=false;
        for(JsonNode label:device) if("MEETS_DEVICE_INTEGRITY".equals(label.asText()) || "MEETS_STRONG_INTEGRITY".equals(label.asText())) integrity=true;
        if(!integrity) throw new SecurityException("Android device integrity insufficient");
    }
}
