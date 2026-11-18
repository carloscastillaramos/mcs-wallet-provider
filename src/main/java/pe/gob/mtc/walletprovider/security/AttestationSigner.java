package pe.gob.mtc.walletprovider.security;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jwt.*;
import pe.gob.mtc.walletprovider.config.ProviderProperties;
import org.springframework.stereotype.Component;
import java.io.FileInputStream;
import java.security.*;
import java.security.interfaces.*;
import java.security.cert.Certificate;
import com.nimbusds.jose.util.Base64;
import java.time.Instant;
import java.util.*;

@Component
public class AttestationSigner {
    private final PrivateKey privateKey;
    private final JWK publicJwk;
    private final String issuer;
    private final String keyId;
    private final JWSAlgorithm algorithm;
    private final List<Base64> certificateChain;
    private final String walletClientId;

    public AttestationSigner(ProviderProperties config) throws Exception {
        var p=config.signing();
        if (p.password()==null || p.password().isBlank()) throw new IllegalStateException("SIGNING_KEYSTORE_PASSWORD required");
        KeyStore ks=KeyStore.getInstance("PKCS12");
        try(var input=new FileInputStream(p.keyStore())) { ks.load(input,p.password().toCharArray()); }
        Key key=ks.getKey(p.alias(),p.password().toCharArray());
        if (!(key instanceof PrivateKey pk)) throw new IllegalStateException("Signing alias must contain private key");
        Certificate cert=ks.getCertificate(p.alias());
        if (cert==null) throw new IllegalStateException("Signing certificate missing");
        this.privateKey=pk; this.keyId=p.keyId(); this.issuer=p.issuer(); this.walletClientId=p.walletClientId();
        this.certificateChain=new ArrayList<>();
        Certificate[] certs=ks.getCertificateChain(p.alias());
        if(certs!=null) for(int i=0;i<certs.length;i++) {
            if(i==certs.length-1 && certs[i] instanceof java.security.cert.X509Certificate x
                    && x.getSubjectX500Principal().equals(x.getIssuerX500Principal())) continue;
            certificateChain.add(Base64.encode(certs[i].getEncoded()));
        }
        if(pk instanceof RSAPrivateKey && cert.getPublicKey() instanceof RSAPublicKey rsa) {
            algorithm=JWSAlgorithm.RS256;
            publicJwk=new com.nimbusds.jose.jwk.RSAKey.Builder(rsa).keyID(keyId).algorithm(algorithm).keyUse(KeyUse.SIGNATURE).build();
        } else if(pk instanceof ECPrivateKey && cert.getPublicKey() instanceof ECPublicKey ec) {
            algorithm=JWSAlgorithm.ES256;
            publicJwk=new com.nimbusds.jose.jwk.ECKey.Builder(Curve.P_256,ec).keyID(keyId).algorithm(algorithm).keyUse(KeyUse.SIGNATURE).build();
        } else throw new IllegalStateException("Only RSA or P-256 signing keys supported");
    }
    public Map<String,Object> jwks() { return new JWKSet(publicJwk).toJSONObject(true); }
    private String sign(JWSObjectTypeAndClaims spec) {
        try {
            JWSHeader.Builder header=new JWSHeader.Builder(algorithm).type(new JOSEObjectType(spec.type())).keyID(keyId);
            if(!certificateChain.isEmpty()) header.x509CertChain(certificateChain);
            SignedJWT jwt=new SignedJWT(header.build(),spec.claims());
            if(algorithm.equals(JWSAlgorithm.RS256)) jwt.sign(new RSASSASigner((RSAPrivateKey)privateKey));
            else jwt.sign(new ECDSASigner((ECPrivateKey)privateKey));
            return jwt.serialize();
        } catch(Exception ex) { throw new IllegalStateException("Unable to sign attestation",ex); }
    }
    private record JWSObjectTypeAndClaims(String type,JWTClaimsSet claims) {}
    public String walletAttestation(PublicKey instanceKey,long seconds) {
        Instant now=Instant.now();
        try {
            if(walletClientId==null || walletClientId.isBlank()) throw new IllegalStateException("Wallet client ID not configured");
            if(!(instanceKey instanceof ECPublicKey ec)) throw new IllegalArgumentException("Expected P-256 installation key");
            var jwk=new com.nimbusds.jose.jwk.ECKey.Builder(Curve.P_256,ec).build().toPublicJWK().toJSONObject();
            JWTClaimsSet claims=new JWTClaimsSet.Builder().issuer(issuer).subject(walletClientId)
                .issueTime(Date.from(now)).notBeforeTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(seconds)))
                .claim("cnf",Map.of("jwk",jwk)).claim("wallet_name","Billetera MTC").build();
            return sign(new JWSObjectTypeAndClaims("oauth-client-attestation+jwt",claims));
        } catch(Exception e) { throw new IllegalStateException("Wallet Attestation failed",e); }
    }
    public String keyAttestation(PublicKey attestedKey,long seconds) {
        return keyAttestation(attestedKey,seconds,null);
    }
    /** Key attestation for an issuer-provided c_nonce, when present. */
    public String keyAttestation(PublicKey attestedKey,long seconds,String issuerNonce) {
        Instant now=Instant.now();
        if(!(attestedKey instanceof ECPublicKey ec)) throw new IllegalArgumentException("Expected P-256 key");
        // HAIP requires a certificate chain with a non-self-signed signer.
        if(certificateChain.isEmpty()) throw new IllegalStateException("Trusted institutional X.509 signing chain required");
        var jwk=new com.nimbusds.jose.jwk.ECKey.Builder(Curve.P_256,ec).build().toPublicJWK().toJSONObject();
        JWTClaimsSet.Builder claims=new JWTClaimsSet.Builder().issuer(issuer)
            .issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(seconds)))
            .claim("attested_keys",List.of(jwk));
        if(issuerNonce!=null && !issuerNonce.isBlank()) claims.claim("nonce",issuerNonce);
        return sign(new JWSObjectTypeAndClaims("key-attestation+jwt",claims.build()));
    }
    public String issue(String subject,String audience,String purpose,Map<String,Object> claims,long seconds) {
        try {
            Instant now=Instant.now();
            JWTClaimsSet.Builder builder=new JWTClaimsSet.Builder().issuer(issuer).subject(subject).audience(audience)
                .issueTime(Date.from(now)).notBeforeTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(seconds)))
                .jwtID(UUID.randomUUID().toString()).claim("purpose",purpose);
            claims.forEach(builder::claim);
            SignedJWT jwt=new SignedJWT(new JWSHeader.Builder(algorithm).type(JOSEObjectType.JWT).keyID(keyId).build(),builder.build());
            if(algorithm.equals(JWSAlgorithm.RS256)) jwt.sign(new RSASSASigner((RSAPrivateKey)privateKey));
            else jwt.sign(new ECDSASigner((ECPrivateKey)privateKey));
            return jwt.serialize();
        } catch(Exception ex) { throw new IllegalStateException("Unable to sign attestation",ex); }
    }
}
