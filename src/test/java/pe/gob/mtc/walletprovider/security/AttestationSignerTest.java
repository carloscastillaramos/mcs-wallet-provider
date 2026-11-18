package pe.gob.mtc.walletprovider.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pe.gob.mtc.walletprovider.config.ProviderProperties;
import java.nio.file.Path;
import java.nio.file.Files;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class AttestationSignerTest {
    @TempDir Path temp;
    @Test void emitsTypedWalletAndKeyAttestationsWithoutUniqueWalletSubject() throws Exception {
        KeyPairGenerator rsaGen=KeyPairGenerator.getInstance("RSA");rsaGen.initialize(2048);
        KeyPair signing=rsaGen.generateKeyPair();
        KeyPair root=rsaGen.generateKeyPair();
        Date now=new Date();
        X500Name dn=new X500Name("CN=Test Wallet Provider");
        X500Name rootDn=new X500Name("CN=Test-Only Root CA");
        var rootBuilder=new JcaX509v3CertificateBuilder(rootDn,BigInteger.valueOf(19),
            new Date(now.getTime()-60_000),new Date(now.getTime()+3600_000),rootDn,root.getPublic());
        X509Certificate rootCert=new JcaX509CertificateConverter().getCertificate(rootBuilder.build(
            new JcaContentSignerBuilder("SHA256withRSA").build(root.getPrivate())));
        var builder=new JcaX509v3CertificateBuilder(rootDn,BigInteger.valueOf(17),
            new Date(now.getTime()-60_000),new Date(now.getTime()+3600_000),dn,signing.getPublic());
        X509Certificate cert=new JcaX509CertificateConverter().getCertificate(builder.build(
            new JcaContentSignerBuilder("SHA256withRSA").build(root.getPrivate())));
        KeyStore ks=KeyStore.getInstance("PKCS12");ks.load(null,"temporary-test-pass".toCharArray());
        ks.setKeyEntry("provider-current",signing.getPrivate(),"temporary-test-pass".toCharArray(),new java.security.cert.Certificate[]{cert,rootCert});
        Path path=temp.resolve("test-only.p12");
        try(var out=Files.newOutputStream(path)){ks.store(out,"temporary-test-pass".toCharArray());}
        var settings=new ProviderProperties(new ProviderProperties.Signing(path.toString(),"temporary-test-pass","provider-current",
            "test-kid","https://provider.example.test","https://wallet.example.test"),null,null,null);
        AttestationSigner signer=new AttestationSigner(settings);
        KeyPairGenerator ecGen=KeyPairGenerator.getInstance("EC");ecGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair deviceKey=ecGen.generateKeyPair();
        SignedJWT wallet=SignedJWT.parse(signer.walletAttestation(deviceKey.getPublic(),300));
        SignedJWT key=SignedJWT.parse(signer.keyAttestation(deviceKey.getPublic(),300,"issuer-nonce"));
        assertEquals("oauth-client-attestation+jwt",wallet.getHeader().getType().getType());
        assertEquals("key-attestation+jwt",key.getHeader().getType().getType());
        assertEquals("https://wallet.example.test",wallet.getJWTClaimsSet().getSubject());
        assertNotNull(wallet.getJWTClaimsSet().getJSONObjectClaim("cnf"));
        assertEquals(1,key.getJWTClaimsSet().getListClaim("attested_keys").size());
        assertEquals("issuer-nonce",key.getJWTClaimsSet().getStringClaim("nonce"));
        assertEquals(1,key.getHeader().getX509CertChain().size(),"x5c must omit trust anchor");
        assertTrue(wallet.verify(new RSASSAVerifier((java.security.interfaces.RSAPublicKey)signing.getPublic())));
        assertTrue(key.verify(new RSASSAVerifier((java.security.interfaces.RSAPublicKey)signing.getPublic())));
        assertEquals(JWSAlgorithm.RS256,key.getHeader().getAlgorithm());
    }
}
