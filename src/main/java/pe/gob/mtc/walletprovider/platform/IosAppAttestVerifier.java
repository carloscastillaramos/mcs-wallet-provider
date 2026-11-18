package pe.gob.mtc.walletprovider.platform;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import org.bouncycastle.asn1.*;
import org.springframework.stereotype.Component;
import pe.gob.mtc.walletprovider.config.ProviderProperties;
import pe.gob.mtc.walletprovider.security.ProofVerifier;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.ECPublicKey;
import java.util.*;

@Component
public class IosAppAttestVerifier {
    private static final String NONCE_OID="1.2.840.113635.100.8.2";
    private final ProviderProperties config;
    private final ObjectMapper cbor=new ObjectMapper(new CBORFactory());
    private final ProofVerifier proof;
    public record VerifiedKey(String pem,long counter) {}
    public IosAppAttestVerifier(ProviderProperties config,ProofVerifier proof) { this.config=config;this.proof=proof; }

    public VerifiedKey verifyEnrollment(String encoded,String keyId,String challenge) throws Exception {
        String appId=config.ios().appId();
        if(appId==null || appId.isBlank()) throw new SecurityException("IOS_APP_ID not configured");
        JsonNode object=cbor.readTree(Base64.getDecoder().decode(encoded));
        if(!"apple-appattest".equals(object.path("fmt").asText())) throw new SecurityException("Unsupported App Attest format");
        JsonNode certificates=object.path("attStmt").path("x5c");
        if(!certificates.isArray() || certificates.size()<2 || certificates.size()>5) throw new SecurityException("App Attest certificate chain missing");
        CertificateFactory factory=CertificateFactory.getInstance("X.509");
        List<X509Certificate> chain=new ArrayList<>();
        for(JsonNode n:certificates) chain.add((X509Certificate)factory.generateCertificate(new ByteArrayInputStream(n.binaryValue())));
        Set<TrustAnchor> roots=new HashSet<>();
        try(InputStream in=new FileInputStream(config.ios().appAttestRoot())) {
            for(java.security.cert.Certificate c:factory.generateCertificates(in)) roots.add(new TrustAnchor((X509Certificate)c,null));
        }
        if(roots.isEmpty()) throw new SecurityException("Apple App Attest trust anchor missing");
        PKIXParameters params=new PKIXParameters(roots); params.setRevocationEnabled(false);
        CertPathValidator.getInstance("PKIX").validate(factory.generateCertPath(chain),params);
        byte[] authData=object.path("authData").binaryValue();
        if(authData==null || authData.length<55) throw new SecurityException("Invalid authenticator data");
        assertRpId(authData,appId);
        if((authData[32]&0x40)==0) throw new SecurityException("Attested credential data flag missing");
        long count=readCount(authData);
        if(count!=0) throw new SecurityException("Unexpected App Attest enrollment counter");
        String expectedAaguid=config.ios().production() ? "appattest\0\0\0\0\0\0\0" : "appattestdevelop";
        byte[] aaguid=Arrays.copyOfRange(authData,37,53);
        if(!MessageDigest.isEqual(aaguid,expectedAaguid.getBytes(StandardCharsets.UTF_8)))
            throw new SecurityException("Unexpected App Attest environment");
        int credentialLength=((authData[53]&255)<<8)|(authData[54]&255);
        if(credentialLength<1 || authData.length<=55+credentialLength)
            throw new SecurityException("Malformed credential identifier");
        byte[] credentialId=Arrays.copyOfRange(authData,55,55+credentialLength);
        if(!MessageDigest.isEqual(credentialId,Base64.getUrlDecoder().decode(keyId)))
            throw new SecurityException("App Attest credential identifier mismatch");
        PublicKey key=chain.get(0).getPublicKey();
        if(!(key instanceof ECPublicKey ec)) throw new SecurityException("App Attest key is not EC");
        byte[] rawPublic=uncompressed(ec);
        if(!MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(rawPublic),credentialId))
            throw new SecurityException("App Attest credential identifier not bound to public key");
        byte[] expectedNonce=digest(join(authData,digest(challenge.getBytes(StandardCharsets.UTF_8))));
        byte[] extension=chain.get(0).getExtensionValue(NONCE_OID);
        if(extension==null || !MessageDigest.isEqual(extractAppleNonce(extension),expectedNonce))
            throw new SecurityException("Apple nonce certificate extension invalid");
        return new VerifiedKey(proof.pem(key),count);
    }

    public long verifyAssertion(String encoded,String challenge,String pem,long previousCounter) throws Exception {
        JsonNode value=cbor.readTree(Base64.getDecoder().decode(encoded));
        byte[] authData=value.path("authenticatorData").binaryValue();
        byte[] signature=value.path("signature").binaryValue();
        if(authData==null || authData.length!=37 || signature==null) throw new SecurityException("Invalid App Attest assertion");
        assertRpId(authData,config.ios().appId());
        long counter=readCount(authData);
        if(counter<=previousCounter) throw new SecurityException("App Attest counter replay");
        Signature verifier=Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(proof.decodePem(pem));
        verifier.update(join(authData,digest(challenge.getBytes(StandardCharsets.UTF_8))));
        if(!verifier.verify(signature)) throw new SecurityException("Invalid App Attest assertion signature");
        return counter;
    }
    private void assertRpId(byte[] authData,String appId) throws Exception {
        if(!MessageDigest.isEqual(Arrays.copyOf(authData,32),digest(appId.getBytes(StandardCharsets.UTF_8))))
            throw new SecurityException("App Attest RP ID mismatch");
    }
    private static long readCount(byte[] authData) {
        return Integer.toUnsignedLong(ByteBuffer.wrap(authData,33,4).getInt());
    }
    private static byte[] digest(byte[] bytes) throws Exception {return MessageDigest.getInstance("SHA-256").digest(bytes);}
    private static byte[] join(byte[] a,byte[] b) {
        byte[] all=Arrays.copyOf(a,a.length+b.length);System.arraycopy(b,0,all,a.length,b.length);return all;
    }
    private static byte[] uncompressed(ECPublicKey key) {
        byte[] x=to32(key.getW().getAffineX().toByteArray()),y=to32(key.getW().getAffineY().toByteArray());
        byte[] out=new byte[65];out[0]=4;System.arraycopy(x,0,out,1,32);System.arraycopy(y,0,out,33,32);return out;
    }
    private static byte[] to32(byte[] n) {
        byte[] out=new byte[32];System.arraycopy(n,Math.max(0,n.length-32),out,32-Math.min(n.length,32),Math.min(n.length,32));return out;
    }
    private static byte[] extractAppleNonce(byte[] extension) throws Exception {
        ASN1Primitive outer=ASN1Primitive.fromByteArray(extension);
        ASN1Sequence seq=ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(outer).getOctets()));
        ASN1TaggedObject tagged=ASN1TaggedObject.getInstance(seq.getObjectAt(0));
        ASN1OctetString octet=ASN1OctetString.getInstance(tagged.getBaseObject());
        return octet.getOctets();
    }
}
