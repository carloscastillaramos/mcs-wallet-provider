package pe.gob.mtc.walletprovider.platform;

import org.bouncycastle.asn1.*;
import org.springframework.stereotype.Component;
import pe.gob.mtc.walletprovider.config.ProviderProperties;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.util.*;

@Component
public class AndroidKeyAttestationVerifier {
    private static final String ATTESTATION_OID="1.3.6.1.4.1.11129.2.1.17";
    private final ProviderProperties config;
    public AndroidKeyAttestationVerifier(ProviderProperties config) { this.config=config; }
    public String verify(List<String> chain,String nonce,PublicKey expectedKey) throws Exception {
        if(chain==null || chain.size()<2 || chain.size()>8) throw new SecurityException("Key attestation certificate chain missing");
        CertificateFactory factory=CertificateFactory.getInstance("X.509");
        List<X509Certificate> certs=new ArrayList<>();
        for(String value:chain) certs.add((X509Certificate)factory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(value))));
        X509Certificate leaf=certs.get(0);
        if(!MessageDigest.isEqual(leaf.getPublicKey().getEncoded(),expectedKey.getEncoded()))
            throw new SecurityException("Attested public key differs from enrolled key");
        String rootsPath=config.android().keyAttestationRoots();
        if(rootsPath==null || rootsPath.isBlank()) throw new SecurityException("Attestation roots missing");
        Collection<? extends java.security.cert.Certificate> rootCertificates;
        try(InputStream in=new FileInputStream(rootsPath)) { rootCertificates=factory.generateCertificates(in); }
        if(rootCertificates.isEmpty()) throw new SecurityException("No trusted attestation roots");
        Set<TrustAnchor> anchors=new HashSet<>();
        for(var c:rootCertificates) anchors.add(new TrustAnchor((X509Certificate)c,null));
        List<X509Certificate> pathCerts=new ArrayList<>(certs);
        if(anchors.stream().anyMatch(a->a.getTrustedCert().equals(pathCerts.get(pathCerts.size()-1)))) pathCerts.remove(pathCerts.size()-1);
        CertPath path=factory.generateCertPath(pathCerts);
        PKIXParameters params=new PKIXParameters(anchors);
        params.setRevocationEnabled(false); // CRL/OCSP unavailable here: rotate root bundle and use Play verdict too.
        CertPathValidator.getInstance("PKIX").validate(path,params);
        byte[] extension=leaf.getExtensionValue(ATTESTATION_OID);
        if(extension==null) throw new SecurityException("Android Key Attestation extension not found");
        ASN1OctetString outer=ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(extension));
        ASN1Sequence description=ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(outer.getOctets()));
        if(description.size()<8) throw new SecurityException("Invalid Android key attestation ASN.1");
        int securityLevel=ASN1Enumerated.getInstance(description.getObjectAt(1)).getValue().intValueExact();
        int keymasterLevel=ASN1Enumerated.getInstance(description.getObjectAt(3)).getValue().intValueExact();
        String actualNonce=new String(ASN1OctetString.getInstance(description.getObjectAt(4)).getOctets(),StandardCharsets.UTF_8);
        if(!nonce.equals(actualNonce)) throw new SecurityException("Key attestation challenge mismatch");
        if(securityLevel<1 || keymasterLevel<1) throw new SecurityException("Key attestation is software-backed");
        // Keymaster authorization lists are index 6 (software) and 7 (hardware).
        // rootOfTrust [704] MUST be in the hardware-enforced authorization list.
        ASN1Sequence hardware=ASN1Sequence.getInstance(description.getObjectAt(7));
        ASN1Sequence rootOfTrust=null;
        for(ASN1Encodable entry:hardware) {
            if(entry instanceof ASN1TaggedObject tagged && tagged.getTagNo()==704) {
                rootOfTrust=ASN1Sequence.getInstance(tagged.getBaseObject());
                break;
            }
        }
        if(rootOfTrust==null || rootOfTrust.size()<3) throw new SecurityException("Verified boot proof missing");
        boolean bootLocked=ASN1Boolean.getInstance(rootOfTrust.getObjectAt(1)).isTrue();
        int bootState=ASN1Enumerated.getInstance(rootOfTrust.getObjectAt(2)).getValue().intValueExact();
        if(!bootLocked || bootState!=0) throw new SecurityException("Bootloader unlocked or boot not verified");
        return securityLevel==2 ? "ANDROID_STRONGBOX" : "ANDROID_TEE";
    }
}
