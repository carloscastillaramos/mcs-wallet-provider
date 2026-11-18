package pe.gob.mtc.walletprovider.security;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.springframework.stereotype.Component;

@Component
public class ProofVerifier {
    public PublicKey decodePem(String pem) throws GeneralSecurityException {
        String b64=pem.replace("-----BEGIN PUBLIC KEY-----","").replace("-----END PUBLIC KEY-----","").replaceAll("\\s","");
        byte[] bytes=Base64.getDecoder().decode(b64);
        PublicKey key=KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(bytes));
        if(!(key instanceof ECPublicKey ec) || ec.getParams().getCurve().getField().getFieldSize()!=256)
            throw new GeneralSecurityException("Expected EC P-256 public key");
        return key;
    }
    public void verify(PublicKey key,String message,String signatureB64) throws GeneralSecurityException {
        Signature verifier=Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(key);
        verifier.update(message.getBytes(StandardCharsets.UTF_8));
        if(!verifier.verify(Base64.getUrlDecoder().decode(signatureB64)))
            throw new GeneralSecurityException("Invalid proof of possession");
    }
    public String pem(PublicKey key) {
        return "-----BEGIN PUBLIC KEY-----\n"+Base64.getMimeEncoder(64,new byte[]{'\n'}).encodeToString(key.getEncoded())+"\n-----END PUBLIC KEY-----";
    }
}
