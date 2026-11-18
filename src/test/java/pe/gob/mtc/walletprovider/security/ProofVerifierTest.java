package pe.gob.mtc.walletprovider.security;

import org.junit.jupiter.api.Test;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import static org.junit.jupiter.api.Assertions.*;

class ProofVerifierTest {
    private final ProofVerifier verifier=new ProofVerifier();
    @Test void acceptsValidPossessionAndRejectsReplayDifferentChallenge() throws Exception {
        KeyPairGenerator generator=KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys=generator.generateKeyPair();
        String message="wp-enroll:challenge:nonce:key-id";
        Signature signer=Signature.getInstance("SHA256withECDSA");
        signer.initSign(keys.getPrivate());signer.update(message.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String signature=Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
        PublicKey decoded=verifier.decodePem(verifier.pem(keys.getPublic()));
        assertDoesNotThrow(()->verifier.verify(decoded,message,signature));
        assertThrows(GeneralSecurityException.class,()->verifier.verify(decoded,message+"-modified",signature));
    }
}
