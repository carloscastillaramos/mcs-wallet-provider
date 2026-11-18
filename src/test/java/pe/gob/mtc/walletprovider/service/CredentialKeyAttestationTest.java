package pe.gob.mtc.walletprovider.service;

import org.junit.jupiter.api.Test;
import pe.gob.mtc.walletprovider.api.ApiModels.AndroidCredentialKeyAttestationRequest;
import pe.gob.mtc.walletprovider.config.ProviderProperties;
import pe.gob.mtc.walletprovider.domain.*;
import pe.gob.mtc.walletprovider.platform.*;
import pe.gob.mtc.walletprovider.security.*;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.time.OffsetDateTime;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CredentialKeyAttestationTest {
    @Test void attestsOnlyCredentialKeyAfterBothProofsAndHardwareAttestation() throws Exception {
        var fixture=new Fixture();
        var result=fixture.service.attestAndroidCredentialKey(fixture.request());
        assertEquals("credential-key-attestation",result.token());
        verify(fixture.androidKeys).verify(anyList(),eq("challenge-nonce"),eq(fixture.credential.getPublic()));
        verify(fixture.signer).keyAttestation(eq(fixture.credential.getPublic()),eq(300L),eq("issuer-c-nonce"));
        verify(fixture.audit).save(any(Audit.class));
    }

    @Test void rejectsCredentialKeyNotControlledByTheInstallation() throws Exception {
        var fixture=new Fixture();
        var correct=fixture.request();
        var wrong=new AndroidCredentialKeyAttestationRequest(correct.installationId(),correct.challengeId(),
            correct.credentialPublicKeyPem(),correct.credentialKeyAttestationChain(),correct.issuerNonce(),
            correct.installationProofSignature(),fixture.sign(fixture.installation,"tampered-message"));
        assertThrows(GeneralSecurityException.class,()->fixture.service.attestAndroidCredentialKey(wrong));
        verifyNoInteractions(fixture.androidKeys,fixture.signer);
    }

    @Test void rejectsHardwareKeyWithoutValidCertificateEvidence() throws Exception {
        var fixture=new Fixture();
        when(fixture.androidKeys.verify(anyList(),anyString(),any(PublicKey.class)))
            .thenThrow(new SecurityException("Key attestation certificate chain invalid"));
        assertThrows(SecurityException.class,()->fixture.service.attestAndroidCredentialKey(fixture.request()));
        verifyNoInteractions(fixture.signer);
    }

    private static class Fixture {
        final ChallengeRepository challenges=mock(ChallengeRepository.class);
        final InstallationRepository installations=mock(InstallationRepository.class);
        final AuditRepository audit=mock(AuditRepository.class);
        final AndroidKeyAttestationVerifier androidKeys=mock(AndroidKeyAttestationVerifier.class);
        final AttestationSigner signer=mock(AttestationSigner.class);
        final ProofVerifier proof=new ProofVerifier();
        final KeyPair installation=keyPair();
        final KeyPair credential=keyPair();
        final EnrollmentService service;
        Fixture() throws Exception {
            var entity=new Installation("installation-id","ANDROID","installation-key",proof.pem(installation.getPublic()),
                "ANDROID_TEE","example.test",0);
            when(installations.lockById("installation-id")).thenReturn(Optional.of(entity));
            when(challenges.lockById("challenge-id")).thenReturn(Optional.of(new Challenge("challenge-id","ANDROID",
                "challenge-nonce",OffsetDateTime.now().plusMinutes(3))));
            when(androidKeys.verify(anyList(),anyString(),any(PublicKey.class))).thenReturn("ANDROID_TEE");
            when(signer.keyAttestation(any(PublicKey.class),eq(300L),anyString())).thenReturn("credential-key-attestation");
            service=new EnrollmentService(challenges,installations,audit,new ProviderProperties(null,null,null,
                new ProviderProperties.Policy(180,300,120)),mock(AndroidIntegrityVerifier.class),androidKeys,
                mock(IosAppAttestVerifier.class),proof,signer,
                mock(DiagnosticsKeyRepository.class),mock(pe.gob.mtc.walletprovider.sync.DiagnosticsOutbox.class));
        }
        AndroidCredentialKeyAttestationRequest request() throws Exception {
            String pem=proof.pem(credential.getPublic());
            String keyHash=sha256Url(credential.getPublic().getEncoded());
            String nonceHash=sha256Url("issuer-c-nonce".getBytes(StandardCharsets.UTF_8));
            String message="wp-credential-key:v1:challenge-id:challenge-nonce:installation-id:"+keyHash+":"+nonceHash;
            return new AndroidCredentialKeyAttestationRequest("installation-id","challenge-id",pem,
                List.of("cert-chain-base64"),"issuer-c-nonce",sign(installation,message),sign(credential,message));
        }
        String sign(KeyPair pair,String message) throws Exception {
            Signature s=Signature.getInstance("SHA256withECDSA");
            s.initSign(pair.getPrivate());s.update(message.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(s.sign());
        }
        static String sha256Url(byte[] input) throws Exception {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(input));
        }
        static KeyPair keyPair() {
            try {KeyPairGenerator g=KeyPairGenerator.getInstance("EC");g.initialize(new ECGenParameterSpec("secp256r1"));return g.generateKeyPair();}
            catch(Exception e) {throw new IllegalStateException(e);}
        }
    }
}
