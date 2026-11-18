package pe.gob.mtc.walletprovider.service;

import org.junit.jupiter.api.Test;
import pe.gob.mtc.walletprovider.api.ApiModels.DiagnosticsKeyBindingRequest;
import pe.gob.mtc.walletprovider.domain.*;
import pe.gob.mtc.walletprovider.platform.IosAppAttestVerifier;
import pe.gob.mtc.walletprovider.security.ProofVerifier;
import pe.gob.mtc.walletprovider.sync.DiagnosticsOutbox;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.time.OffsetDateTime;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class DiagnosticsKeyBindingServiceTest {
    private final InstallationRepository installations=mock(InstallationRepository.class);
    private final ChallengeRepository challenges=mock(ChallengeRepository.class);
    private final DiagnosticsKeyRepository keys=mock(DiagnosticsKeyRepository.class);
    private final AuditRepository audit=mock(AuditRepository.class);
    private final IosAppAttestVerifier apple=mock(IosAppAttestVerifier.class);
    private final DiagnosticsOutbox outbox=mock(DiagnosticsOutbox.class);
    private final ProofVerifier verifier=new ProofVerifier();
    private final DiagnosticsKeyBindingService service=new DiagnosticsKeyBindingService(
            installations,challenges,keys,audit,verifier,apple,outbox);

    @Test void validAndroidDualProofEnqueuesWithoutCallingDiagnostics() throws Exception {
        KeyPair installation=pair(), diagnostics=pair();
        var entity=new Installation("installation-uuid","ANDROID","installationKey",
                verifier.pem(installation.getPublic()),"TEE","pe.gob.mtc",0);
        when(installations.lockById(entity.id)).thenReturn(Optional.of(entity));
        var challenge=new Challenge("challenge-id","ANDROID","nonce",OffsetDateTime.now().plusMinutes(2));
        when(challenges.lockById(challenge.id)).thenReturn(Optional.of(challenge));
        String spki=Base64.getEncoder().encodeToString(diagnostics.getPublic().getEncoded());
        String digest=Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(diagnostics.getPublic().getEncoded()));
        String text="wp-diagnostics-bind:v1:installation-uuid:challenge-id:nonce:diagKey:"+digest;
        var response=service.bind(entity.id,new DiagnosticsKeyBindingRequest(challenge.id,"diagKey",spki,
                sign(diagnostics,text),sign(installation,text),null));
        assertEquals("PENDING_SYNC",response.syncStatus());
        assertNotNull(challenge.consumedAt);
        verify(keys).save(any(DiagnosticsKey.class));
        verify(outbox).enqueueRegister(entity.id,"diagKey","ANDROID",spki);
    }

    @Test void wrongInstallationProofNeverEnqueues() throws Exception {
        KeyPair installation=pair(), diagnostics=pair();
        var entity=new Installation("installation-uuid","ANDROID","installationKey",
                verifier.pem(installation.getPublic()),"TEE","pe.gob.mtc",0);
        when(installations.lockById(entity.id)).thenReturn(Optional.of(entity));
        when(challenges.lockById("challenge-id")).thenReturn(Optional.of(new Challenge("challenge-id","ANDROID",
                "nonce",OffsetDateTime.now().plusMinutes(2))));
        String spki=Base64.getEncoder().encodeToString(diagnostics.getPublic().getEncoded());
        String digest=Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(diagnostics.getPublic().getEncoded()));
        String msg="wp-diagnostics-bind:v1:installation-uuid:challenge-id:nonce:diagKey:"+digest;
        assertThrows(GeneralSecurityException.class,()->service.bind(entity.id,new DiagnosticsKeyBindingRequest(
                "challenge-id","diagKey",spki,sign(diagnostics,msg),sign(pair(),msg),null)));
        verifyNoInteractions(outbox);
    }

    @Test void iosUsesAppAttestAssertionAndCounterNotRawInstallationSignature() throws Exception {
        KeyPair install=pair(),diag=pair();
        var entity=new Installation("installation-uuid","IOS","appAttestKey",
                verifier.pem(install.getPublic()),"APPLE_APP_ATTEST","Team.bundle",2);
        when(installations.lockById(entity.id)).thenReturn(Optional.of(entity));
        when(challenges.lockById("challenge-id")).thenReturn(Optional.of(new Challenge("challenge-id","IOS",
                "nonce",OffsetDateTime.now().plusMinutes(2))));
        when(apple.verifyAssertion(anyString(),anyString(),anyString(),eq(2L))).thenReturn(3L);
        String spki=Base64.getEncoder().encodeToString(diag.getPublic().getEncoded());
        String digest=Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(diag.getPublic().getEncoded()));
        String msg="wp-diagnostics-bind:v1:installation-uuid:challenge-id:nonce:diagKey:"+digest;
        service.bind(entity.id,new DiagnosticsKeyBindingRequest("challenge-id","diagKey",spki,
                sign(diag,msg),null,"signed-app-attest-assertion"));
        verify(apple).verifyAssertion("signed-app-attest-assertion",msg,entity.publicKey,2L);
        assertEquals(3,entity.counterValue);
        verify(outbox).enqueueRegister(entity.id,"diagKey","IOS",spki);
    }

    private static KeyPair pair() throws Exception {
        var k=KeyPairGenerator.getInstance("EC"); k.initialize(new ECGenParameterSpec("secp256r1"));return k.generateKeyPair();
    }
    private static String sign(KeyPair p,String text) throws Exception {
        Signature signer=Signature.getInstance("SHA256withECDSA");signer.initSign(p.getPrivate());
        signer.update(text.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
    }
}
