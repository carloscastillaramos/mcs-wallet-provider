package pe.gob.mtc.walletprovider.service;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import pe.gob.mtc.walletprovider.api.ApiModels.ChallengeRequest;
import pe.gob.mtc.walletprovider.config.ProviderProperties;
import pe.gob.mtc.walletprovider.domain.*;
import pe.gob.mtc.walletprovider.identity.HolderCredentialAttestationPolicy;
import pe.gob.mtc.walletprovider.identity.CredentialKeyBindingRegistry;
import pe.gob.mtc.walletprovider.platform.*;
import pe.gob.mtc.walletprovider.security.*;
import java.time.OffsetDateTime;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class EnrollmentServiceTest {
    @Test void challengeIsRandomAndExpires() {
        var challenges=mock(ChallengeRepository.class);
        var service=new EnrollmentService(challenges,mock(InstallationRepository.class),mock(AuditRepository.class),
            new ProviderProperties(null,null,null,new ProviderProperties.Policy(180,300,120)),
            mock(AndroidIntegrityVerifier.class),mock(AndroidKeyAttestationVerifier.class),mock(IosAppAttestVerifier.class),
            mock(ProofVerifier.class),mock(AttestationSigner.class),
            mock(DiagnosticsKeyRepository.class),mock(pe.gob.mtc.walletprovider.sync.DiagnosticsOutbox.class),
            mock(HolderCredentialAttestationPolicy.class),mock(CredentialKeyBindingRegistry.class), mock(org.springframework.jdbc.core.JdbcTemplate.class));
        var a=service.challenge(new ChallengeRequest("android"));
        var b=service.challenge(new ChallengeRequest("ANDROID"));
        assertNotEquals(a.nonce(),b.nonce());
        assertNotEquals(a.challengeId(),b.challengeId());
        assertTrue(a.expiresAt().isAfter(OffsetDateTime.now()));
        ArgumentCaptor<Challenge> captor=ArgumentCaptor.forClass(Challenge.class);
        verify(challenges,times(2)).save(captor.capture());
        assertEquals("ANDROID",captor.getAllValues().get(0).platform);
    }
    @Test void rejectsUnsupportedPlatform() {
        var service=new EnrollmentService(mock(ChallengeRepository.class),mock(InstallationRepository.class),mock(AuditRepository.class),
            new ProviderProperties(null,null,null,new ProviderProperties.Policy(180,300,120)),
            mock(AndroidIntegrityVerifier.class),mock(AndroidKeyAttestationVerifier.class),mock(IosAppAttestVerifier.class),
            mock(ProofVerifier.class),mock(AttestationSigner.class),
            mock(DiagnosticsKeyRepository.class),mock(pe.gob.mtc.walletprovider.sync.DiagnosticsOutbox.class),
            mock(HolderCredentialAttestationPolicy.class),mock(CredentialKeyBindingRegistry.class), mock(org.springframework.jdbc.core.JdbcTemplate.class));
        assertThrows(IllegalArgumentException.class,()->service.challenge(new ChallengeRequest("WINDOWS")));
    }

    @Test void revokingInstallationEnqueuesRevocationsInSameTransaction() {
        var challenges=mock(ChallengeRepository.class);
        var installations=mock(InstallationRepository.class);
        var audit=mock(AuditRepository.class);
        var keys=mock(DiagnosticsKeyRepository.class);
        var outbox=mock(pe.gob.mtc.walletprovider.sync.DiagnosticsOutbox.class);
        var installation=new Installation("c31a1641-d7fa-4e22-bd4e-fc54b2f5ef49","ANDROID","installation-key",
            "public-key-pem","TEE","test",0);
        var first=new DiagnosticsKey(installation.id,"diagnosticsKey","spki");
        when(installations.lockById(installation.id)).thenReturn(Optional.of(installation));
        when(keys.findByInstallationIdAndStatus(installation.id,"ACTIVE")).thenReturn(List.of(first));
        var service=new EnrollmentService(challenges,installations,audit,
            new ProviderProperties(null,null,null,new ProviderProperties.Policy(180,300,120)),
            mock(AndroidIntegrityVerifier.class),mock(AndroidKeyAttestationVerifier.class),
            mock(IosAppAttestVerifier.class),mock(ProofVerifier.class),mock(AttestationSigner.class),keys,outbox,
            mock(HolderCredentialAttestationPolicy.class),mock(CredentialKeyBindingRegistry.class), mock(org.springframework.jdbc.core.JdbcTemplate.class));
        service.revoke(installation.id);
        assertEquals("REVOKED",installation.status);
        assertEquals("REVOKED",first.status);
        verify(outbox).enqueueRevoke(installation.id,"diagnosticsKey","ANDROID");
        service.revoke(installation.id);
        verify(outbox,times(1)).enqueueRevoke(anyString(),anyString(),anyString());
    }
}
