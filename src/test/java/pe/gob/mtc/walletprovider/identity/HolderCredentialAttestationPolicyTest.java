package pe.gob.mtc.walletprovider.identity;

import org.junit.jupiter.api.Test;
import pe.gob.mtc.walletprovider.domain.Installation;
import pe.gob.mtc.walletprovider.security.ProofVerifier;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class HolderCredentialAttestationPolicyTest {
    private final HolderIdentityStatusService status=mock(HolderIdentityStatusService.class);
    private final ProofVerifier proof=new ProofVerifier();

    private HolderCredentialAttestationPolicy policy(boolean required, boolean enabled) {
        return new HolderCredentialAttestationPolicy(status, proof, required, enabled);
    }

    private Installation installation() throws Exception {
        KeyPairGenerator generator=KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keys=generator.generateKeyPair();
        return new Installation("29eecbc3-5553-43ca-ae1d-b99197d20c99", "ANDROID",
            "device-key",proof.pem(keys.getPublic()),"ANDROID_TEE","example.test",0);
    }

    private HolderIdentityStatusService.Status value(HolderIdentityStatusService.State state, boolean allowed) {
        return new HolderIdentityStatusService.Status(state,allowed,Instant.now());
    }

    @Test void disabledPolicyDoesNotReadIdentityDatabase() throws Exception {
        var policy=policy(false,false);
        policy.assertSafeConfiguration();
        policy.requireAccredited(installation());
        verifyNoInteractions(status);
    }

    @Test void disabledPolicyAllowsTechnicalEnrollmentWithoutHolder() {
        assertDoesNotThrow(() -> policy(false,false).requireAccredited(null));
        verifyNoInteractions(status);
    }

    @Test void enabledEnforcementWithoutIdentityInfrastructureFailsStartup() {
        assertThrows(IllegalStateException.class, () -> policy(true,false).assertSafeConfiguration());
    }

    @Test void accreditedWithMatchingTrustedInstallationKeyPasses() throws Exception {
        when(status.get(anyString(),anyString()))
            .thenReturn(value(HolderIdentityStatusService.State.ACCREDITED,true));
        policy(true,true).requireAccredited(installation());
        verify(status).get(eq("29eecbc3-5553-43ca-ae1d-b99197d20c99"),matches("[A-Za-z0-9_-]{43}"));
    }

    @Test void cannotPassWithInconsistentAccreditedBoolean() throws Exception {
        when(status.get(anyString(),anyString()))
            .thenReturn(value(HolderIdentityStatusService.State.ACCREDITED,false));
        assertThrows(SecurityException.class, () -> policy(true,true).requireAccredited(installation()));
    }

    @Test void requiresKnownIdentityState() throws Exception {
        when(status.get(anyString(),anyString()))
            .thenReturn(value(HolderIdentityStatusService.State.IDENTITY_REQUIRED,false));
        assertThrows(SecurityException.class, () -> policy(true,true).requireAccredited(installation()));
    }

    @Test void rejectsPendingSession() throws Exception {
        when(status.get(anyString(),anyString()))
            .thenReturn(value(HolderIdentityStatusService.State.IDENTITY_PENDING,false));
        assertThrows(SecurityException.class, () -> policy(true,true).requireAccredited(installation()));
    }

    @Test void rejectsRevokedInstallationState() throws Exception {
        var installation=installation();
        installation.status="REVOKED";
        assertThrows(SecurityException.class, () -> policy(true,true).requireAccredited(installation));
        verifyNoInteractions(status);
    }

    @Test void rejectsBlockedHolder() throws Exception {
        when(status.get(anyString(),anyString()))
            .thenReturn(value(HolderIdentityStatusService.State.IDENTITY_BLOCKED,false));
        assertThrows(SecurityException.class, () -> policy(true,true).requireAccredited(installation()));
    }

    @Test void rejectsInactiveInstallationFromDatabase() throws Exception {
        when(status.get(anyString(),anyString()))
            .thenReturn(value(HolderIdentityStatusService.State.INSTALLATION_INACTIVE,false));
        assertThrows(SecurityException.class, () -> policy(true,true).requireAccredited(installation()));
    }

    @Test void rejectsMissingStatus() throws Exception {
        assertThrows(SecurityException.class, () -> policy(true,true).requireAccredited(installation()));
    }

    @Test void rejectsStatusDatabaseFailureWithoutFailingOpen() throws Exception {
        when(status.get(anyString(),anyString())).thenThrow(new IllegalStateException("database unavailable"));
        assertThrows(SecurityException.class, () -> policy(true,true).requireAccredited(installation()));
    }

    @Test void rejectsUnparseableStoredKeyWithoutConsultingDatabase() throws Exception {
        var installation=installation();
        installation.publicKey="not-a-valid-pem";
        assertThrows(SecurityException.class, () -> policy(true,true).requireAccredited(installation));
        verifyNoInteractions(status);
    }

    @Test void rejectsNullInstallationWhenEnabled() {
        assertThrows(SecurityException.class, () -> policy(true,true).requireAccredited(null));
        verifyNoInteractions(status);
    }

    @Test void invalidProductionConfigurationIsDeniedAtRequestTimeAlso() throws Exception {
        assertThrows(SecurityException.class, () -> policy(true,false).requireAccredited(installation()));
        verifyNoInteractions(status);
    }
}
