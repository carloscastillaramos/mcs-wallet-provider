package pe.gob.mtc.walletprovider.identity;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class MimotoIdentityM2mControllerTest {
    private static final UUID SESSION = UUID.fromString("c3de0eab-2409-494a-b4ad-6b0f749df580");
    private static final String INSTALL = "58d30b2d-e2ce-4dcc-b91a-720c270365c7";
    private static final String NONCE = "A".repeat(43);
    private static final String THUMB = "B".repeat(43);

    @Test void startRequiresInstallationKeyBeforeCreatingProviderSession() {
        var binding = mock(HolderInstallationBindingVerifier.class);
        var identity = mock(IdentityAccreditationService.class);
        var end = Instant.now().plusSeconds(600);
        when(identity.beginForProvenInstallation(INSTALL))
            .thenReturn(new IdentityAccreditationService.Started(SESSION, NONCE, end));
        var result = new MimotoIdentityM2mController(binding, identity)
            .start(new MimotoIdentityM2mController.StartRequest(INSTALL, THUMB));
        assertEquals(201, result.getStatusCode().value());
        assertNotNull(result.getBody());
        assertEquals(SESSION, result.getBody().sessionId());
        assertEquals(NONCE, result.getBody().nonce());
        var sequence = inOrder(binding, identity);
        sequence.verify(binding).verifyActiveInstallationForStart(INSTALL, THUMB);
        sequence.verify(identity).beginForProvenInstallation(INSTALL);
    }
    @Test void startRejectsWrongKeyBeforeCreatingSession() {
        var binding = mock(HolderInstallationBindingVerifier.class);
        var identity = mock(IdentityAccreditationService.class);
        doThrow(new SecurityException("wrong key"))
            .when(binding).verifyActiveInstallationForStart(INSTALL, THUMB);
        assertThrows(SecurityException.class, () ->
            new MimotoIdentityM2mController(binding, identity)
                .start(new MimotoIdentityM2mController.StartRequest(INSTALL, THUMB)));
        verifyNoInteractions(identity);
    }

    @Test void verifyDelegatesAndReturnsNoContent() {
        var binding = mock(HolderInstallationBindingVerifier.class);
        var identity = mock(IdentityAccreditationService.class);
        var controller = new MimotoIdentityM2mController(binding, identity);
        var response = controller.verifyBinding(new MimotoIdentityM2mController.BindingRequest(SESSION, INSTALL, NONCE, THUMB));
        assertEquals(204, response.getStatusCode().value());
        verify(binding).verifyPendingSession(SESSION, INSTALL, NONCE, THUMB);
        verifyNoInteractions(identity);
    }
    @Test void completeRechecksBindingAndUsesTrustedService() {
        var binding = mock(HolderInstallationBindingVerifier.class);
        var identity = mock(IdentityAccreditationService.class);
        when(identity.completeFromTrustedEvidence(SESSION, NONCE, "signed-opaque-evidence"))
            .thenReturn(new IdentityAccreditationService.Completed(INSTALL, UUID.randomUUID(), Instant.now()));
        var response = new MimotoIdentityM2mController(binding, identity).complete(
            new MimotoIdentityM2mController.CompletionRequest(SESSION, INSTALL, NONCE, THUMB, "signed-opaque-evidence"));
        assertEquals(204, response.getStatusCode().value());
        var ordered = inOrder(binding, identity);
        ordered.verify(binding).verifyPendingSession(SESSION, INSTALL, NONCE, THUMB);
        ordered.verify(identity).completeFromTrustedEvidence(SESSION, NONCE, "signed-opaque-evidence");
    }
    @Test void badBindingPreventsIdentityConsumption() {
        var binding = mock(HolderInstallationBindingVerifier.class);
        var identity = mock(IdentityAccreditationService.class);
        doThrow(new SecurityException("binding denied"))
            .when(binding).verifyPendingSession(SESSION, INSTALL, NONCE, THUMB);
        var controller = new MimotoIdentityM2mController(binding, identity);
        assertThrows(SecurityException.class, () -> controller.complete(
            new MimotoIdentityM2mController.CompletionRequest(SESSION, INSTALL, NONCE, THUMB, "signed-opaque-evidence")));
        verifyNoInteractions(identity);
    }
    @Test void invalidEvidenceFromAccreditationServicePropagates() {
        var binding = mock(HolderInstallationBindingVerifier.class);
        var identity = mock(IdentityAccreditationService.class);
        doThrow(new SecurityException("invalid evidence"))
            .when(identity).completeFromTrustedEvidence(SESSION, NONCE, "invalid");
        var controller = new MimotoIdentityM2mController(binding, identity);
        assertThrows(SecurityException.class, () -> controller.complete(
            new MimotoIdentityM2mController.CompletionRequest(SESSION, INSTALL, NONCE, THUMB, "invalid")));
    }
}
