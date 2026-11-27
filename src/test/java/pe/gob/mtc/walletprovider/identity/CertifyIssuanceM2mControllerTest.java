package pe.gob.mtc.walletprovider.identity;

import jakarta.validation.Validation;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CertifyIssuanceM2mControllerTest {
    private final CredentialKeyBindingRegistry registry=mock(CredentialKeyBindingRegistry.class);
    private final CertifyIssuanceM2mController controller=new CertifyIssuanceM2mController(registry);
    private final CertifyIssuanceM2mController.AuthorizeRequest request=
        new CertifyIssuanceM2mController.AuthorizeRequest("A".repeat(43),"issuer-secret-nonce");

    @Test void returnsOnly204OnActiveAccreditedBinding() {
        when(registry.activeAccreditedBinding(request.credentialKeyThumbprint(),request.issuerNonce())).thenReturn(true);
        var response=controller.authorize(request);
        assertEquals(204,response.getStatusCode().value());
        assertNull(response.getBody());
        assertTrue(response.getHeaders().getCacheControl().contains("no-store"));
        verify(registry).activeAccreditedBinding("A".repeat(43),"issuer-secret-nonce");
    }
    @Test void deniesUnregisteredOrRevokedBinding() {
        var error=assertThrows(ResponseStatusException.class,()->controller.authorize(request));
        assertEquals(HttpStatus.FORBIDDEN,error.getStatusCode());
    }
    @Test void databaseErrorNeverAllows() {
        when(registry.activeAccreditedBinding(anyString(),anyString()))
            .thenThrow(new IllegalStateException("DB unavailable"));
        assertThrows(IllegalStateException.class,()->controller.authorize(request));
    }
    @Test void invalidThumbprintRejectedByRequestValidation() {
        try(var factory=Validation.buildDefaultValidatorFactory()) {
            var invalid=new CertifyIssuanceM2mController.AuthorizeRequest("not-a-proof-key","nonce");
            assertFalse(factory.getValidator().validate(invalid).isEmpty());
        }
        verifyNoInteractions(registry);
    }
    @Test void missingOrOversizedNonceRejectedByValidation() {
        try(var factory=Validation.buildDefaultValidatorFactory()) {
            assertFalse(factory.getValidator().validate(
                new CertifyIssuanceM2mController.AuthorizeRequest("A".repeat(43)," ")).isEmpty());
            assertFalse(factory.getValidator().validate(
                new CertifyIssuanceM2mController.AuthorizeRequest("A".repeat(43),"b".repeat(1025))).isEmpty());
        }
        verifyNoInteractions(registry);
    }
}
