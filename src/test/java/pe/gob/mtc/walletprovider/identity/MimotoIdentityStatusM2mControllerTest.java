package pe.gob.mtc.walletprovider.identity;

import org.junit.jupiter.api.Test;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class MimotoIdentityStatusM2mControllerTest {
    private static final String INSTALL = "2d37c660-9951-4a12-976e-d6a1cdac60e4";
    private static final String THUMB = "A".repeat(43);

    @Test void statusUsesOnlyBoundKeyAndDisablesCache() {
        var service = mock(HolderIdentityStatusService.class);
        var expected = new HolderIdentityStatusService.Status(
            HolderIdentityStatusService.State.ACCREDITED, true, Instant.now());
        when(service.get(INSTALL, THUMB)).thenReturn(expected);
        var controller = new MimotoIdentityStatusM2mController(service);
        var response = controller.status(new MimotoIdentityStatusM2mController.StatusRequest(INSTALL, THUMB));
        assertEquals(200, response.getStatusCode().value());
        assertEquals(expected, response.getBody());
        assertTrue(response.getHeaders().getCacheControl().contains("no-store"));
        verify(service).get(INSTALL, THUMB);
    }

    @Test void bindingErrorNeverReturnsFalsePositive() {
        var service = mock(HolderIdentityStatusService.class);
        doThrow(new SecurityException("binding denied")).when(service).get(INSTALL, THUMB);
        assertThrows(SecurityException.class, () -> new MimotoIdentityStatusM2mController(service)
            .status(new MimotoIdentityStatusM2mController.StatusRequest(INSTALL, THUMB)));
    }
}
