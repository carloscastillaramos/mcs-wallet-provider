package pe.gob.mtc.walletprovider.institutional;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.server.ResponseStatusException;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class MtcOperatorAccessTest {
    @Test void anonymousAndUnverifiedOperatorDeniedBeforeQuery() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        var service = new MtcOperatorAccess(jdbc);
        assertThrows(ResponseStatusException.class, () -> service.require(null));
        verifyNoInteractions(jdbc);
    }
}
