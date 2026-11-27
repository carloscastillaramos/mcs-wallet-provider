package pe.gob.mtc.walletprovider.institutional;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.server.ResponseStatusException;
import java.util.Set;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class MtcDualControlRolesTest {
    @Test void registradorDoesNotHaveApprovalPrivilege() {
        var actor = new MtcOperatorAccess.Operator(UUID.randomUUID(), "https://issuer", "registrador",
            Set.of(MtcOperatorAccess.REGISTRADOR));
        assertTrue(actor.canRegister());
        assertFalse(actor.canApprove());
        assertFalse(actor.isSuperAdmin());
    }
    @Test void aprobadorDoesNotHaveRegistrationPrivilege() {
        var actor = new MtcOperatorAccess.Operator(UUID.randomUUID(), "https://issuer", "aprobador",
            Set.of(MtcOperatorAccess.APROBADOR));
        assertFalse(actor.canRegister());
        assertTrue(actor.canApprove());
    }
    @Test void oneUserCanAccumulateBothRoles() {
        var actor = new MtcOperatorAccess.Operator(UUID.randomUUID(), "https://issuer", "ambos",
            Set.of(MtcOperatorAccess.REGISTRADOR, MtcOperatorAccess.APROBADOR));
        assertTrue(actor.canRegister());
        assertTrue(actor.canApprove());
        assertFalse(actor.isSuperAdmin());
    }
    @Test void superAdminHasBothPrivileges() {
        var actor = new MtcOperatorAccess.Operator(UUID.randomUUID(), "https://issuer", "admin",
            Set.of(MtcOperatorAccess.SUPER_ADMIN));
        assertTrue(actor.canRegister());
        assertTrue(actor.canApprove());
        assertTrue(actor.isSuperAdmin());
    }
    @Test void anonymousStillRejectedBeforeDatabaseQuery() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        var access = new MtcOperatorAccess(jdbc);
        assertThrows(ResponseStatusException.class, () -> access.requireRegister(null));
        assertThrows(ResponseStatusException.class, () -> access.requireApprove(null));
        verifyNoInteractions(jdbc);
    }
}
