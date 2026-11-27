package pe.gob.mtc.walletprovider.institutional;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;
import java.time.LocalDate;
import static org.junit.jupiter.api.Assertions.*;

class MtcPortalAdministrationTest {
    @Test void invalidDniOrInstitutionCodeCannotBeGranted() {
        assertThrows(IllegalArgumentException.class, () -> MtcPortalAdministration.validate(
            new MtcPortalAdministration.CreateGrant("123", "AB", "OPER", LocalDate.now().plusDays(10))));
        assertThrows(ResponseStatusException.class, () -> MtcPortalAdministration.validate(
            new MtcPortalAdministration.CreateGrant("12345678", "BAD|CODE", "OPER", LocalDate.now().plusDays(10))));
    }
    @Test void pastOrExcessiveValidityIsRejected() {
        assertThrows(ResponseStatusException.class, () -> MtcPortalAdministration.validate(
            new MtcPortalAdministration.CreateGrant("12345678", "AB", "OPER", LocalDate.now().minusDays(1))));
        assertThrows(ResponseStatusException.class, () -> MtcPortalAdministration.validate(
            new MtcPortalAdministration.CreateGrant("12345678", "AB", "OPER", LocalDate.now().plusYears(3))));
    }
}
