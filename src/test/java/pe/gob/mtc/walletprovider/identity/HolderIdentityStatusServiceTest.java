package pe.gob.mtc.walletprovider.identity;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;

import java.sql.ResultSet;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class HolderIdentityStatusServiceTest {
    private static final String INSTALLATION = "2d37c660-9951-4a12-976e-d6a1cdac60e4";
    private static final String THUMB = "A".repeat(43);
    private static final String OTHER = "B".repeat(43);
    private static final Instant NOW = Instant.parse("2026-11-24T23:00:00Z");

    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final HolderInstallationBindingVerifier verifier = mock(HolderInstallationBindingVerifier.class);
    private final HolderIdentityStatusService service = new HolderIdentityStatusService(
        jdbc, verifier, Clock.fixed(NOW, ZoneOffset.UTC));

    @Test void accreditedInstallationUnlocksWallet() throws Exception {
        stub("ACTIVE", "ACTIVE", "COMPLETED", "HOLDER_ENROLLMENT", true, true, false);
        var status = service.get(INSTALLATION, THUMB);
        assertEquals(HolderIdentityStatusService.State.ACCREDITED, status.state());
        assertTrue(status.walletAccessAllowed());
        assertEquals(NOW, status.checkedAt());
    }

    @Test void noHolderRequiresAccreditation() throws Exception {
        stub("ACTIVE", null, null, null, false, false, false);
        var status = service.get(INSTALLATION, THUMB);
        assertEquals(HolderIdentityStatusService.State.IDENTITY_REQUIRED, status.state());
        assertFalse(status.walletAccessAllowed());
    }

    @Test void pendingBiometricsKeepsWalletBlocked() throws Exception {
        stub("ACTIVE", null, null, null, false, false, true);
        var status = service.get(INSTALLATION, THUMB);
        assertEquals(HolderIdentityStatusService.State.IDENTITY_PENDING, status.state());
        assertFalse(status.walletAccessAllowed());
    }

    @Test void revokedInstallationCannotUnlockEvenWithAccreditedHolder() throws Exception {
        stub("REVOKED", "ACTIVE", "COMPLETED", "HOLDER_ENROLLMENT", true, true, false);
        var status = service.get(INSTALLATION, THUMB);
        assertEquals(HolderIdentityStatusService.State.INSTALLATION_INACTIVE, status.state());
        assertFalse(status.walletAccessAllowed());
    }

    @Test void blockedIdentityCannotUnlock() throws Exception {
        stub("ACTIVE", "BLOCKED", "COMPLETED", "HOLDER_ENROLLMENT", true, true, false);
        assertEquals(HolderIdentityStatusService.State.IDENTITY_BLOCKED, service.get(INSTALLATION, THUMB).state());
        assertFalse(service.get(INSTALLATION, THUMB).walletAccessAllowed());
    }

    @Test void completedWithoutEvidenceFailsClosed() throws Exception {
        stub("ACTIVE", "ACTIVE", "COMPLETED", "HOLDER_ENROLLMENT", false, false, false);
        var state = service.get(INSTALLATION, THUMB);
        assertEquals(HolderIdentityStatusService.State.IDENTITY_BLOCKED, state.state());
        assertFalse(state.walletAccessAllowed());
    }

    @Test void wrongPurposeFailsClosed() throws Exception {
        stub("ACTIVE", "ACTIVE", "COMPLETED", "ISSUANCE", true, true, false);
        assertEquals(HolderIdentityStatusService.State.IDENTITY_BLOCKED, service.get(INSTALLATION, THUMB).state());
    }

    @Test void mismatchedProvenKeyDeniedDespiteValidAccreditation() throws Exception {
        stub("ACTIVE", "ACTIVE", "COMPLETED", "HOLDER_ENROLLMENT", true, true, false);
        assertThrows(SecurityException.class, () -> service.get(INSTALLATION, OTHER));
    }

    @Test void invalidIdentifiersRejectedBeforeJdbc() {
        assertThrows(SecurityException.class, () -> service.get("bad", THUMB));
        assertThrows(SecurityException.class, () -> service.get(INSTALLATION, "bad"));
        assertThrows(SecurityException.class, () -> service.get(null, THUMB));
        verifyNoInteractions(jdbc, verifier);
    }

    @Test void installationNotFoundDenied() {
        when(jdbc.query(anyString(), any(RowMapper.class), any(OffsetDateTime.class), eq(INSTALLATION)))
            .thenReturn(List.of());
        assertThrows(SecurityException.class, () -> service.get(INSTALLATION, THUMB));
    }

    @Test void duplicateInstallationRowsDenied() throws Exception {
        stub("ACTIVE", null, null, null, false, false, false);
        // A duplicate result is an integrity error; never unlock the application.
        when(jdbc.query(anyString(), any(RowMapper.class), any(OffsetDateTime.class), eq(INSTALLATION)))
            .thenReturn(List.of("unexpected", "duplicate"));
        assertThrows(SecurityException.class, () -> service.get(INSTALLATION, THUMB));
    }

    @SuppressWarnings("unchecked")
    private void stub(String installationStatus, String holderStatus, String sessionStatus,
                      String purpose, boolean consumed, boolean evidence, boolean pending) throws Exception {
        ResultSet rs = mock(ResultSet.class);
        when(rs.getString("installation_status")).thenReturn(installationStatus);
        when(rs.getString("public_key")).thenReturn("synthetic-public-key");
        when(rs.getString("holder_status")).thenReturn(holderStatus);
        when(rs.getString("session_status")).thenReturn(sessionStatus);
        when(rs.getString("session_purpose")).thenReturn(purpose);
        when(rs.getObject("session_consumed_at", OffsetDateTime.class)).thenReturn(
            consumed ? OffsetDateTime.ofInstant(NOW.minusSeconds(3), ZoneOffset.UTC) : null);
        when(rs.getBytes("session_evidence_digest")).thenReturn(evidence ? new byte[32] : null);
        when(rs.getBoolean("has_pending")).thenReturn(pending);
        when(verifier.thumbprintFromStoredPem("synthetic-public-key")).thenReturn(THUMB);
        when(jdbc.query(anyString(), any(RowMapper.class), any(OffsetDateTime.class), eq(INSTALLATION)))
            .thenAnswer(inv -> {
                RowMapper<?> mapper = inv.getArgument(1);
                return List.of(mapper.mapRow(rs, 0));
            });
    }
}
