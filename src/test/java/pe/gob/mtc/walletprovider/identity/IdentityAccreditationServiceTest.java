package pe.gob.mtc.walletprovider.identity;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class IdentityAccreditationServiceTest {
    private IdentityAccreditationService service(JdbcTemplate jdbc, TrustedReniecEvidenceVerifier verifier) {
        byte[] a = new byte[32];
        byte[] b = new byte[32];
        java.util.Arrays.fill(a, (byte) 12);
        java.util.Arrays.fill(b, (byte) 24);
        return new IdentityAccreditationService(jdbc, new HolderIdentityCrypto(
            Base64.getEncoder().encodeToString(a), Base64.getEncoder().encodeToString(b), 1),
            verifier, Clock.fixed(Instant.parse("2026-11-24T20:00:00Z"), java.time.ZoneOffset.UTC));
    }

    @Test void deniesUnprovenOrMalformedIdentityBeforeDatabaseAccess() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        TrustedReniecEvidenceVerifier verifier = mock(TrustedReniecEvidenceVerifier.class);
        IdentityAccreditationService s = service(jdbc, verifier);
        assertThrows(SecurityException.class, () -> s.beginForProvenInstallation("unknown"));
        assertThrows(SecurityException.class, () -> s.completeFromTrustedEvidence(null, "nonce", "evidence"));
        assertThrows(SecurityException.class, () -> s.completeFromTrustedEvidence(UUID.randomUUID(), "abc", "evidence"));
        assertThrows(SecurityException.class, () -> s.completeFromTrustedEvidence(UUID.randomUUID(), "a".repeat(43), ""));
        verifyNoInteractions(jdbc, verifier);
    }

    @Test void rejectsIdentityCompletionWhenSessionNotFound() {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        TrustedReniecEvidenceVerifier verifier = mock(TrustedReniecEvidenceVerifier.class);
        IdentityAccreditationService s = service(jdbc, verifier);
        when(jdbc.query(anyString(), any(org.springframework.jdbc.core.RowMapper.class), any(UUID.class)))
            .thenReturn(java.util.List.of());
        assertThrows(SecurityException.class, () -> s.completeFromTrustedEvidence(
            UUID.randomUUID(), "a".repeat(43), "opaque-signed-evidence"));
        verifyNoInteractions(verifier);
    }
}
