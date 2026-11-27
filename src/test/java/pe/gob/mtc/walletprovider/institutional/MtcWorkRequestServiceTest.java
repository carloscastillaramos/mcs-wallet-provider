package pe.gob.mtc.walletprovider.institutional;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.server.ResponseStatusException;
import pe.gob.mtc.walletprovider.identity.HolderIdentityCrypto;

import java.sql.ResultSet;
import java.time.LocalDate;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class MtcWorkRequestServiceTest {
    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final HolderIdentityCrypto crypto = mock(HolderIdentityCrypto.class);
    private final MtcPortalAdministration admin = mock(MtcPortalAdministration.class);
    private final MtcWorkRequestService service = new MtcWorkRequestService(jdbc, crypto, admin, new ObjectMapper().findAndRegisterModules());
    private final MtcOperatorAccess.Operator registrar = new MtcOperatorAccess.Operator(
        UUID.randomUUID(), "https://mtc-issuer", "registrador", Set.of(MtcOperatorAccess.REGISTRADOR));
    private final MtcOperatorAccess.Operator aprobador = new MtcOperatorAccess.Operator(
        UUID.randomUUID(), "https://mtc-issuer", "aprobador", Set.of(MtcOperatorAccess.APROBADOR));

    @Test void registrarOnlyStagesEncryptedRequestWithoutApplyingGrant() {
        UUID entityId = UUID.randomUUID();
        when(admin.activeEntity("MTC")).thenReturn(new MtcPortalAdministration.Entity(entityId, "MTC", "Ministerio"));
        when(crypto.encryptImportRow(anyString())).thenReturn(new byte[40]);
        var dto = new MtcPortalAdministration.CreateGrant("12345678", "U01", "Unidad", LocalDate.now().plusDays(5));
        UUID id = service.registerGrant("MTC", dto, "idempotencia.123456", registrar);
        assertNotNull(id);
        verify(jdbc).update(contains("INSERT INTO wallet_provider.wp_mtc_work_request"),
            eq(id), eq(entityId), eq(MtcWorkRequestService.GRANT_CREATE), isNull(), any(byte[].class),
            eq(registrar.id()), eq("idempotencia.123456"));
        verify(admin, never()).create(anyString(), any(), any());
        verify(admin, never()).revoke(anyString(), any(), anyLong(), anyString(), any());
        verify(admin, never()).linkInstallation(anyString(), any(), any(), any());
    }

    @Test void approveAppliesGrantOnceAndRecordsDecisionInSameServiceInvocation() throws Exception {
        UUID requestId = UUID.randomUUID();
        UUID entityId = UUID.randomUUID();
        UUID grantId = UUID.randomUUID();
        mockLock(requestId, entityId, "GRANT_CREATE", null, "PENDING");
        when(jdbc.query(contains("SELECT code FROM wallet_provider.wp_entity"),
            org.mockito.ArgumentMatchers.<RowMapper<String>>any(), eq(entityId)))
            .thenReturn(List.of("MTC"));
        String until = LocalDate.now().plusDays(30).toString();
        when(crypto.decryptImportRow(any(byte[].class)))
            .thenReturn("{\"dni\":\"12345678\",\"institutionalCode\":\"U01\",\"unit\":\"Unidad\",\"validUntil\":\"" + until + "\"}");
        when(admin.create(eq("MTC"), any(MtcPortalAdministration.CreateGrant.class), eq(aprobador)))
            .thenReturn(grantId);
        when(jdbc.update(contains("UPDATE wallet_provider.wp_mtc_work_request"),
            eq(aprobador.id()), eq(grantId.toString()), eq(requestId))).thenReturn(1);
        service.approve(requestId, aprobador);
        verify(admin).create(eq("MTC"), any(MtcPortalAdministration.CreateGrant.class), eq(aprobador));
        verify(jdbc).update(contains("UPDATE wallet_provider.wp_mtc_work_request"),
            eq(aprobador.id()), eq(grantId.toString()), eq(requestId));
        verify(admin).audit(eq(aprobador), eq(entityId), eq("REQUEST_APPROVE"),
            eq(requestId.toString()), eq("APPROVED"), isNull());
    }

    @Test void rejectDoesNotCallEffectiveEnrollmentOrRevocation() throws Exception {
        UUID requestId = UUID.randomUUID();
        UUID entityId = UUID.randomUUID();
        mockLock(requestId, entityId, "GRANT_CREATE", null, "PENDING");
        when(jdbc.update(contains("UPDATE wallet_provider.wp_mtc_work_request"),
            any(), any(), eq(requestId))).thenReturn(1);
        service.reject(requestId, new MtcWorkRequestService.Decision("DNI inconsistente"), aprobador);
        verify(admin, never()).create(anyString(), any(), any());
        verify(admin, never()).revoke(anyString(), any(), anyLong(), anyString(), any());
        verify(admin, never()).linkInstallation(anyString(), any(), any(), any());
        verify(admin, never()).revokeInstallation(any(), anyString(), any());
        verify(admin).audit(eq(aprobador), eq(entityId), eq("REQUEST_REJECT"),
            eq(requestId.toString()), eq("REJECTED"), eq("DNI inconsistente"));
    }

    @Test void decidedRequestCannotBeApprovedAgain() throws Exception {
        UUID requestId = UUID.randomUUID();
        mockLock(requestId, UUID.randomUUID(), "GRANT_CREATE", null, "APPROVED");
        assertThrows(ResponseStatusException.class, () -> service.approve(requestId, aprobador));
        verify(admin, never()).create(anyString(), any(), any());
    }

    @Test void globalRevocationRequiresSuperAdminEvenWhenUserCanApprove() throws Exception {
        UUID requestId = UUID.randomUUID();
        mockLock(requestId, null, "INSTALLATION_REVOKE", UUID.randomUUID().toString(), "PENDING");
        assertThrows(ResponseStatusException.class, () -> service.approve(requestId, aprobador));
        verify(admin, never()).revokeInstallation(any(), anyString(), any());
    }

    @Test void ordinaryMesaDePartesCannotRegisterGlobalWalletRevocation() {
        assertThrows(ResponseStatusException.class, () -> service.registerInstallationRevoke(
            UUID.randomUUID(), new MtcWorkRequestService.InstallationRevoke("Motivo"),
            "idempotencia.123456", registrar));
        verifyNoInteractions(jdbc);
    }

    @Test void rejectionMustHaveReason() {
        assertThrows(ResponseStatusException.class, () -> MtcWorkRequestService.validateReason(" "));
        assertThrows(ResponseStatusException.class, () -> MtcWorkRequestService.validateReason(null));
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private void mockLock(UUID id, UUID entityId, String action, String resource, String status) throws Exception {
        ResultSet rs = mock(ResultSet.class);
        when(rs.getObject("id", UUID.class)).thenReturn(id);
        when(rs.getObject("entity_id", UUID.class)).thenReturn(entityId);
        when(rs.getString("action")).thenReturn(action);
        when(rs.getString("resource_id")).thenReturn(resource);
        when(rs.getBytes("payload_cipher")).thenReturn(new byte[40]);
        when(rs.getString("status")).thenReturn(status);
        when(jdbc.query(contains("FROM wallet_provider.wp_mtc_work_request WHERE id = ? FOR UPDATE"),
            any(RowMapper.class), eq(id)))
            .thenAnswer(inv -> List.of(((RowMapper) inv.getArgument(1)).mapRow(rs, 0)));
    }
}
