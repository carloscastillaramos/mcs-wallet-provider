package pe.gob.mtc.walletprovider.identity;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class CredentialKeyBindingRegistryTest {
    private final JdbcTemplate jdbc=mock(JdbcTemplate.class);
    private CredentialKeyBindingRegistry ledger(boolean enabled,boolean identity,boolean required) {
        return new CredentialKeyBindingRegistry(jdbc,enabled,identity,required);
    }
    private static KeyPair ecKey() throws Exception {
        KeyPairGenerator g=KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }
    @Test void disabledDoesNotTouchPostgresql() throws Exception {
        ledger(false,false,false).recordValidated("installation",ecKey().getPublic(),"nonce",Instant.now().plusSeconds(60));
        verifyNoInteractions(jdbc);
    }
    @Test void cannotEnableLedgerWithoutIdentity() {
        assertThrows(IllegalStateException.class,()->ledger(true,false,true).assertSafeConfiguration());
    }
    @Test void cannotEnableLedgerWithoutMandatoryKeyAttestation() {
        assertThrows(IllegalStateException.class,()->ledger(true,true,false).assertSafeConfiguration());
    }
    @Test void safeConfigurationAccepted() {
        assertDoesNotThrow(()->ledger(true,true,true).assertSafeConfiguration());
    }
    @Test void recordPersistsOnlyThumbprintAndNonceHash() throws Exception {
        ledger(true,true,true).recordValidated("installation",ecKey().getPublic(),"issuerNonce",Instant.now().plusSeconds(60));
        verify(jdbc).update(contains("INSERT INTO wallet_provider.wp_credential_key_binding"),any(Object[].class));
    }
    @Test void rejectsExpiredRecord() throws Exception {
        assertThrows(SecurityException.class,()->ledger(true,true,true).recordValidated("id",ecKey().getPublic(),"nonce",Instant.now().minusSeconds(1)));
        verifyNoInteractions(jdbc);
    }
    @Test void rejectsMissingInstallation() throws Exception {
        assertThrows(SecurityException.class,()->ledger(true,true,true).recordValidated("",ecKey().getPublic(),"nonce",Instant.now().plusSeconds(60)));
        verifyNoInteractions(jdbc);
    }
    @Test void rejectsInvalidNonce() throws Exception {
        assertThrows(SecurityException.class,()->ledger(true,true,true).recordValidated("id",ecKey().getPublic()," ",Instant.now().plusSeconds(60)));
        verifyNoInteractions(jdbc);
    }
    @Test void rejectsNonP256Key() throws Exception {
        KeyPairGenerator g=KeyPairGenerator.getInstance("RSA");g.initialize(2048);
        var kp=g.generateKeyPair();
        assertThrows(SecurityException.class,()->ledger(true,true,true).recordValidated("id",kp.getPublic(),"nonce",Instant.now().plusSeconds(60)));
        verifyNoInteractions(jdbc);
    }
    @Test void generatesStableJwkThumbprint() throws Exception {
        var key=ecKey().getPublic();
        var a=CredentialKeyBindingRegistry.publicKeyThumbprint(key);
        assertEquals(a,CredentialKeyBindingRegistry.publicKeyThumbprint(key));
        assertTrue(a.matches("[A-Za-z0-9_-]{43}"));
    }
    @Test void lookupAlwaysDeniedWhenDisabled() {
        assertThrows(SecurityException.class,()->ledger(false,true,true).activeAccreditedBinding("a".repeat(43),"nonce"));
        verifyNoInteractions(jdbc);
    }
    @Test void lookupRejectsUntrustedThumbprint() {
        assertThrows(SecurityException.class,()->ledger(true,true,true).activeAccreditedBinding("client-hint", "nonce"));
        verifyNoInteractions(jdbc);
    }
    @Test void lookupReturnsFalseWhenNoMatchingBinding() {
        when(jdbc.queryForObject(contains("wp_credential_key_binding"),eq(Boolean.class),any(Object[].class)))
            .thenReturn(Boolean.FALSE);
        assertFalse(ledger(true,true,true).activeAccreditedBinding("a".repeat(43),"nonce"));
    }
    @Test void lookupRequiresActiveInstallationAndCompletedIdentity() {
        when(jdbc.queryForObject(contains("wp_credential_key_binding"),eq(Boolean.class),any(Object[].class)))
            .thenReturn(Boolean.TRUE);
        assertTrue(ledger(true,true,true).activeAccreditedBinding("a".repeat(43),"nonce"));
        verify(jdbc).queryForObject(argThat(sql->sql.contains("i.status='ACTIVE'")
            && sql.contains("ih.status='ACTIVE'") && sql.contains("s.status='COMPLETED'")
            && sql.contains("b.expires_at>CURRENT_TIMESTAMP")),eq(Boolean.class),any(Object[].class));
    }
    @Test void usesExplicitWalletProviderSchemaForInsertAndRead() throws Exception {
        ledger(true,true,true).recordValidated("installation",ecKey().getPublic(),"nonce",Instant.now().plusSeconds(60));
        verify(jdbc).update(contains("wallet_provider.wp_credential_key_binding"),any(Object[].class));
        when(jdbc.queryForObject(anyString(),eq(Boolean.class),any(Object[].class))).thenReturn(Boolean.FALSE);
        ledger(true,true,true).activeAccreditedBinding("a".repeat(43),"nonce");
        verify(jdbc).queryForObject(argThat(sql -> sql.contains("wallet_provider.wp_credential_key_binding")
            && sql.contains("wallet_provider.wp_installation i")
            && sql.contains("wallet_provider.wp_installation_holder ih")
            && sql.contains("wallet_provider.wp_identity_session s")),
            eq(Boolean.class),any(Object[].class));
    }
    @Test void lookupDatabaseFailureNeverAllowsAccess() {
        when(jdbc.queryForObject(anyString(),eq(Boolean.class),any(Object[].class)))
            .thenThrow(new IllegalStateException("DB unavailable"));
        assertThrows(IllegalStateException.class,()->ledger(true,true,true).activeAccreditedBinding("a".repeat(43),"nonce"));
    }
}
