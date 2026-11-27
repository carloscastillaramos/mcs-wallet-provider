package pe.gob.mtc.walletprovider.identity;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.AlgorithmParameters;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;
import java.util.UUID;

/**
 * Registro durable y minimizado del proof de clave de credencial, creado UNICAMENTE
 * despues de validar instalacion, PoP de ambas claves y evidencia hardware.
 * No almacena DNI, c_nonce en claro, claves privadas ni datos biometricos.
 * Esta clase NO es un endpoint: la autorizacion M2M de Certify se incorporara despues.
 */
@Service
public class CredentialKeyBindingRegistry {
    private final JdbcTemplate jdbc;
    private final boolean enabled;
    private final boolean holderIdentityEnabled;
    private final boolean identityAttestationRequired;

    public CredentialKeyBindingRegistry(JdbcTemplate jdbc,
          @Value("${WALLET_IDENTITY_CREDENTIAL_BINDING_ENABLED:false}") boolean enabled,
          @Value("${WALLET_IDENTITY_ENABLED:false}") boolean holderIdentityEnabled,
          @Value("${WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED:false}") boolean identityAttestationRequired) {
        this.jdbc=Objects.requireNonNull(jdbc);
        this.enabled=enabled;
        this.holderIdentityEnabled=holderIdentityEnabled;
        this.identityAttestationRequired=identityAttestationRequired;
    }

    @PostConstruct
    public void assertSafeConfiguration() {
        if (enabled && (!holderIdentityEnabled || !identityAttestationRequired)) {
            throw new IllegalStateException("Credential key binding requires identity and credential attestation enforcement");
        }
    }

    /** JWK thumbprint RFC 7638, compatible con la clave P-256 usada en el proof OpenID4VCI. */
    public static String publicKeyThumbprint(PublicKey publicKey) {
        if (!(publicKey instanceof ECPublicKey ec)) throw new SecurityException("Credential key must be P-256");
        try {
            // No asumir P-256 solo por el tamaño. Rechazar curvas de 256 bits
            // distintas, incluidas secp256k1, antes de calcular el RFC7638.
            AlgorithmParameters parameters=AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec p256=parameters.getParameterSpec(ECParameterSpec.class);
            ECParameterSpec actual=ec.getParams();
            if (actual==null || !p256.getCurve().equals(actual.getCurve()) ||
                !p256.getGenerator().equals(actual.getGenerator()) ||
                !p256.getOrder().equals(actual.getOrder()) ||
                p256.getCofactor()!=actual.getCofactor()) {
                throw new SecurityException("Wrong key curve");
            }
            ECKey jwk=new ECKey.Builder(Curve.P_256,ec).build();
            return jwk.computeThumbprint().toString();
        } catch (Exception ex) {
            throw new SecurityException("Invalid credential public key",ex);
        }
    }

    private static byte[] nonceDigest(String issuerNonce) {
        if (issuerNonce==null || issuerNonce.isBlank() || issuerNonce.length()>1024) {
            throw new SecurityException("Invalid issuer nonce");
        }
        try {return MessageDigest.getInstance("SHA-256").digest(issuerNonce.getBytes(StandardCharsets.UTF_8));}
        catch (Exception ex) {throw new IllegalStateException("SHA-256 unavailable",ex);}
    }

    /** Inserta dentro de la transaccion que firma la atestacion, nunca antes de las verificaciones. */
    public void recordValidated(String installationId,PublicKey credentialPublicKey,
                                String issuerNonce,Instant expiresAt) {
        if (!enabled) return; // Modo legacy: no exige la tabla ni cambia la respuesta.
        assertEnabled();
        if (installationId==null || installationId.isBlank() || expiresAt==null ||
                !expiresAt.isAfter(Instant.now())) throw new SecurityException("Invalid binding context");
        String thumbprint=publicKeyThumbprint(credentialPublicKey);
        byte[] digest=nonceDigest(issuerNonce);
        // UNIQUE (credential_key_thumbprint, issuer_nonce_sha256): no puede existir
        // el mismo proof/nonce asociado a instalaciones distintas ni reutilizado.
        jdbc.update("INSERT INTO wallet_provider.wp_credential_key_binding (id,installation_id,credential_key_thumbprint,"+
                "issuer_nonce_sha256,expires_at) VALUES (?,?,?,?,?)",
                UUID.randomUUID(),installationId,thumbprint,digest,
                OffsetDateTime.ofInstant(expiresAt,ZoneOffset.UTC));
    }

    /**
     * Consulta interna fail-closed; el futuro endpoint Certify debe autenticar al
     * servicio y verificar ANTES la firma del proof y c_nonce del emisor.
     * No confia en installationId/DNI procedentes del cliente.
     */
    public boolean activeAccreditedBinding(String credentialKeyThumbprint,String issuerNonce) {
        assertEnabled();
        if (credentialKeyThumbprint==null || !credentialKeyThumbprint.matches("[A-Za-z0-9_-]{43}"))
            throw new SecurityException("Invalid key thumbprint");
        byte[] digest=nonceDigest(issuerNonce);
        Boolean allowed=jdbc.queryForObject("SELECT EXISTS ("+
            "SELECT 1 FROM wallet_provider.wp_credential_key_binding b " +
            "JOIN wallet_provider.wp_installation i ON i.id=b.installation_id AND i.status='ACTIVE' " +
            "JOIN wallet_provider.wp_installation_holder ih ON ih.installation_id=i.id AND ih.status='ACTIVE' " +
            "JOIN wallet_provider.wp_identity_session s ON s.id=ih.identity_session_id AND s.installation_id=i.id " +
            "AND s.status='COMPLETED' AND s.purpose='HOLDER_ENROLLMENT' " +
            "AND s.consumed_at IS NOT NULL AND s.evidence_digest IS NOT NULL " +
            "WHERE b.credential_key_thumbprint=? AND b.issuer_nonce_sha256=? " +
            "AND b.expires_at>CURRENT_TIMESTAMP)",
            Boolean.class,credentialKeyThumbprint,digest);
        return Boolean.TRUE.equals(allowed);
    }

    private void assertEnabled() {
        if (!enabled || !holderIdentityEnabled || !identityAttestationRequired)
            throw new SecurityException("Credential key binding lookup is not enabled");
    }
}
