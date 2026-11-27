package pe.gob.mtc.walletprovider.identity;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.UUID;
import java.util.function.UnaryOperator;

import static org.junit.jupiter.api.Assertions.*;

class SignedMimotoReniecEvidenceVerifierTest {
    private static final Instant NOW = Instant.parse("2026-11-24T21:00:00Z");
    private static final String ISSUER = "mtc-mimoto-lab";
    private static final String AUDIENCE = "mtc-wallet-provider-holder-lab";
    private static final String NONCE = "A".repeat(43);
    private static final String INSTALLATION = "55555555-5555-4555-8555-555555555555";
    private static final UUID SESSION = UUID.fromString("44444444-4444-4444-8444-444444444444");
    private KeyPair signing;
    private SignedMimotoReniecEvidenceVerifier verifier;
    private TrustedReniecEvidenceVerifier.Challenge challenge;

    @BeforeEach
    void setup() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        signing = generator.generateKeyPair();
        verifier = new SignedMimotoReniecEvidenceVerifier(signing.getPublic(), ISSUER, AUDIENCE,
                Clock.fixed(NOW, ZoneOffset.UTC));
        challenge = new TrustedReniecEvidenceVerifier.Challenge(
                SESSION, INSTALLATION, NONCE, NOW.plusSeconds(300));
    }

    private JWTClaimsSet.Builder validClaims() {
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .subject("MIMOTO_RENIEC_SESSION:reniec-session-1234567890")
                .jwtID("mimoto-evidence-11111111111111111111")
                .issueTime(Date.from(NOW.minusSeconds(10)))
                .notBeforeTime(Date.from(NOW.minusSeconds(10)))
                .expirationTime(Date.from(NOW.plusSeconds(100)))
                .claim("outcome", "SUCCESS")
                .claim("purpose", "HOLDER_ENROLLMENT")
                .claim("authority", "RENIEC_ID_PERU")
                .claim("dni", "01234567")
                .claim("reniec_session_id", "reniec-session-1234567890")
                .claim("identity_session_id", SESSION.toString())
                .claim("installation_id", INSTALLATION)
                .claim("nonce", NONCE)
                .claim("auth_time", NOW.minusSeconds(20).getEpochSecond());
    }

    private String token(KeyPair keys, UnaryOperator<JWTClaimsSet.Builder> modification) throws Exception {
        JWTClaimsSet.Builder claims = modification.apply(validClaims());
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .type(new JOSEObjectType("mtc-holder-identity+jwt")).build(), claims.build());
        jwt.sign(new RSASSASigner((RSAPrivateKey) keys.getPrivate()));
        return jwt.serialize();
    }

    private String token(UnaryOperator<JWTClaimsSet.Builder> modification) throws Exception {
        return token(signing, modification);
    }

    private void rejects(UnaryOperator<JWTClaimsSet.Builder> change) throws Exception {
        assertThrows(SecurityException.class, () -> verifier.verify(token(change), challenge));
    }

    @Test void acceptsSignedDniAndExactSessionBinding() throws Exception {
        var value = verifier.verify(token(c -> c), challenge);
        assertEquals("01234567", value.dni());
        assertEquals(SESSION, value.sessionId());
        assertEquals(INSTALLATION, value.installationId());
        assertEquals("RENIEC_ID_PERU", value.issuer());
        assertEquals("MIMOTO_RENIEC_SESSION:reniec-session-1234567890", value.subject());
        assertFalse(value.subject().contains(value.dni()));
        assertEquals("reniec-session-1234567890", value.externalReference());
    }

    @Test void acceptsEs256SignedEvidence() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ec = generator.generateKeyPair();
        var esVerifier = new SignedMimotoReniecEvidenceVerifier(ec.getPublic(), ISSUER, AUDIENCE,
                Clock.fixed(NOW, ZoneOffset.UTC));
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("mtc-holder-identity+jwt")).build(), validClaims().build());
        jwt.sign(new ECDSASigner((ECPrivateKey) ec.getPrivate()));
        assertEquals("01234567", esVerifier.verify(jwt.serialize(), challenge).dni());
    }

    @Test void rejectsWrongAuthority() throws Exception { rejects(c -> c.claim("authority", "OTHER")); }
    @Test void rejectsDniInsideSubject() throws Exception { rejects(c -> c.subject("RENIEC_ID_PERU:01234567")); }
    @Test void rejectsMultipleAudiences() throws Exception { rejects(c -> c.audience(java.util.List.of(AUDIENCE, "another"))); }
    @Test void rejectsInvalidAuthTime() throws Exception { rejects(c -> c.claim("auth_time", "invalid")); }

    @Test void rejectsWrongIssuer() throws Exception { rejects(c -> c.issuer("other-issuer")); }
    @Test void rejectsWrongAudience() throws Exception { rejects(c -> c.audience("another-api")); }
    @Test void rejectsOtherPurposes() throws Exception { rejects(c -> c.claim("purpose", "ISSUANCE")); }
    @Test void rejectsFailedBiometricResult() throws Exception { rejects(c -> c.claim("outcome", "FAILED")); }
    @Test void rejectsNonceFromDifferentSession() throws Exception { rejects(c -> c.claim("nonce", "B".repeat(43))); }
    @Test void rejectsInstallationSubstitution() throws Exception { rejects(c -> c.claim("installation_id", "another-installation")); }
    @Test void rejectsIdentitySessionSubstitution() throws Exception { rejects(c -> c.claim("identity_session_id", UUID.randomUUID().toString())); }
    @Test void rejectsExpiredEvidence() throws Exception { rejects(c -> c.expirationTime(Date.from(NOW.minusSeconds(1)))); }
    @Test void rejectsLongLivedEvidence() throws Exception { rejects(c -> c.expirationTime(Date.from(NOW.plusSeconds(300)))); }
    @Test void rejectsFutureNotBefore() throws Exception { rejects(c -> c.notBeforeTime(Date.from(NOW.plusSeconds(60)))); }
    @Test void rejectsStaleBiometric() throws Exception { rejects(c -> c.claim("auth_time", NOW.minusSeconds(600).getEpochSecond())); }
    // El sub identifica la sesión RENIEC, NO el DNI. MiMoto firma el DNI realmente acreditado.
    @Test void acceptsDifferentValidDniWhenSignedByTrustedMiMoto() throws Exception {
        var value = verifier.verify(token(c -> c.claim("dni", "99999999")), challenge);
        assertEquals("99999999", value.dni());
        assertEquals("MIMOTO_RENIEC_SESSION:reniec-session-1234567890", value.subject());
        assertFalse(value.subject().contains(value.dni()));
    }

    @Test void rejectsSubjectReniecSessionMismatch() throws Exception {
        rejects(c -> c.subject("MIMOTO_RENIEC_SESSION:other-reniec-session-1234567890"));
    }

    @Test void rejectsReniecSessionReferenceMismatch() throws Exception {
        rejects(c -> c.claim("reniec_session_id", "other-reniec-session-1234567890"));
    }

    @Test void rejectsDniAlteredAfterSigning() throws Exception {
        String signed = token(c -> c);
        String[] parts = signed.split("\\.", -1);
        assertEquals(3, parts.length);
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        String originalClaim = "\"dni\":\"01234567\"";
        assertTrue(payload.contains(originalClaim), "El JWT de laboratorio debe contener el DNI esperado");
        String changedPayload = payload.replace(originalClaim, "\"dni\":\"99999999\"");
        assertNotEquals(payload, changedPayload);
        String tampered = parts[0] + "." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(changedPayload.getBytes(StandardCharsets.UTF_8)) + "." + parts[2];
        assertThrows(SecurityException.class, () -> verifier.verify(tampered, challenge));
    }
    @Test void rejectsMalformedDni() throws Exception { rejects(c -> c.claim("dni", "ABC12345")); }
    @Test void rejectsExpiredProviderSession() throws Exception {
        var expired = new TrustedReniecEvidenceVerifier.Challenge(SESSION, INSTALLATION, NONCE, NOW);
        assertThrows(SecurityException.class, () -> verifier.verify(token(c -> c), expired));
    }
    @Test void rejectsSignatureFromUnknownSigner() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair other = generator.generateKeyPair();
        assertThrows(SecurityException.class, () -> verifier.verify(token(other, c -> c), challenge));
    }
    @Test void rejectsUntrustedMobileBoolean() {
        assertThrows(SecurityException.class, () -> verifier.verify("{\"biometriaOK\":true}", challenge));
        assertThrows(SecurityException.class, () -> verifier.verify("", challenge));
    }
}
