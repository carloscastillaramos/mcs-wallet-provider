package pe.gob.mtc.walletprovider.identity;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Verifica exclusivamente evidencia firmada por el backend MTC MiMoto.
 * No valida tokens RENIEC emitidos al movil, JWT de Cognito, ni un booleano de ID Peru.
 * Debe invocarse unicamente desde un servicio transaccional de Provider, con contexto
 * de sesion obtenido de su propia base de datos.
 *
 * Contrato MTC-HOLDER-EVIDENCE-1; el emisor del JWT se implementara en MiMoto.
 */
public final class SignedMimotoReniecEvidenceVerifier implements TrustedReniecEvidenceVerifier {
    private static final JOSEObjectType TYPE = new JOSEObjectType("mtc-holder-identity+jwt");
    private static final String PURPOSE = "HOLDER_ENROLLMENT";
    private static final String AUTHORITY = "RENIEC_ID_PERU";
    private static final Duration MAX_TOKEN_LIFETIME = Duration.ofMinutes(2);
    private static final Duration MAX_BIOMETRIC_AGE = Duration.ofMinutes(5);
    private static final Duration CLOCK_SKEW = Duration.ofSeconds(30);

    private final PublicKey trustedKey;
    private final X509Certificate pinnedCertificate;
    private final String expectedIssuer;
    private final String expectedAudience;
    private final Clock clock;

    public SignedMimotoReniecEvidenceVerifier(Path pinnedCertificatePath, String issuer,
                                               String audience, Clock clock) {
        this(readCertificate(pinnedCertificatePath), issuer, audience, clock);
    }

    private SignedMimotoReniecEvidenceVerifier(X509Certificate pinnedCertificate, String issuer,
                                                String audience, Clock clock) {
        this(pinnedCertificate.getPublicKey(), pinnedCertificate, issuer, audience, clock);
    }

    // Constructor visible al paquete para pruebas con claves efimeras sin certificados reales.
    SignedMimotoReniecEvidenceVerifier(PublicKey key, String issuer, String audience, Clock clock) {
        this(key, null, issuer, audience, clock);
    }

    private SignedMimotoReniecEvidenceVerifier(PublicKey key, X509Certificate certificate,
                                                String issuer, String audience, Clock clock) {
        this.trustedKey = Objects.requireNonNull(key, "Mimoto signer key missing");
        if (!(key instanceof ECPublicKey) && !(key instanceof RSAPublicKey))
            throw new IllegalArgumentException("Unsupported Mimoto signing key");
        if (issuer == null || issuer.isBlank() || audience == null || audience.isBlank())
            throw new IllegalArgumentException("Mimoto evidence issuer and audience are mandatory");
        this.expectedIssuer = issuer;
        this.expectedAudience = audience;
        this.clock = Objects.requireNonNull(clock);
        this.pinnedCertificate = certificate;
        if (certificate != null) checkCertificate(certificate, clock.instant());
    }

    @Override
    public VerifiedIdentity verify(String evidence, Challenge challenge) {
        if (challenge == null || challenge.sessionId() == null || challenge.installationId() == null ||
                challenge.nonce() == null || challenge.expiresAt() == null ||
                evidence == null || evidence.isBlank() || evidence.length() > 16384) {
            throw rejected();
        }
        try {
            Instant now = clock.instant();
            if (!now.isBefore(challenge.expiresAt())) throw rejected();
            if (pinnedCertificate != null) checkCertificate(pinnedCertificate, now);

            SignedJWT jwt = SignedJWT.parse(evidence);
            if (!TYPE.equals(jwt.getHeader().getType()) || jwt.getHeader().getJWK() != null ||
                    jwt.getHeader().getJWKURL() != null || jwt.getHeader().getX509CertChain() != null ||
                    jwt.getHeader().getX509CertURL() != null) {
                throw rejected();
            }
            boolean validSignature;
            if (trustedKey instanceof RSAPublicKey rsa) {
                validSignature = JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm()) &&
                        jwt.verify(new RSASSAVerifier(rsa));
            } else {
                validSignature = JWSAlgorithm.ES256.equals(jwt.getHeader().getAlgorithm()) &&
                        jwt.verify(new ECDSAVerifier((ECPublicKey) trustedKey));
            }
            if (!validSignature) throw rejected();

            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            List<String> audiences = claims.getAudience();
            Date issued = claims.getIssueTime();
            Date notBefore = claims.getNotBeforeTime();
            Date expires = claims.getExpirationTime();
            if (!expectedIssuer.equals(claims.getIssuer()) || audiences == null ||
                    audiences.size() != 1 || !expectedAudience.equals(audiences.getFirst()) ||
                    issued == null || notBefore == null || expires == null ||
                    issued.after(Date.from(now.plus(CLOCK_SKEW))) ||
                    notBefore.after(Date.from(now)) ||
                    !expires.toInstant().isAfter(now) ||
                    !expires.toInstant().isAfter(issued.toInstant()) ||
                    Duration.between(issued.toInstant(), expires.toInstant()).compareTo(MAX_TOKEN_LIFETIME) > 0 ||
                    !"SUCCESS".equals(claims.getStringClaim("outcome")) ||
                    !PURPOSE.equals(claims.getStringClaim("purpose")) ||
                    !AUTHORITY.equals(claims.getStringClaim("authority"))) {
                throw rejected();
            }

            String dni = claims.getStringClaim("dni");
            HolderIdentityCrypto.validateDni(dni);
            String reference = claims.getStringClaim("reniec_session_id");
            String subject = reference == null ? null : "MIMOTO_RENIEC_SESSION:" + reference;
            String nonce = claims.getStringClaim("nonce");
            String installation = claims.getStringClaim("installation_id");
            String session = claims.getStringClaim("identity_session_id");
            String jti = claims.getJWTID();
            Long authEpoch = claims.getLongClaim("auth_time");
            if (reference == null || !reference.matches("[A-Za-z0-9._:-]{16,128}") ||
                    !subject.equals(claims.getSubject()) ||
                    jti == null || !jti.matches("[A-Za-z0-9._:-]{16,128}") ||
                    !challenge.nonce().equals(nonce) ||
                    !challenge.installationId().equals(installation) ||
                    !challenge.sessionId().toString().equals(session) ||
                    authEpoch == null) throw rejected();

            Instant biometricAt = Instant.ofEpochSecond(authEpoch);
            if (biometricAt.isAfter(now.plus(CLOCK_SKEW)) ||
                    Duration.between(biometricAt, now).compareTo(MAX_BIOMETRIC_AGE) > 0 ||
                    biometricAt.isAfter(issued.toInstant().plus(CLOCK_SKEW))) throw rejected();

            return new VerifiedIdentity(dni, AUTHORITY, subject, reference,
                    challenge.sessionId(), installation, nonce, biometricAt);
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            // No registrar DNI, evidencia JWT, nonce ni informacion biometrica en excepciones.
            throw rejected();
        }
    }

    private static SecurityException rejected() {
        return new SecurityException("Identity evidence rejected");
    }

    private static X509Certificate readCertificate(Path path) {
        if (path == null || path.toString().isBlank())
            throw new IllegalArgumentException("Mimoto signer certificate path missing");
        try (InputStream input = Files.newInputStream(path)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        } catch (Exception e) {
            throw new IllegalStateException("Mimoto signer certificate unavailable");
        }
    }

    private static void checkCertificate(X509Certificate cert, Instant at) {
        try { cert.checkValidity(Date.from(at)); }
        catch (Exception e) { throw new IllegalStateException("Mimoto signer certificate expired or invalid"); }
    }
}
