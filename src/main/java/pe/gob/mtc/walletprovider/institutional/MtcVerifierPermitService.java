package pe.gob.mtc.walletprovider.institutional;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import pe.gob.mtc.walletprovider.domain.Installation;
import pe.gob.mtc.walletprovider.domain.InstallationRepository;
import pe.gob.mtc.walletprovider.security.AttestationSigner;
import pe.gob.mtc.walletprovider.security.ProofVerifier;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Only Cognito M2M can ask for challenges or permits. PoP is independently validated. */
@Service
@ConditionalOnProperty(prefix = "wallet-provider.verifier-m2m", name = "enabled", havingValue = "true")
public class MtcVerifierPermitService {
    private final JdbcTemplate jdbc;
    private final InstallationRepository installations;
    private final ProofVerifier proof;
    private final InstitutionalAuthorizationService authorizations;
    private final AttestationSigner signer;
    private final SecureRandom random = new SecureRandom();

    public MtcVerifierPermitService(JdbcTemplate jdbc, InstallationRepository installations,
                                   ProofVerifier proof, InstitutionalAuthorizationService authorizations,
                                   AttestationSigner signer) {
        this.jdbc = jdbc; this.installations = installations; this.proof = proof;
        this.authorizations = authorizations; this.signer = signer;
    }
    public record Challenge(UUID challengeId, String nonce, Instant expiresAt) { }
    public record Permit(String permit, Instant expiresAt) { }
    private record Stored(String installationId, String entityCode, String operationHash,
                          byte[] nonceDigest, OffsetDateTime expiresAt, OffsetDateTime consumedAt) { }

    @Transactional
    public Challenge challenge(String installationId, String entityCode, String operationHash) {
        validate(installationId, entityCode, operationHash);
        // Read-only precheck; final authorization is re-evaluated under lock on redemption.
        if (authorizations.checkVerifiedInstallation(installationId, entityCode)
                != InstitutionalAuthorizationService.Decision.ALLOW) throw denied();
        byte[] value = new byte[32]; random.nextBytes(value);
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(value);
        UUID id = UUID.randomUUID();
        Instant expires = Instant.now().plusSeconds(60);
        jdbc.update("""
            INSERT INTO wallet_provider.wp_verifier_challenge
                (id, installation_id, entity_code, operation_hash, nonce_hash, expires_at)
            VALUES (?,?,?,?,?,?)
            """, id, installationId, entityCode, operationHash, digest(nonce),
            OffsetDateTime.ofInstant(expires, ZoneOffset.UTC));
        return new Challenge(id, nonce, expires);
    }

    @Transactional
    public Permit authorize(UUID challengeId, String nonce, String signature) {
        if (challengeId == null || nonce == null || !nonce.matches("[A-Za-z0-9_-]{43}") ||
            signature == null || signature.length() > 512) throw denied();
        List<Stored> rows = jdbc.query("""
            SELECT installation_id, entity_code, operation_hash, nonce_hash, expires_at, consumed_at
            FROM wallet_provider.wp_verifier_challenge WHERE id = ? FOR UPDATE
            """, (rs,n) -> new Stored(rs.getString(1), rs.getString(2), rs.getString(3),
                rs.getBytes(4), rs.getObject(5, OffsetDateTime.class),
                rs.getObject(6, OffsetDateTime.class)), challengeId);
        if (rows.size() != 1) throw denied();
        Stored row = rows.getFirst();
        if (row.consumedAt() != null || !row.expiresAt().toInstant().isAfter(Instant.now()) ||
            !MessageDigest.isEqual(row.nonceDigest(), digest(nonce))) throw denied();
        Installation installation = installations.lockById(row.installationId()).orElseThrow(
            MtcVerifierPermitService::denied);
        if (!"ACTIVE".equals(installation.status)) throw denied();
        String message = "mtc-verifier:v1:" + challengeId + ":" + nonce + ":" +
            row.installationId() + ":" + row.entityCode() + ":" + row.operationHash();
        try { proof.verify(proof.decodePem(installation.publicKey), message, signature); }
        catch (Exception ex) { throw denied(); }
        if (authorizations.checkVerifiedInstallation(row.installationId(), row.entityCode())
                != InstitutionalAuthorizationService.Decision.ALLOW) throw denied();
        int changed = jdbc.update("""
            UPDATE wallet_provider.wp_verifier_challenge SET consumed_at = CURRENT_TIMESTAMP
            WHERE id = ? AND consumed_at IS NULL
            """, challengeId);
        if (changed != 1) throw denied();
        // 30 s, proof-bound and single-use at Verify; never grants persistent access.
        return new Permit(signer.issue(row.installationId(), "mtc-inji-verify",
            "MTC_VERIFIER_PERMIT", Map.of("op_hash", row.operationHash(),
                "entity", row.entityCode()), 30), Instant.now().plusSeconds(30));
    }

    private static void validate(String installationId, String entityCode, String operationHash) {
        if (installationId == null || !installationId.matches("[0-9a-fA-F-]{36}") ||
            entityCode == null || !entityCode.matches("[A-Za-z0-9_-]{2,32}") ||
            operationHash == null || !operationHash.matches("[0-9a-f]{64}")) throw denied();
        try { UUID.fromString(installationId); }
        catch (IllegalArgumentException ex) { throw denied(); }
    }
    private static byte[] digest(String value) {
        try { return MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.US_ASCII)); }
        catch (Exception ex) { throw new IllegalStateException("Digest unavailable", ex); }
    }
    private static ResponseStatusException denied() {
        return new ResponseStatusException(HttpStatus.FORBIDDEN, "Verifier authorization denied");
    }
}
