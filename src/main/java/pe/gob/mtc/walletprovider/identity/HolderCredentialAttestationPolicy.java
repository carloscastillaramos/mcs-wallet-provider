package pe.gob.mtc.walletprovider.identity;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import pe.gob.mtc.walletprovider.domain.Installation;
import pe.gob.mtc.walletprovider.security.ProofVerifier;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Objects;

/**
 * Optional identity precondition at the instant a key attestation is issued.
 *
 * IMPORTANT: EnrollmentService must authenticate the installation's PoP (and,
 * for credential keys, the separate key PoP and hardware attestation) BEFORE
 * calling this policy. The public key is read from the persisted installation,
 * never copied from an untrusted request header.
 *
 * This is NOT a replacement for an online identity/revocation check at the
 * Certify issuance boundary: a previously issued attestation may remain valid.
 */
@Component
public final class HolderCredentialAttestationPolicy {
    private final HolderIdentityStatusService identityStatus;
    private final ProofVerifier proof;
    private final boolean required;
    private final boolean identityEnabled;

    public HolderCredentialAttestationPolicy(
            HolderIdentityStatusService identityStatus,
            ProofVerifier proof,
            @Value("${WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED:false}") boolean required,
            @Value("${WALLET_IDENTITY_ENABLED:false}") boolean identityEnabled) {
        this.identityStatus = Objects.requireNonNull(identityStatus);
        this.proof = Objects.requireNonNull(proof);
        this.required = required;
        this.identityEnabled = identityEnabled;
    }

    @PostConstruct
    public void assertSafeConfiguration() {
        if (required && !identityEnabled) {
            throw new IllegalStateException(
                "Key attestation identity requirement needs WALLET_IDENTITY_ENABLED=true");
        }
    }

    public void requireAccredited(Installation installation) {
        if (!required) return;
        if (!identityEnabled || installation == null ||
                !"ACTIVE".equals(installation.status) ||
                installation.id == null || installation.publicKey == null) {
            throw denied();
        }
        try {
            PublicKey key = proof.decodePem(installation.publicKey);
            if (!(key instanceof ECPublicKey ec)) throw denied();
            String thumbprint = new ECKey.Builder(Curve.P_256, ec)
                    .build().computeThumbprint().toString();
            HolderIdentityStatusService.Status status = identityStatus.get(installation.id, thumbprint);
            if (status == null || status.state() != HolderIdentityStatusService.State.ACCREDITED
                    || !status.walletAccessAllowed()) {
                throw denied();
            }
        } catch (Exception ex) {
            // Neither the stored public key nor the reason for a denial is
            // included in the response or emitted to log output.
            throw denied();
        }
    }

    private static SecurityException denied() {
        return new SecurityException("Credential key attestation denied");
    }
}
