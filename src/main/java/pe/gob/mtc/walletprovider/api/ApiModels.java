package pe.gob.mtc.walletprovider.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.time.OffsetDateTime;
import java.util.List;

public final class ApiModels {
    private ApiModels() {}
    public record ChallengeRequest(@NotBlank String platform) {}
    public record ChallengeResponse(String challengeId,String nonce,OffsetDateTime expiresAt) {}
    public record AndroidEnrollment(@NotBlank String challengeId,@NotBlank String keyId,
                                    @NotBlank String publicKeyPem,@NotBlank String proofSignature,
                                    @NotBlank String playIntegrityToken,List<String> keyAttestationChain) {}
    public record IosEnrollment(@NotBlank String challengeId,@NotBlank String keyId,
                                @NotBlank String attestationObject) {}

    /** A distinct ES256 signing key for diagnostics, bound by the installation key or App Attest assertion. */
    public record DiagnosticsKeyBindingRequest(@NotBlank String challengeId,
            @NotBlank String keyId,@NotBlank String publicKeySpkiBase64,
            @NotBlank @jakarta.validation.constraints.Size(max=512) String keyProofSignature,
            @jakarta.validation.constraints.Size(max=512) String installationProofSignature,
            @jakarta.validation.constraints.Size(max=16384) String appAttestAssertion) {}
    public record DiagnosticsKeyResponse(String installationId,String keyId,String syncStatus) {}
    public record EnrollmentResponse(String installationId,String status,String assurance) {}
    public record TrustResponse(String installationId,String platform,String status,String assurance) {}
    public record AttestationRequest(@NotBlank String challengeId,@NotBlank String proofSignature) {}
    public record IosAttestationRequest(@NotBlank String challengeId,@NotBlank String assertionObject) {}
    public record InstallationProofRequest(@NotBlank String installationId,@NotBlank String challengeId,@NotBlank String proofSignature) {}
    public record InstallationIosProofRequest(@NotBlank String installationId,@NotBlank String challengeId,@NotBlank String assertionObject) {}
    /** Independent Android hardware-backed credential key, distinct from the installation key. */
    public record AndroidCredentialKeyAttestationRequest(
            @NotBlank String installationId,
            @NotBlank String challengeId,
            @NotBlank String credentialPublicKeyPem,
            @NotEmpty List<String> credentialKeyAttestationChain,
            @NotBlank String issuerNonce,
            @NotBlank String installationProofSignature,
            @NotBlank String credentialProofSignature) {}
    public record AttestationResponse(String token,String expiresAt) {}
    public record ErrorResponse(String code,String message) {}
}
