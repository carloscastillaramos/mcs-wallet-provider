package pe.gob.mtc.walletprovider.institutional;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

/** Internal machine-to-machine only; never exposed by the MTC public portal. */
@RestController
@RequestMapping("/api/v1/internal/verifier")
@ConditionalOnProperty(prefix = "wallet-provider.verifier-m2m", name = "enabled", havingValue = "true")
public final class MtcVerifierPermitController {
    private final MtcVerifierPermitService service;
    public MtcVerifierPermitController(MtcVerifierPermitService service) { this.service = service; }
    public record ChallengeRequest(@NotBlank String installationId, @NotBlank String entityCode,
                                   @NotBlank String operationHash) { }
    public record AuthorizeRequest(@NotNull UUID challengeId, @NotBlank String nonce,
                                   @NotBlank String proofSignature) { }
    @PostMapping("/challenge")
    public MtcVerifierPermitService.Challenge challenge(@Valid @RequestBody ChallengeRequest req) {
        return service.challenge(req.installationId(), req.entityCode(), req.operationHash());
    }
    @PostMapping("/authorize")
    public MtcVerifierPermitService.Permit authorize(@Valid @RequestBody AuthorizeRequest req) {
        return service.authorize(req.challengeId(), req.nonce(), req.proofSignature());
    }
}
