package pe.gob.mtc.walletprovider.identity;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.beans.factory.annotation.Autowired;
import pe.gob.mtc.walletprovider.institutional.InstitutionalAuthorizationService;

import java.util.Objects;

/** Consulta privada, nunca apta para navegadores ni llamadas sin PoP. */
@RestController
@RequestMapping("/api/v1/internal/identity/mimoto")
@ConditionalOnProperty(prefix = "wallet-provider.identity",
    name = {"enabled", "mimoto-m2m.enabled"}, havingValue = "true")
public final class MimotoIdentityStatusM2mController {
    private final HolderIdentityStatusService service;
    private final HolderInstallationBindingVerifier binding;
    private final InstitutionalAuthorizationService institution;

    @Autowired
    public MimotoIdentityStatusM2mController(HolderIdentityStatusService service,
        HolderInstallationBindingVerifier binding,
        InstitutionalAuthorizationService institution) {
        this.service = Objects.requireNonNull(service);
        this.binding = Objects.requireNonNull(binding);
        this.institution = Objects.requireNonNull(institution);
    }


    public MimotoIdentityStatusM2mController(HolderIdentityStatusService service) {
        this.service = Objects.requireNonNull(service);
        this.binding = null; this.institution = null;
    }

    public record StatusRequest(@NotBlank String installationId,
                                @NotBlank String keyThumbprint) { }

    public record EligibilityRequest(@NotBlank String installationId,
                                     @NotBlank String keyThumbprint,
                                     @NotBlank String entityCode) { }
    public record EligibilityResponse(boolean authorized) { }

    @PostMapping("/verifier-eligible")
    public ResponseEntity<EligibilityResponse> eligible(@Valid @RequestBody EligibilityRequest req) {
        if (binding == null || institution == null) throw new SecurityException("Unavailable");
        // Key originates from MiMoto's fresh OAuth Client Attestation and signed PoP.
        binding.verifyActiveInstallationForStart(req.installationId(), req.keyThumbprint());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(
            new EligibilityResponse(institution.checkVerifiedInstallation(req.installationId(),
                req.entityCode()) == InstitutionalAuthorizationService.Decision.ALLOW));
    }

    @PostMapping("/status")
    public ResponseEntity<HolderIdentityStatusService.Status> status(
        @Valid @RequestBody StatusRequest request) {
        return ResponseEntity.ok()
            .cacheControl(CacheControl.noStore())
            .body(service.get(request.installationId(), request.keyThumbprint()));
    }
}
