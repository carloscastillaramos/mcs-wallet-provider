package pe.gob.mtc.walletprovider.identity;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import java.time.Instant;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;
import java.util.UUID;

/**
 * Contrato privado, exclusivamente para MiMoto autenticado con Cognito M2M.
 * Este controlador no inicia sesion Wallet ni verifica un PoP de movil:
 * MiMoto primero debe hacer MtcWalletSessionGate.authorize+requireBoundHolderSession.
 * Los controles obligatorios de seguridad se aplican también en SecurityConfig.
 * No registra ni devuelve el DNI o la evidencia firmada.
 */
@RestController
@RequestMapping("/api/v1/internal/identity/mimoto")
@ConditionalOnProperty(prefix = "wallet-provider.identity", name = {"enabled", "mimoto-m2m.enabled"}, havingValue = "true")
public class MimotoIdentityM2mController {
    private final HolderInstallationBindingVerifier bindingVerifier;
    private final IdentityAccreditationService accreditationService;

    public MimotoIdentityM2mController(HolderInstallationBindingVerifier bindingVerifier,
                                      IdentityAccreditationService accreditationService) {
        this.bindingVerifier = Objects.requireNonNull(bindingVerifier);
        this.accreditationService = Objects.requireNonNull(accreditationService);
    }

    public record BindingRequest(@NotNull UUID identitySessionId,
                                 @NotBlank String installationId,
                                 @NotBlank String nonce,
                                 @NotBlank String keyThumbprint) { }

    public record CompletionRequest(@NotNull UUID identitySessionId,
                                    @NotBlank String installationId,
                                    @NotBlank String nonce,
                                    @NotBlank String keyThumbprint,
                                    @NotBlank @Size(max = 16384) String signedEvidence) { }

    public record StartRequest(@NotBlank String installationId,
                               @NotBlank String keyThumbprint) { }
    public record StartResponse(UUID sessionId, String nonce, Instant expiresAt) { }

    /**
     * MiMoto ya verifico la atestacion y el PoP de Wallet. La API interna
     * valida nuevamente la clave en Provider antes de crear la sesion.
     * Los identificadores y el nonce SIEMPRE se generan en Provider.
     */
    @PostMapping("/start")
    public ResponseEntity<StartResponse> start(@Valid @RequestBody StartRequest request) {
        bindingVerifier.verifyActiveInstallationForStart(request.installationId(),
            request.keyThumbprint());
        IdentityAccreditationService.Started result =
            accreditationService.beginForProvenInstallation(request.installationId());
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(new StartResponse(result.sessionId(), result.nonce(), result.expiresAt()));
    }

    @PostMapping("/verify-binding")
    public ResponseEntity<Void> verifyBinding(@Valid @RequestBody BindingRequest request) {
        bindingVerifier.verifyPendingSession(request.identitySessionId(), request.installationId(),
            request.nonce(), request.keyThumbprint());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/complete")
    public ResponseEntity<Void> complete(@Valid @RequestBody CompletionRequest request) {
        // Revalidacion dentro de Provider, sin confiar en una confirmacion previa de MiMoto.
        bindingVerifier.verifyPendingSession(request.identitySessionId(), request.installationId(),
            request.nonce(), request.keyThumbprint());
        // completeFromTrustedEvidence valida sessionId, nonce y installationId del JWT
        // bajo lock transaccional, ademas de la evidencia firmada de MiMoto.
        accreditationService.completeFromTrustedEvidence(request.identitySessionId(),
            request.nonce(), request.signedEvidence());
        return ResponseEntity.noContent().build();
    }
}
