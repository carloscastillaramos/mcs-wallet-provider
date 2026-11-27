package pe.gob.mtc.walletprovider.identity;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.Objects;

/**
 * The caller is Certify (not Wallet). Certify MUST first validate the OpenID4VCI
 * proof signature/audience/c_nonce and tie the signed Key Attestation to its JWK.
 * Only then may it forward the thumbprint computed from THAT verified proof key
 * and the c_nonce read from its own issuance session. No installationId or DNI.
 * Fail closed: never authorize merely because a token or a JWT is present.
 */
@RestController
@RequestMapping("/api/v1/internal/identity/certify")
@ConditionalOnProperty(prefix = "wallet-provider.identity",
        name = {"enabled", "credential-binding.enabled", "certify-m2m.enabled"},
        havingValue = "true")
public final class CertifyIssuanceM2mController {
    private final CredentialKeyBindingRegistry registry;

    public CertifyIssuanceM2mController(CredentialKeyBindingRegistry registry) {
        this.registry = Objects.requireNonNull(registry);
    }

    public record AuthorizeRequest(
        @NotBlank @Pattern(regexp = "[A-Za-z0-9_-]{43}") String credentialKeyThumbprint,
        @NotBlank @Size(max = 1024) String issuerNonce) { }

    @PostMapping("/authorize-issuance")
    public ResponseEntity<Void> authorize(@Valid @RequestBody AuthorizeRequest request) {
        if (!registry.activeAccreditedBinding(request.credentialKeyThumbprint(), request.issuerNonce())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Issuance not authorized");
        }
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
    }
}
