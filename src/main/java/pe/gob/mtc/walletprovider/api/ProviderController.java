package pe.gob.mtc.walletprovider.api;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import pe.gob.mtc.walletprovider.api.ApiModels.*;
import pe.gob.mtc.walletprovider.security.AttestationSigner;
import pe.gob.mtc.walletprovider.service.EnrollmentService;
import pe.gob.mtc.walletprovider.service.DiagnosticsKeyBindingService;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class ProviderController {
    private final EnrollmentService service;
    private final AttestationSigner signer;
    private final DiagnosticsKeyBindingService diagnosticsKeys;
    public ProviderController(EnrollmentService service,AttestationSigner signer,DiagnosticsKeyBindingService diagnosticsKeys) {
        this.service=service;this.signer=signer;this.diagnosticsKeys=diagnosticsKeys;
    }

    @PostMapping("/enrollments/challenge") public ChallengeResponse challenge(@Valid @RequestBody ChallengeRequest req) {return service.challenge(req);}
    @PostMapping("/enrollments/android") public EnrollmentResponse android(@Valid @RequestBody AndroidEnrollment req) throws Exception {return service.android(req);}
    @PostMapping("/enrollments/ios") public EnrollmentResponse ios(@Valid @RequestBody IosEnrollment req) throws Exception {return service.ios(req);}
    @PostMapping("/installations/{id}/diagnostics-keys")
    public DiagnosticsKeyResponse bindDiagnosticsKey(@PathVariable String id,
            @Valid @RequestBody DiagnosticsKeyBindingRequest request) throws Exception {
        return diagnosticsKeys.bind(id,request);
    }
    @GetMapping("/installations/{id}/trust") public TrustResponse trust(@PathVariable String id) {return service.trust(id);}
    @PostMapping("/installations/{id}/revoke") @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revoke(@PathVariable String id) {service.revoke(id);}
    @PostMapping("/attestations/wallet/android") public AttestationResponse attestAndroid(@Valid @RequestBody InstallationProofRequest req) throws Exception {return service.attestAndroid(req,"wallet_attestation");}
    @PostMapping("/attestations/wallet/ios") public AttestationResponse attestIos(@Valid @RequestBody InstallationIosProofRequest req) throws Exception {return service.attestIos(req,"wallet_attestation");}
    @PostMapping("/attestations/keys/android") public AttestationResponse keyAndroid(@Valid @RequestBody InstallationProofRequest req) throws Exception {return service.attestAndroid(req,"key_attestation");}
    @PostMapping("/attestations/keys/ios") public AttestationResponse keyIos(@Valid @RequestBody InstallationIosProofRequest req) throws Exception {return service.attestIos(req,"key_attestation");}
    @PostMapping("/attestations/credential-keys/android")
    public AttestationResponse credentialKeyAndroid(@Valid @RequestBody AndroidCredentialKeyAttestationRequest req) throws Exception {
        return service.attestAndroidCredentialKey(req);
    }
    @GetMapping("/.well-known/jwks.json") public Map<String,Object> jwks() {return signer.jwks();}
}
