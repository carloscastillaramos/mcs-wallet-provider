package pe.gob.mtc.walletprovider.institutional;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Uso exclusivo MTC. Todas las mutaciones del padron requieren una aprobacion persistida. */
@RestController
@RequestMapping("/api/v1/mtc/portal")
@ConditionalOnProperty(prefix = "wallet-provider.portal", name = "enabled", havingValue = "true")
public final class MtcPortalAdminController {
    private final MtcOperatorAccess access;
    private final MtcPortalAdministration admin;
    private final MtcPortalImportService imports;
    private final MtcWorkRequestService requests;
    private final MtcOperatorDirectory operators;

    public MtcPortalAdminController(MtcOperatorAccess access, MtcPortalAdministration admin,
                                    MtcPortalImportService imports, MtcWorkRequestService requests,
                                    MtcOperatorDirectory operators) {
        this.access = access;
        this.admin = admin;
        this.imports = imports;
        this.requests = requests;
        this.operators = operators;
    }

    /** Return the domain status directly. Avoid sendError dispatch to /error,
     * which is denied by the restrictive resource-server filter chain. */
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, String>> domainStatus(ResponseStatusException ex) {
        return ResponseEntity.status(ex.getStatusCode()).headers(ex.getHeaders())
            .body(Map.of("code", "PORTAL_REQUEST_REJECTED", "message", "La operación no pudo completarse"));
    }

    @GetMapping("/me")
    public MtcOperatorAccess.Operator me(JwtAuthenticationToken token) {
        return access.require(token);
    }
    @GetMapping("/entities")
    public List<MtcPortalAdministration.Entity> entities(JwtAuthenticationToken token) {
        access.require(token);
        return admin.entities();
    }
    @GetMapping("/entities/{code}/grants")
    public List<MtcPortalAdministration.Grant> grants(@PathVariable String code,
                                                       JwtAuthenticationToken token) {
        access.require(token);
        return admin.grants(code);
    }

    @PostMapping("/entities/{code}/requests/grants")
    public ResponseEntity<Map<String, UUID>> registerGrant(@PathVariable String code,
            @Valid @RequestBody MtcPortalAdministration.CreateGrant request,
            @RequestHeader("Idempotency-Key") String key, JwtAuthenticationToken token) {
        UUID id = requests.registerGrant(code, request, key, access.requireRegister(token));
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("id", id));
    }
    @PostMapping("/entities/{code}/requests/grants/{id}/revoke")
    public ResponseEntity<Map<String, UUID>> registerRevoke(@PathVariable String code,
            @PathVariable UUID id, @Valid @RequestBody MtcWorkRequestService.GrantRevoke request,
            @RequestHeader("Idempotency-Key") String key, JwtAuthenticationToken token) {
        UUID requestId = requests.registerGrantRevoke(code, id, request, key, access.requireRegister(token));
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("id", requestId));
    }
    @PostMapping("/entities/{code}/requests/grants/{id}/installations")
    public ResponseEntity<Map<String, UUID>> registerLink(@PathVariable String code,
            @PathVariable UUID id, @Valid @RequestBody MtcWorkRequestService.InstallationLink request,
            @RequestHeader("Idempotency-Key") String key, JwtAuthenticationToken token) {
        UUID requestId = requests.registerInstallationLink(code, id, request, key, access.requireRegister(token));
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("id", requestId));
    }
    @PostMapping("/entities/{code}/requests/grants/{id}/installations/revoke")
    public ResponseEntity<Map<String, UUID>> registerInstitutionalUnlink(@PathVariable String code,
            @PathVariable UUID id, @Valid @RequestBody MtcWorkRequestService.InstallationUnlink request,
            @RequestHeader("Idempotency-Key") String key, JwtAuthenticationToken token) {
        UUID requestId = requests.registerInstitutionalUnlink(code, id, request, key, access.requireRegister(token));
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("id", requestId));
    }
    @PostMapping("/requests/installations/{id}/revoke")
    public ResponseEntity<Map<String, UUID>> registerGlobalRevocation(@PathVariable UUID id,
            @Valid @RequestBody MtcWorkRequestService.InstallationRevoke request,
            @RequestHeader("Idempotency-Key") String key, JwtAuthenticationToken token) {
        UUID requestId = requests.registerInstallationRevoke(id, request, key, access.requireSuperAdmin(token));
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("id", requestId));
    }

    @GetMapping("/requests")
    public List<MtcWorkRequestService.WorkRequest> pending(
            @RequestParam(value = "entity", required = false) String entity,
            JwtAuthenticationToken token) {
        access.require(token);
        return requests.list(entity);
    }
    @PostMapping("/requests/{id}/approve")
    public ResponseEntity<Void> approve(@PathVariable UUID id, JwtAuthenticationToken token) {
        requests.approve(id, access.requireApprove(token));
        return ResponseEntity.noContent().build();
    }
    @PostMapping("/requests/{id}/reject")
    public ResponseEntity<Void> reject(@PathVariable UUID id,
            @Valid @RequestBody MtcWorkRequestService.Decision decision,
            JwtAuthenticationToken token) {
        requests.reject(id, decision, access.requireApprove(token));
        return ResponseEntity.noContent().build();
    }

    @PostMapping(path = "/entities/{code}/imports", consumes = "multipart/form-data")
    public ResponseEntity<MtcPortalImportService.ImportResult> upload(@PathVariable String code,
            @RequestParam("file") org.springframework.web.multipart.MultipartFile file,
            @RequestHeader("Idempotency-Key") String key,
            JwtAuthenticationToken token) {
        var actor = access.requireRegister(token);
        return ResponseEntity.status(HttpStatus.CREATED).body(imports.validateAndStage(code, file, key, actor));
    }
    @GetMapping("/entities/{code}/imports")
    public List<MtcPortalImportService.ImportResult> imports(@PathVariable String code,
            JwtAuthenticationToken token) {
        access.require(token);
        return imports.list(code);
    }
    @PostMapping("/entities/{code}/imports/{id}/apply")
    public MtcPortalImportService.ImportResult apply(@PathVariable String code,
            @PathVariable UUID id, JwtAuthenticationToken token) {
        return imports.apply(code, id, access.requireApprove(token));
    }
    @PostMapping("/entities/{code}/imports/{id}/reject")
    public ResponseEntity<Void> rejectImport(@PathVariable String code, @PathVariable UUID id,
            @Valid @RequestBody MtcWorkRequestService.Decision decision,
            JwtAuthenticationToken token) {
        imports.reject(code, id, decision.reason(), access.requireApprove(token));
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/operators")
    public List<MtcOperatorDirectory.OperatorRecord> operators(JwtAuthenticationToken token) {
        return operators.list(access.requireSuperAdmin(token));
    }
    @PostMapping("/operators")
    public ResponseEntity<Map<String, UUID>> createOperator(
            @Valid @RequestBody MtcOperatorDirectory.CreateOperator request, JwtAuthenticationToken token) {
        UUID id = operators.create(request, access.requireSuperAdmin(token));
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("id", id));
    }
    @PutMapping("/operators/{id}/roles")
    public ResponseEntity<Void> roles(@PathVariable UUID id,
            @Valid @RequestBody MtcOperatorDirectory.UpdateRoles request, JwtAuthenticationToken token) {
        operators.updateRoles(id, request, access.requireSuperAdmin(token));
        return ResponseEntity.noContent().build();
    }
}
