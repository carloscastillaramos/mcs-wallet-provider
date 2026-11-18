package pe.gob.mtc.walletprovider.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pe.gob.mtc.walletprovider.api.ApiModels.*;
import pe.gob.mtc.walletprovider.domain.*;
import pe.gob.mtc.walletprovider.platform.IosAppAttestVerifier;
import pe.gob.mtc.walletprovider.security.ProofVerifier;
import pe.gob.mtc.walletprovider.sync.DiagnosticsOutbox;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;

@Service
public class DiagnosticsKeyBindingService {
    private final InstallationRepository installations;
    private final ChallengeRepository challenges;
    private final DiagnosticsKeyRepository keys;
    private final AuditRepository audit;
    private final ProofVerifier proof;
    private final IosAppAttestVerifier apple;
    private final DiagnosticsOutbox outbox;

    public DiagnosticsKeyBindingService(InstallationRepository installations,ChallengeRepository challenges,
            DiagnosticsKeyRepository keys,AuditRepository audit,ProofVerifier proof,
            IosAppAttestVerifier apple,DiagnosticsOutbox outbox) {
        this.installations=installations;this.challenges=challenges;this.keys=keys;this.audit=audit;
        this.proof=proof;this.apple=apple;this.outbox=outbox;
    }

    @Transactional
    public DiagnosticsKeyResponse bind(String installationId,DiagnosticsKeyBindingRequest request) throws Exception {
        if(!request.keyId().matches("[A-Za-z0-9_-]{1,64}")) throw new IllegalArgumentException("Invalid key ID");
        Installation i=installations.lockById(installationId)
                .orElseThrow(()->new SecurityException("Unknown installation"));
        if(!"ACTIVE".equals(i.status)) throw new SecurityException("Installation not active");
        Challenge challenge=challenges.lockById(request.challengeId())
                .orElseThrow(()->new SecurityException("Unknown challenge"));
        if(!i.platform.equals(challenge.platform) || challenge.consumedAt!=null ||
                !challenge.expiresAt.isAfter(OffsetDateTime.now(ZoneOffset.UTC)))
            throw new SecurityException("Challenge invalid, consumed or expired");

        // The diagnostics key is distinct from the installation App Attest key on iOS.
        PublicKey diagnosticsKey=decodeP256(request.publicKeySpkiBase64());
        String normalized=Base64.getEncoder().encodeToString(diagnosticsKey.getEncoded());
        String digest=Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(diagnosticsKey.getEncoded()));
        String message="wp-diagnostics-bind:v1:"+i.id+":"+challenge.id+":"+challenge.nonce+":"+request.keyId()+":"+digest;
        proof.verify(diagnosticsKey,message,request.keyProofSignature());

        if("ANDROID".equals(i.platform)) {
            if(request.installationProofSignature()==null || request.installationProofSignature().isBlank())
                throw new SecurityException("Installation signature required");
            proof.verify(proof.decodePem(i.publicKey),message,request.installationProofSignature());
        } else if("IOS".equals(i.platform)) {
            if(request.appAttestAssertion()==null || request.appAttestAssertion().isBlank())
                throw new SecurityException("App Attest assertion required");
            i.counterValue=apple.verifyAssertion(request.appAttestAssertion(),message,i.publicKey,i.counterValue);
            i.updatedAt=OffsetDateTime.now(ZoneOffset.UTC);
        } else throw new SecurityException("Unsupported platform");
        if(keys.existsById(new DiagnosticsKeyId(i.id,request.keyId())))
            throw new SecurityException("Diagnostics key already bound");
        challenge.consumedAt=OffsetDateTime.now(ZoneOffset.UTC);
        keys.save(new DiagnosticsKey(i.id,request.keyId(),normalized));
        audit.save(new Audit(i.id,"DIAGNOSTICS_KEY_BIND","ACCEPTED",null));
        outbox.enqueueRegister(i.id,request.keyId(),i.platform,normalized);
        return new DiagnosticsKeyResponse(i.id,request.keyId(),"PENDING_SYNC");
    }

    private static PublicKey decodeP256(String encoded) throws Exception {
        if(encoded==null || encoded.length()>2048) throw new SecurityException("Invalid diagnostics public key");
        byte[] der=Base64.getDecoder().decode(encoded);
        PublicKey key=KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
        if(!(key instanceof ECPublicKey ec)) throw new SecurityException("Diagnostics key must be P-256");
        AlgorithmParameters params=AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec expected=params.getParameterSpec(ECParameterSpec.class);
        if(!ec.getParams().getCurve().equals(expected.getCurve()) ||
                !ec.getParams().getGenerator().equals(expected.getGenerator()) ||
                !ec.getParams().getOrder().equals(expected.getOrder()) ||
                ec.getParams().getCofactor()!=expected.getCofactor())
            throw new SecurityException("Diagnostics key must be P-256");
        return key;
    }
}
