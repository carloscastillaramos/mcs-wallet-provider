package pe.gob.mtc.walletprovider.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pe.gob.mtc.walletprovider.api.ApiModels.*;
import pe.gob.mtc.walletprovider.config.ProviderProperties;
import pe.gob.mtc.walletprovider.domain.*;
import pe.gob.mtc.walletprovider.platform.*;
import pe.gob.mtc.walletprovider.security.*;
import pe.gob.mtc.walletprovider.sync.DiagnosticsOutbox;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.*;
import java.util.*;

@Service
public class EnrollmentService {
    private final ChallengeRepository challenges;
    private final InstallationRepository installations;
    private final AuditRepository audit;
    private final ProviderProperties config;
    private final AndroidIntegrityVerifier play;
    private final AndroidKeyAttestationVerifier androidKeys;
    private final IosAppAttestVerifier apple;
    private final ProofVerifier proof;
    private final AttestationSigner signer;
    private final DiagnosticsKeyRepository diagnosticsKeys;
    private final DiagnosticsOutbox diagnosticsOutbox;
    private final SecureRandom random=new SecureRandom();

    public EnrollmentService(ChallengeRepository challenges,InstallationRepository installations,AuditRepository audit,
                             ProviderProperties config,AndroidIntegrityVerifier play,AndroidKeyAttestationVerifier androidKeys,
                             IosAppAttestVerifier apple,ProofVerifier proof,AttestationSigner signer,
                             DiagnosticsKeyRepository diagnosticsKeys,DiagnosticsOutbox diagnosticsOutbox) {
        this.challenges=challenges;this.installations=installations;this.audit=audit;this.config=config;
        this.play=play;this.androidKeys=androidKeys;this.apple=apple;this.proof=proof;this.signer=signer;
        this.diagnosticsKeys=diagnosticsKeys;this.diagnosticsOutbox=diagnosticsOutbox;
    }
    @Transactional
    public ChallengeResponse challenge(ChallengeRequest req) {
        String platform=req.platform().toUpperCase(Locale.ROOT);
        if(!List.of("ANDROID","IOS").contains(platform)) throw new IllegalArgumentException("Unsupported platform");
        byte[] bytes=new byte[32];random.nextBytes(bytes);
        String nonce=Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        Challenge c=new Challenge(UUID.randomUUID().toString(),platform,nonce,OffsetDateTime.now(ZoneOffset.UTC).plusSeconds(config.policy().challengeSeconds()));
        challenges.save(c);
        return new ChallengeResponse(c.id,c.nonce,c.expiresAt);
    }
    private Challenge consume(String id,String platform) {
        Challenge c=challenges.lockById(id).orElseThrow(()->new SecurityException("Unknown challenge"));
        if(!platform.equals(c.platform) || c.consumedAt!=null || !c.expiresAt.isAfter(OffsetDateTime.now(ZoneOffset.UTC)))
            throw new SecurityException("Challenge invalid, consumed or expired");
        c.consumedAt=OffsetDateTime.now(ZoneOffset.UTC);
        return c;
    }
    @Transactional
    public EnrollmentResponse android(AndroidEnrollment req) throws Exception {
        Challenge c=consume(req.challengeId(),"ANDROID");
        PublicKey key=proof.decodePem(req.publicKeyPem());
        String signedMessage="wp-enroll:"+c.id+":"+c.nonce+":"+req.keyId();
        proof.verify(key,signedMessage,req.proofSignature());
        String assurance=androidKeys.verify(req.keyAttestationChain(),c.nonce,key);
        play.verify(req.playIntegrityToken(),AndroidIntegrityVerifier.requestHash(c.id,c.nonce,req.keyId(),req.publicKeyPem()));
        return register("ANDROID",req.keyId(),req.publicKeyPem(),assurance,config.android().packageName(),0);
    }
    @Transactional
    public EnrollmentResponse ios(IosEnrollment req) throws Exception {
        Challenge c=consume(req.challengeId(),"IOS");
        IosAppAttestVerifier.VerifiedKey verified=apple.verifyEnrollment(req.attestationObject(),req.keyId(),c.nonce);
        return register("IOS",req.keyId(),verified.pem(),"APPLE_APP_ATTEST",config.ios().appId(),verified.counter());
    }
    private EnrollmentResponse register(String platform,String keyId,String pem,String assurance,String app,long counter) {
        if(installations.existsByPlatformAndKeyId(platform,keyId)) throw new SecurityException("Installation key already registered");
        Installation i=installations.save(new Installation(UUID.randomUUID().toString(),platform,keyId,pem,assurance,app,counter));
        audit.save(new Audit(i.id,"ENROLL","ACCEPTED",null));
        return new EnrollmentResponse(i.id,i.status,i.assurance);
    }
    @Transactional(readOnly=true)
    public TrustResponse trust(String id) {
        Installation i=installations.findById(id).orElseThrow(()->new NoSuchElementException("Installation unavailable"));
        return new TrustResponse(i.id,i.platform,i.status,i.assurance);
    }
    @Transactional
    public void revoke(String id) {
        Installation i=installations.lockById(id).orElseThrow(()->new NoSuchElementException("Installation unavailable"));
        if("REVOKED".equals(i.status)) return; // idempotent administrator operation
        i.status="REVOKED";i.updatedAt=OffsetDateTime.now(ZoneOffset.UTC);
        // Committed atomically with installation revocation. Do not invoke HTTP in this transaction.
        for(DiagnosticsKey key:diagnosticsKeys.findByInstallationIdAndStatus(i.id,"ACTIVE")) {
            key.status="REVOKED";
            key.revokedAt=OffsetDateTime.now(ZoneOffset.UTC);
            diagnosticsOutbox.enqueueRevoke(i.id,key.keyId,i.platform);
        }
        audit.save(new Audit(i.id,"REVOKE","ACCEPTED",null));
    }
    @Transactional
    public AttestationResponse attestAndroid(InstallationProofRequest req,String purpose) throws Exception {
        Installation i=active(req.installationId(),"ANDROID");
        Challenge c=consume(req.challengeId(),"ANDROID");
        proof.verify(proof.decodePem(i.publicKey),"wp-attest:"+purpose+":"+c.id+":"+c.nonce+":"+i.id,req.proofSignature());
        return issue(i,purpose);
    }
    @Transactional
    public AttestationResponse attestIos(InstallationIosProofRequest req,String purpose) throws Exception {
        Installation i=active(req.installationId(),"IOS");
        Challenge c=consume(req.challengeId(),"IOS");
        i.counterValue=apple.verifyAssertion(req.assertionObject(),c.nonce,i.publicKey,i.counterValue);
        i.updatedAt=OffsetDateTime.now(ZoneOffset.UTC);
        return issue(i,purpose);
    }
    /**
     * Attests the actual credential public key after independently verifying:
     * the registered installation's signature, the credential key's possession,
     * and Android's hardware attestation of that exact credential key.
     *
     * A nonce supplied by the Credential Issuer is carried into the signed
     * Key Attestation, as required when OpenID4VCI uses c_nonce.
     */
    @Transactional
    public AttestationResponse attestAndroidCredentialKey(AndroidCredentialKeyAttestationRequest req) throws Exception {
        Installation installation=active(req.installationId(),"ANDROID");
        Challenge challenge=consume(req.challengeId(),"ANDROID");
        if(req.issuerNonce().length()>1024) throw new IllegalArgumentException("Issuer nonce too long");

        PublicKey credentialKey=proof.decodePem(req.credentialPublicKeyPem());
        PublicKey installationKey=proof.decodePem(installation.publicKey);
        String credentialKeyHash=sha256Url(credentialKey.getEncoded());
        String issuerNonceHash=sha256Url(req.issuerNonce().getBytes(StandardCharsets.UTF_8));
        String signedMessage="wp-credential-key:v1:"+challenge.id+":"+challenge.nonce+":"+
            installation.id+":"+credentialKeyHash+":"+issuerNonceHash;

        proof.verify(installationKey,signedMessage,req.installationProofSignature());
        proof.verify(credentialKey,signedMessage,req.credentialProofSignature());
        String assurance=androidKeys.verify(req.credentialKeyAttestationChain(),challenge.nonce,credentialKey);
        String token=signer.keyAttestation(credentialKey,config.policy().attestationSeconds(),req.issuerNonce());
        audit.save(new Audit(installation.id,"CREDENTIAL_KEY_ATTESTATION","ISSUED",assurance));
        return new AttestationResponse(token,Instant.now().plusSeconds(config.policy().attestationSeconds()).toString());
    }
    private static String sha256Url(byte[] value) throws NoSuchAlgorithmException {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(value));
    }
    private Installation active(String id,String platform) {
        Installation i=installations.lockById(id).orElseThrow(()->new SecurityException("Unknown installation"));
        if(!platform.equals(i.platform) || !"ACTIVE".equals(i.status)) throw new SecurityException("Installation not active");
        return i;
    }
    private AttestationResponse issue(Installation i,String purpose) {
        long seconds=config.policy().attestationSeconds();
        PublicKey installationKey;
        try { installationKey=proof.decodePem(i.publicKey); }
        catch(GeneralSecurityException e) { throw new SecurityException("Stored installation key invalid",e); }
        String token="key_attestation".equals(purpose)
            ? signer.keyAttestation(installationKey,seconds)
            : signer.walletAttestation(installationKey,seconds);
        audit.save(new Audit(i.id,purpose,"ISSUED",null));
        return new AttestationResponse(token,Instant.now().plusSeconds(seconds).toString());
    }
}
