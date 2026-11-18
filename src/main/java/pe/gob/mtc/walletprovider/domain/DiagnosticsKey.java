package pe.gob.mtc.walletprovider.domain;

import jakarta.persistence.*;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

@Entity
@Table(name="WP_DIAGNOSTICS_KEY")
@IdClass(DiagnosticsKeyId.class)
public class DiagnosticsKey {
    @Id @Column(name="INSTALLATION_ID", length=36) public String installationId;
    @Id @Column(name="KEY_ID", length=64) public String keyId;
    @Column(name="PUBLIC_KEY_SPKI_B64", nullable=false,length=2048) public String publicKeySpkiBase64;
    @Column(nullable=false,length=16) public String status;
    @Column(name="CREATED_AT", nullable=false) public OffsetDateTime createdAt;
    @Column(name="REVOKED_AT") public OffsetDateTime revokedAt;
    protected DiagnosticsKey() {}
    public DiagnosticsKey(String installationId, String keyId, String spki) {
        this.installationId=installationId; this.keyId=keyId; this.publicKeySpkiBase64=spki;
        this.status="ACTIVE"; this.createdAt=OffsetDateTime.now(ZoneOffset.UTC);
    }
}
