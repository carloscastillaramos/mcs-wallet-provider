package pe.gob.mtc.walletprovider.domain;

import jakarta.persistence.*;
import java.time.OffsetDateTime;

@Entity @Table(name="WP_INSTALLATION", uniqueConstraints=@UniqueConstraint(columnNames={"PLATFORM","KEY_ID"}))
public class Installation {
    @Id @Column(length=36) public String id;
    @Column(nullable=false,length=10) public String platform;
    @Column(name="KEY_ID",nullable=false) public String keyId;
    @Column(name="PUBLIC_KEY",nullable=false,columnDefinition="text") public String publicKey;
    @Column(nullable=false,length=16) public String status;
    @Column(nullable=false,length=48) public String assurance;
    @Column(name="APP_IDENTIFIER",nullable=false) public String appIdentifier;
    @Column(name="COUNTER_VALUE",nullable=false) public long counterValue;
    @Column(name="CREATED_AT",nullable=false) public OffsetDateTime createdAt;
    @Column(name="UPDATED_AT",nullable=false) public OffsetDateTime updatedAt;
    protected Installation() {}
    public Installation(String id, String platform, String keyId, String publicKey, String assurance, String appIdentifier, long counter) {
        this.id=id; this.platform=platform; this.keyId=keyId; this.publicKey=publicKey;
        this.status="ACTIVE"; this.assurance=assurance; this.appIdentifier=appIdentifier; this.counterValue=counter;
        this.createdAt=OffsetDateTime.now(java.time.ZoneOffset.UTC); this.updatedAt=createdAt;
    }
}
