package pe.gob.mtc.walletprovider.domain;

import jakarta.persistence.*;
import java.time.OffsetDateTime;

@Entity @Table(name = "WP_CHALLENGE")
public class Challenge {
    @Id @Column(length=36) public String id;
    @Column(nullable=false,length=10) public String platform;
    @Column(nullable=false,length=128) public String nonce;
    @Column(name="EXPIRES_AT",nullable=false) public OffsetDateTime expiresAt;
    @Column(name="CONSUMED_AT") public OffsetDateTime consumedAt;
    @Column(name="CREATED_AT",nullable=false) public OffsetDateTime createdAt;
    protected Challenge() {}
    public Challenge(String id, String platform, String nonce, OffsetDateTime expiry) {
        this.id=id; this.platform=platform; this.nonce=nonce; this.expiresAt=expiry; this.createdAt=OffsetDateTime.now(java.time.ZoneOffset.UTC);
    }
}
