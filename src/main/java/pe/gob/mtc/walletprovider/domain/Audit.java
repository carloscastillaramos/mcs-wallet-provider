package pe.gob.mtc.walletprovider.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

/** Composite primary key required by PostgreSQL partitioned audit table. */
@Entity
@Table(name = "WP_AUDIT")
@IdClass(AuditId.class)
public class Audit {
    @Id
    @Column(name = "ID", nullable = false, length = 36)
    public String id = UUID.randomUUID().toString();

    @Id
    @Column(name = "CREATED_AT", nullable = false)
    public OffsetDateTime createdAt = OffsetDateTime.now(ZoneOffset.UTC);

    @Column(name = "INSTALLATION_ID", length = 36)
    public String installationId;

    @Column(name = "ACTION", nullable = false, length = 40)
    public String action;

    @Column(name = "RESULT", nullable = false, length = 24)
    public String result;

    @Column(name = "CORRELATION_ID", length = 64)
    public String correlationId;

    protected Audit() {}

    public Audit(String installationId, String action, String result, String correlationId) {
        this.installationId = installationId;
        this.action = action;
        this.result = result;
        this.correlationId = correlationId;
    }
}
