package pe.gob.mtc.walletprovider.domain;

import java.io.Serializable;
import java.time.OffsetDateTime;
import java.util.Objects;

/** Mirrors the composite (id, created_at) primary key of wp_audit. */
public class AuditId implements Serializable {
    public String id;
    public OffsetDateTime createdAt;

    public AuditId() {}

    public AuditId(String id, OffsetDateTime createdAt) {
        this.id = id;
        this.createdAt = createdAt;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof AuditId that)) return false;
        return Objects.equals(id, that.id) && Objects.equals(createdAt, that.createdAt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, createdAt);
    }
}
