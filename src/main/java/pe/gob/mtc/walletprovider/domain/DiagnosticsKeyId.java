package pe.gob.mtc.walletprovider.domain;

import java.io.Serializable;
import java.util.Objects;

public class DiagnosticsKeyId implements Serializable {
    public String installationId;
    public String keyId;
    public DiagnosticsKeyId() {}
    public DiagnosticsKeyId(String installationId,String keyId) { this.installationId=installationId; this.keyId=keyId; }
    @Override public boolean equals(Object other) {
        return other instanceof DiagnosticsKeyId id && Objects.equals(installationId,id.installationId)
                && Objects.equals(keyId,id.keyId);
    }
    @Override public int hashCode() { return Objects.hash(installationId,keyId); }
}
