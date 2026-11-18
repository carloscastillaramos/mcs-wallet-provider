package pe.gob.mtc.walletprovider.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface DiagnosticsKeyRepository extends JpaRepository<DiagnosticsKey,DiagnosticsKeyId> {
    List<DiagnosticsKey> findByInstallationIdAndStatus(String installationId, String status);
}
