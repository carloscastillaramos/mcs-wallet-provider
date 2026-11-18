package pe.gob.mtc.walletprovider.domain;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import jakarta.persistence.LockModeType;
import java.util.Optional;
public interface InstallationRepository extends JpaRepository<Installation,String> {
    boolean existsByPlatformAndKeyId(String platform,String keyId);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @org.springframework.data.jpa.repository.Query("select i from Installation i where i.id = :id")
    Optional<Installation> lockById(String id);
}
