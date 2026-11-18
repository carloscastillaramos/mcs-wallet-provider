package pe.gob.mtc.walletprovider.domain;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;
import jakarta.persistence.LockModeType;
import java.util.Optional;
public interface ChallengeRepository extends JpaRepository<Challenge,String> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @org.springframework.data.jpa.repository.Query("select c from Challenge c where c.id = :id")
    Optional<Challenge> lockById(String id);

    @Modifying
    @Transactional
    @Query(value = "DELETE FROM wallet_provider.wp_challenge WHERE id IN ("
            + "SELECT id FROM wallet_provider.wp_challenge "
            + "WHERE expires_at < CURRENT_TIMESTAMP - INTERVAL '1 day' "
            + "ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED)", nativeQuery = true)
    int purgeExpiredBatch();
}
