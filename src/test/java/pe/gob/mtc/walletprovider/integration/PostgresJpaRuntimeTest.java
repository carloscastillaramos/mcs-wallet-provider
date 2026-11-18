package pe.gob.mtc.walletprovider.integration;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import pe.gob.mtc.walletprovider.domain.Audit;
import pe.gob.mtc.walletprovider.domain.AuditId;
import pe.gob.mtc.walletprovider.domain.AuditRepository;
import pe.gob.mtc.walletprovider.domain.Challenge;
import pe.gob.mtc.walletprovider.domain.ChallengeRepository;
import pe.gob.mtc.walletprovider.domain.Installation;
import pe.gob.mtc.walletprovider.domain.InstallationRepository;

import javax.sql.DataSource;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pruebas OPCIONALES de Spring Data JPA sobre PostgreSQL local desechable.
 * Las operaciones son transacciones reales; no afectan codigo productivo.
 */
@DataJpaTest(properties = {
        "spring.flyway.enabled=true",
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.datasource.hikari.maximum-pool-size=8"
})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@EnabledIfEnvironmentVariable(named = "WALLET_PG_DEEP_IT", matches = "true")
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class PostgresJpaRuntimeTest {

    @DynamicPropertySource
    static void localPostgres(DynamicPropertyRegistry registry) {
        String url = required("WALLET_PG_JDBC_URL");
        if (!(url.startsWith("jdbc:postgresql://127.0.0.1:55432/")
                || url.startsWith("jdbc:postgresql://localhost:55432/"))) {
            throw new IllegalStateException("Prueba permitida solo sobre PostgreSQL local:55432");
        }
        registry.add("spring.datasource.url", () -> url);
        registry.add("spring.datasource.username", () -> required("WALLET_PG_USER"));
        registry.add("spring.datasource.password", () -> required("WALLET_PG_PASSWORD"));
    }

    private static String required(String key) {
        String value = System.getenv(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Variable obligatoria de laboratorio: " + key);
        }
        return value;
    }

    @Autowired private ChallengeRepository challenges;
    @Autowired private InstallationRepository installations;
    @Autowired private AuditRepository audits;
    @Autowired private PlatformTransactionManager transactionManager;
    @Autowired private DataSource dataSource;

    private TransactionTemplate tx;
    private JdbcTemplate jdbc;
    private final List<String> challengeIds = new ArrayList<>();
    private final List<String> installationIds = new ArrayList<>();
    private String correlationId;

    @BeforeEach
    void initialize() {
        tx = new TransactionTemplate(transactionManager);
        jdbc = new JdbcTemplate(dataSource);
        correlationId = "test-" + UUID.randomUUID();
    }

    @AfterEach
    void cleanOnlySyntheticRecords() {
        jdbc.update("DELETE FROM wallet_provider.wp_audit WHERE correlation_id=?", correlationId);
        for (String id : installationIds) {
            jdbc.update("DELETE FROM wallet_provider.wp_installation WHERE id=?", id);
        }
        for (String id : challengeIds) {
            jdbc.update("DELETE FROM wallet_provider.wp_challenge WHERE id=?", id);
        }
    }

    @Test
    void validatesSchemaAndPersistsAllThreeJpaEntities() {
        String challengeId = nextChallengeId();
        String installationId = nextInstallationId();
        String keyId = "key-" + UUID.randomUUID();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.MICROS);
        Audit audit = new Audit(installationId, "ENROLL", "ACCEPTED", correlationId);
        audit.createdAt = now;

        tx.executeWithoutResult(status -> {
            challenges.saveAndFlush(new Challenge(challengeId, "ANDROID", "nonce-test",
                    now.plusMinutes(3)));
            installations.saveAndFlush(new Installation(installationId, "ANDROID", keyId,
                    "TEST_PUBLIC_KEY", "ANDROID_TEE", "pe.gob.mtc.test", 0));
            audits.saveAndFlush(audit);
        });

        tx.executeWithoutResult(status -> {
            assertEquals("nonce-test", challenges.findById(challengeId).orElseThrow().nonce);
            assertTrue(installations.existsByPlatformAndKeyId("ANDROID", keyId));
            assertEquals("ACTIVE", installations.findById(installationId).orElseThrow().status);
            assertTrue(audits.findById(new AuditId(audit.id, audit.createdAt)).isPresent());
        });

        String partition = jdbc.queryForObject(
                "SELECT tableoid::regclass::text FROM wallet_provider.wp_audit WHERE correlation_id=?",
                String.class, correlationId);
        assertNotNull(partition);
        assertTrue(partition.contains("wp_audit_"), "La auditoria debe residir en una particion mensual");
    }

    @Test
    void concurrentChallengeLockAllowsOnlyOneConsumption() throws Exception {
        String challengeId = nextChallengeId();
        tx.executeWithoutResult(status -> challenges.saveAndFlush(new Challenge(challengeId,
                "ANDROID", "lock-test", OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(3))));

        CountDownLatch firstLocked = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch secondStarted = new CountDownLatch(1);
        ExecutorService workers = Executors.newFixedThreadPool(2);
        try {
            Future<Boolean> first = workers.submit(() -> tx.execute(status -> {
                Challenge challenge = challenges.lockById(challengeId).orElseThrow();
                firstLocked.countDown();
                await(releaseFirst);
                if (challenge.consumedAt != null) return false;
                challenge.consumedAt = OffsetDateTime.now(ZoneOffset.UTC);
                challenges.saveAndFlush(challenge);
                return true;
            }));

            assertTrue(firstLocked.await(10, TimeUnit.SECONDS), "Primera transaccion no obtuvo el bloqueo");

            Future<Boolean> second = workers.submit(() -> {
                secondStarted.countDown();
                return tx.execute(status -> {
                    Challenge challenge = challenges.lockById(challengeId).orElseThrow();
                    if (challenge.consumedAt != null) return false;
                    challenge.consumedAt = OffsetDateTime.now(ZoneOffset.UTC);
                    challenges.saveAndFlush(challenge);
                    return true;
                });
            });
            assertTrue(secondStarted.await(10, TimeUnit.SECONDS));
            // Dar oportunidad a la segunda transaccion de intentar tomar el bloqueo.
            Thread.sleep(200);
            assertFalse(second.isDone(), "La segunda transaccion no debe consumir antes del commit");
            releaseFirst.countDown();

            assertTrue(Boolean.TRUE.equals(first.get(15, TimeUnit.SECONDS)));
            assertFalse(Boolean.TRUE.equals(second.get(15, TimeUnit.SECONDS)),
                    "La segunda transaccion debe ver el desafio consumido");

            OffsetDateTime consumedAt = tx.execute(status ->
                    challenges.findById(challengeId).orElseThrow().consumedAt);
            assertNotNull(consumedAt);
        } finally {
            releaseFirst.countDown();
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(10, TimeUnit.SECONDS));
        }
    }

    @Test
    void removesExpiredChallengesInBoundedBatchesWithoutDeletingValidOnes() {
        String expiredId = nextChallengeId();
        String freshId = nextChallengeId();
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        tx.executeWithoutResult(status -> {
            challenges.saveAndFlush(new Challenge(expiredId, "ANDROID", "expired-nonce",
                    now.minusDays(3)));
            challenges.saveAndFlush(new Challenge(freshId, "ANDROID", "fresh-nonce",
                    now.plusMinutes(5)));
        });

        int removed = tx.execute(status -> challenges.purgeExpiredBatch());
        assertTrue(removed >= 1);
        assertEquals(Boolean.FALSE, tx.execute(status -> challenges.existsById(expiredId)));
        assertEquals(Boolean.TRUE, tx.execute(status -> challenges.existsById(freshId)));
    }

    private String nextChallengeId() {
        String id = UUID.randomUUID().toString();
        challengeIds.add(id);
        return id;
    }

    private String nextInstallationId() {
        String id = UUID.randomUUID().toString();
        installationIds.add(id);
        return id;
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timeout esperando la transaccion concurrente");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Prueba interrumpida", e);
        }
    }
}
