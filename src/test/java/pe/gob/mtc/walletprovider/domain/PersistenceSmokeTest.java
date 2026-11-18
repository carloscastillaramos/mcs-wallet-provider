package pe.gob.mtc.walletprovider.domain;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.TestPropertySource;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@TestPropertySource(properties={
    "spring.flyway.enabled=false",
    "spring.jpa.hibernate.ddl-auto=create-drop",
    "spring.datasource.url=jdbc:h2:mem:wallet_provider_tests;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
    "spring.datasource.driver-class-name=org.h2.Driver",
    "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
    "spring.jpa.properties.hibernate.default_schema=PUBLIC"
})
class PersistenceSmokeTest {
    @Autowired ChallengeRepository challenges;
    @Autowired InstallationRepository installations;
    @Autowired AuditRepository audits;
    @Test void persistsChallengeInstallationAndAuditOnH2() {
        var challenge=new Challenge(UUID.randomUUID().toString(),"ANDROID","temporary-random",
            OffsetDateTime.now(ZoneOffset.UTC).plusMinutes(3));
        challenges.saveAndFlush(challenge);
        assertEquals("temporary-random",challenges.lockById(challenge.id).orElseThrow().nonce);
        var installation=new Installation(UUID.randomUUID().toString(),"ANDROID","key-qa","PUBLIC KEY QA",
            "ANDROID_TEE","test.package",0);
        installations.saveAndFlush(installation);
        assertTrue(installations.existsByPlatformAndKeyId("ANDROID","key-qa"));
        assertEquals("ACTIVE",installations.lockById(installation.id).orElseThrow().status);
        var audit=audits.saveAndFlush(new Audit(installation.id,"ENROLL","ACCEPTED",null));
        assertTrue(audits.findById(new AuditId(audit.id,audit.createdAt)).isPresent());
    }
}
