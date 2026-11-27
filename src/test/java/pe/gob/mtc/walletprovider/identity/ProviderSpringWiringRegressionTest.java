package pe.gob.mtc.walletprovider.identity;

import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import pe.gob.mtc.walletprovider.security.ProofVerifier;

import java.time.Clock;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Regression for constructor selection and transactional Spring proxies.
 * All dependencies are local mocks; no DB, AWS, RENIEC, or external network.
 */
class ProviderSpringWiringRegressionTest {

    @Test
    void injectsDependenciesWithoutDefaultConstructorAndCreatesTransactionalProxies() {
        try (var context = new AnnotationConfigApplicationContext()) {
            context.register(TestBeans.class,
                HolderInstallationBindingVerifier.class,
                HolderIdentityStatusService.class);
            context.refresh();

            var binding = context.getBean(HolderInstallationBindingVerifier.class);
            var status = context.getBean(HolderIdentityStatusService.class);
            var accreditation = context.getBean(IdentityAccreditationService.class);

            assertAll(
                () -> assertNotNull(binding),
                () -> assertNotNull(status),
                () -> assertNotNull(accreditation),
                () -> assertTrue(AopUtils.isCglibProxy(binding), "Binding verifier requires transactional proxy"),
                () -> assertTrue(AopUtils.isCglibProxy(status), "Holder status requires transactional proxy"),
                () -> assertTrue(AopUtils.isCglibProxy(accreditation), "Accreditation requires transactional proxy")
            );
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableTransactionManagement(proxyTargetClass = true)
    static class TestBeans {
        @Bean JdbcTemplate jdbcTemplate() { return mock(JdbcTemplate.class); }
        @Bean ProofVerifier proofVerifier() { return mock(ProofVerifier.class); }
        @Bean PlatformTransactionManager transactionManager() { return mock(PlatformTransactionManager.class); }
        @Bean IdentityAccreditationService identityAccreditationService(JdbcTemplate jdbcTemplate) {
            return new IdentityAccreditationService(jdbcTemplate,
                mock(HolderIdentityCrypto.class),
                mock(TrustedReniecEvidenceVerifier.class),
                Clock.systemUTC());
        }
    }
}
