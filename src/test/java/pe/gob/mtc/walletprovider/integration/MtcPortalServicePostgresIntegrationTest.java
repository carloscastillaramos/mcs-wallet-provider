package pe.gob.mtc.walletprovider.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.server.ResponseStatusException;
import pe.gob.mtc.walletprovider.identity.HolderIdentityCrypto;
import pe.gob.mtc.walletprovider.institutional.MtcOperatorAccess;
import pe.gob.mtc.walletprovider.institutional.MtcOperatorDirectory;
import pe.gob.mtc.walletprovider.institutional.MtcPortalAdministration;
import pe.gob.mtc.walletprovider.institutional.MtcPortalImportService;
import pe.gob.mtc.walletprovider.institutional.MtcWorkRequestService;
import pe.gob.mtc.walletprovider.service.EnrollmentService;

import javax.sql.DataSource;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * E2E de persistencia del servicio REAL: PostgreSQL 16 efimero + proxies Spring @Transactional.
 * No usa H2, mocks de JdbcTemplate ni credenciales institucionales.
 * Habilitado exclusivamente por el script de laboratorio y LabPostgresGuard.
 */
@EnabledIfEnvironmentVariable(named = "WALLET_PG_IT", matches = "true")
@SpringJUnitConfig(MtcPortalServicePostgresIntegrationTest.LocalConfig.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MtcPortalServicePostgresIntegrationTest {
    private static final String ISSUER = "https://mtc-it.invalid";

    @Configuration(proxyBeanMethods = false)
    @EnableTransactionManagement
    static class LocalConfig {
        @Bean
        DataSource dataSource() {
            // Validacion obligatoria ANTES de la primera conexion con permisos de escritura.
            LabPostgresGuard.Target t = LabPostgresGuard.verify();
            return new DriverManagerDataSource(t.url(), t.user(), t.password());
        }
        @Bean
        JdbcTemplate jdbc(DataSource dataSource) { return new JdbcTemplate(dataSource); }
        @Bean
        PlatformTransactionManager transactionManager(DataSource dataSource) {
            return new DataSourceTransactionManager(dataSource);
        }
        @Bean
        HolderIdentityCrypto identityCrypto() {
            byte[] hmac = new byte[32];
            byte[] aes = new byte[32];
            SecureRandom r = new SecureRandom();
            r.nextBytes(hmac);
            r.nextBytes(aes);
            return new HolderIdentityCrypto(Base64.getEncoder().encodeToString(hmac),
                Base64.getEncoder().encodeToString(aes), 1);
        }
        @Bean
        ObjectMapper objectMapper() { return new ObjectMapper().findAndRegisterModules(); }
        @Bean
        EnrollmentService enrollmentService() { return mock(EnrollmentService.class); }
        @Bean
        MtcPortalAdministration portalAdministration(JdbcTemplate jdbc, HolderIdentityCrypto crypto,
                                                     EnrollmentService enrollmentService) {
            return new MtcPortalAdministration(jdbc, crypto, enrollmentService);
        }
        @Bean
        MtcWorkRequestService workRequests(JdbcTemplate jdbc, HolderIdentityCrypto crypto,
                                            MtcPortalAdministration portal, ObjectMapper mapper) {
            return new MtcWorkRequestService(jdbc, crypto, portal, mapper);
        }
        @Bean
        MtcPortalImportService imports(JdbcTemplate jdbc, HolderIdentityCrypto crypto,
                                      MtcPortalAdministration portal) {
            return new MtcPortalImportService(jdbc, crypto, portal);
        }
        @Bean
        MtcOperatorDirectory operators(JdbcTemplate jdbc, MtcPortalAdministration portal) {
            return new MtcOperatorDirectory(jdbc, portal);
        }
        @Bean
        MtcOperatorAccess access(JdbcTemplate jdbc) { return new MtcOperatorAccess(jdbc); }
    }

    @Autowired private DataSource dataSource;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private MtcWorkRequestService requests;
    @Autowired private MtcPortalAdministration admin;
    @Autowired private MtcPortalImportService imports;
    @Autowired private MtcOperatorDirectory operators;
    @Autowired private MtcOperatorAccess access;

    private UUID entity;
    private String code;
    private MtcOperatorAccess.Operator registrador;
    private MtcOperatorAccess.Operator aprobador;
    private MtcOperatorAccess.Operator superAdmin;

    @BeforeAll
    void flywayAgainstGuardedDatabase() {
        assertTrue(AopUtils.isAopProxy(requests), "@Transactional no esta activo en WorkRequestService");
        assertTrue(AopUtils.isAopProxy(admin), "@Transactional no esta activo en PortalAdministration");
        assertTrue(AopUtils.isAopProxy(imports), "@Transactional no esta activo en PortalImportService");
        assertTrue(AopUtils.isAopProxy(operators), "@Transactional no esta activo en OperatorDirectory");
        Flyway flyway = Flyway.configure().dataSource(dataSource)
            .schemas("wallet_provider").defaultSchema("wallet_provider")
            .createSchemas(false).table("flyway_schema_history")
            .locations("classpath:db/migration").load();
        flyway.migrate();
        flyway.validate();
        assertEquals(7, jdbc.queryForObject("SELECT count(*) FROM wallet_provider.flyway_schema_history " +
            "WHERE success AND version ~ '^[1-7]$'", Integer.class));
    }

    @BeforeEach
    void createTestActorsAndEntity() {
        entity = UUID.randomUUID();
        code = "IT" + UUID.randomUUID().toString().replace("-", "").substring(0, 12).toUpperCase();
        jdbc.update("INSERT INTO wallet_provider.wp_entity (id, code, name, status) VALUES (?, ?, 'TEST LOCAL', 'ACTIVE')",
            entity, code);
        registrador = createActor("reg", Set.of(MtcOperatorAccess.REGISTRADOR));
        aprobador = createActor("apr", Set.of(MtcOperatorAccess.APROBADOR));
        superAdmin = createActor("adm", Set.of(MtcOperatorAccess.SUPER_ADMIN));
    }

    private MtcOperatorAccess.Operator createActor(String prefix, Set<String> roles) {
        UUID id = UUID.randomUUID();
        String subject = prefix + "-" + id;
        jdbc.update("INSERT INTO wallet_provider.wp_mtc_operator (id,issuer,subject,role,status) " +
            "VALUES (?,?,?,?, 'ACTIVE')", id, ISSUER, subject,
            roles.contains(MtcOperatorAccess.SUPER_ADMIN) ? "SUPER_ADMIN" : "MESA_DE_PARTES");
        roles.forEach(role -> jdbc.update("INSERT INTO wallet_provider.wp_mtc_operator_role(operator_id,role) VALUES (?,?)", id, role));
        return new MtcOperatorAccess.Operator(id, ISSUER, subject, roles);
    }

    private MtcPortalAdministration.CreateGrant grant() {
        return new MtcPortalAdministration.CreateGrant("00000000", "LAB-01", "Mesa de pruebas",
            LocalDate.now(ZoneOffset.UTC).plusDays(40));
    }
    private String key() { return "it-" + UUID.randomUUID(); }
    private int grants() {
        return jdbc.queryForObject("SELECT count(*) FROM wallet_provider.wp_verifier_grant WHERE entity_id = ?",
            Integer.class, entity);
    }
    private String state(UUID id) {
        return jdbc.queryForObject("SELECT status FROM wallet_provider.wp_mtc_work_request WHERE id = ?",
            String.class, id);
    }

    @Test
    void stagingApprovalAndPersistenceAreDistinctTransactionalSteps() {
        UUID request = requests.registerGrant(code, grant(), key(), registrador);
        assertEquals("PENDING", state(request));
        assertEquals(0, grants(), "Registrar NO puede activar un verificador");
        requests.approve(request, aprobador);
        assertEquals("APPROVED", state(request));
        assertEquals(1, grants());
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM wallet_provider.wp_verifier_grant " +
            "WHERE entity_id = ? AND status = 'ACTIVE'", Integer.class, entity));
        assertEquals(aprobador.id(), jdbc.queryForObject("SELECT decided_by FROM wallet_provider.wp_mtc_work_request " +
            "WHERE id = ?", UUID.class, request));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM wallet_provider.wp_admin_audit " +
            "WHERE resource_id = ? AND action = 'REQUEST_APPROVE'", Integer.class, request.toString()));
        assertThrows(ResponseStatusException.class, () -> requests.approve(request, aprobador));
        assertEquals(1, grants());
    }

    @Test
    void rejectionAndIdempotencyDoNotCreateEffectiveGrant() {
        String idempotency = key();
        UUID request = requests.registerGrant(code, grant(), idempotency, registrador);
        assertThrows(ResponseStatusException.class,
            () -> requests.registerGrant(code, grant(), idempotency, registrador));
        requests.reject(request, new MtcWorkRequestService.Decision("No validado"), aprobador);
        assertEquals("REJECTED", state(request));
        assertEquals(0, grants());
        assertThrows(ResponseStatusException.class, () -> requests.approve(request, aprobador));
    }

    @Test
    void approverAndRegistrarCanAccumulateRolesWithoutAutomaticPrivilegeEscalation() {
        // Solo SUPER_ADMIN asigna roles. La cuenta inicialmente registradora se vuelve dual.
        assertFalse(registrador.canApprove());
        assertFalse(aprobador.canRegister());
        operators.updateRoles(registrador.id(),
            new MtcOperatorDirectory.UpdateRoles(Set.of(MtcOperatorAccess.REGISTRADOR,
                MtcOperatorAccess.APROBADOR)), superAdmin);
        Integer roles = jdbc.queryForObject("SELECT count(*) FROM wallet_provider.wp_mtc_operator_role " +
            "WHERE operator_id = ?", Integer.class, registrador.id());
        assertEquals(2, roles);
        // MtcOperatorAccess toma autorizaciones de la BD, no del token o del navegador.
        // Este test invoca directamente el servicio, sin pasar por el filtro OAuth2/JWT.
        // El fixture NO prueba la firma del JWT: solo prueba la autorizacion de roles
        // de un principal que el filtro habria autenticado previamente.
        var jwt = org.springframework.security.oauth2.jwt.Jwt.withTokenValue("fake-IT-only")
            .header("alg", "RS256").issuer(ISSUER).subject(registrador.subject())
            .issuedAt(java.time.Instant.now()).expiresAt(java.time.Instant.now().plusSeconds(600)).build();
        var token = new org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken(jwt);
        assertFalse(token.isAuthenticated(), "El JWT sintetico no esta autenticado por defecto");
        ResponseStatusException denied = assertThrows(ResponseStatusException.class,
            () -> access.requireRegister(token));
        assertEquals(403, denied.getStatusCode().value(), "Un JWT sin autenticar debe seguir rechazado");
        token.setAuthenticated(true); // Simula EXCLUSIVAMENTE el resultado del filtro en este test.
        assertTrue(access.requireRegister(token).canRegister());
        assertTrue(access.requireApprove(token).canApprove());
        UUID request = requests.registerGrant(code, grant(), key(), access.requireRegister(token));
        requests.approve(request, access.requireApprove(token));
        assertEquals("APPROVED", state(request));
    }

    @Test
    void concurrentApprovalOfSameRequestProducesOnlyOneGrant() throws Exception {
        UUID request = requests.registerGrant(code, grant(), key(), registrador);
        var pool = Executors.newFixedThreadPool(2);
        CountDownLatch begin = new CountDownLatch(1);
        try {
            java.util.concurrent.Callable<Boolean> task = () -> {
                assertTrue(begin.await(12, TimeUnit.SECONDS));
                try { requests.approve(request, aprobador); return true; }
                catch (ResponseStatusException ex) {
                    assertEquals(409, ex.getStatusCode().value());
                    return false;
                }
            };
            Future<Boolean> one = pool.submit(task);
            Future<Boolean> two = pool.submit(task);
            begin.countDown();
            assertEquals(1, (one.get(20, TimeUnit.SECONDS) ? 1 : 0)
                + (two.get(20, TimeUnit.SECONDS) ? 1 : 0));
            assertEquals(1, grants());
            assertEquals("APPROVED", state(request));
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void failureDuringApprovalAuditRollsBackGrantAndRequestDecision() {
        UUID request = requests.registerGrant(code, grant(), key(), registrador);
        jdbc.execute("""
            CREATE OR REPLACE FUNCTION wallet_provider.mtc_it_force_audit_failure()
            RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
              IF NEW.action = 'REQUEST_APPROVE' THEN
                RAISE EXCEPTION 'intentional-local-it-audit-failure';
              END IF;
              RETURN NEW;
            END $$
            """);
        jdbc.execute("""
            CREATE TRIGGER mtc_it_force_audit_failure
            BEFORE INSERT ON wallet_provider.wp_admin_audit
            FOR EACH ROW EXECUTE FUNCTION wallet_provider.mtc_it_force_audit_failure()
            """);
        try {
            assertThrows(DataAccessException.class, () -> requests.approve(request, aprobador));
        } finally {
            jdbc.execute("DROP TRIGGER IF EXISTS mtc_it_force_audit_failure " +
                "ON wallet_provider.wp_admin_audit");
            jdbc.execute("DROP FUNCTION IF EXISTS wallet_provider.mtc_it_force_audit_failure()");
        }
        assertEquals("PENDING", state(request), "La decisión debe retroceder");
        assertEquals(0, grants(), "El enrolamiento efectivo también debe retroceder");
    }

    @Test
    void standardizedXlsxIsStagedThenAppliedAndAudited() throws Exception {
        var file = spreadsheet("00000000");
        var staged = imports.validateAndStage(code, file, key(), registrador);
        assertEquals("VALIDATED", staged.status());
        assertEquals(0, grants());
        var applied = imports.apply(code, staged.id(), aprobador);
        assertEquals("APPLIED", applied.status());
        assertEquals(1, applied.created());
        assertEquals(1, grants());
        assertEquals(aprobador.id(), jdbc.queryForObject(
            "SELECT decided_by FROM wallet_provider.wp_import_batch WHERE id = ?",
            UUID.class, staged.id()));
        assertThrows(ResponseStatusException.class, () -> imports.apply(code, staged.id(), aprobador));
    }

    @Test
    void rejectedXlsxNeverChangesEffectivePadrón() throws Exception {
        var staged = imports.validateAndStage(code, spreadsheet("00000000"), key(), registrador);
        imports.reject(code, staged.id(), "Expediente no conforme", aprobador);
        assertEquals("REJECTED", jdbc.queryForObject(
            "SELECT status FROM wallet_provider.wp_import_batch WHERE id = ?",
            String.class, staged.id()));
        assertEquals(0, grants());
        assertThrows(ResponseStatusException.class, () -> imports.apply(code, staged.id(), aprobador));
    }

    private static MockMultipartFile spreadsheet(String dni) throws Exception {
        try (var workbook = new XSSFWorkbook(); var out = new ByteArrayOutputStream()) {
            var sheet = workbook.createSheet("Padron");
            var header = sheet.createRow(0);
            String[] columns = {"DNI", "CODIGO_INSTITUCIONAL", "UNIDAD", "VIGENCIA_HASTA"};
            for (int i = 0; i < columns.length; i++) header.createCell(i).setCellValue(columns[i]);
            var row = sheet.createRow(1);
            row.createCell(0).setCellValue(dni);
            row.createCell(1).setCellValue("LAB-01");
            row.createCell(2).setCellValue("Unidad Prueba");
            row.createCell(3).setCellValue(LocalDate.now(ZoneOffset.UTC).plusDays(45).toString());
            workbook.write(out);
            return new MockMultipartFile("file", "padron-ficticio.xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", out.toByteArray());
        }
    }
}
