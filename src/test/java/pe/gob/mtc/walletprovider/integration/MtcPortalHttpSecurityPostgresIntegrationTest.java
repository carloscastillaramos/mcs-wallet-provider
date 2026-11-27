package pe.gob.mtc.walletprovider.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.flywaydb.core.Flyway;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.mock.web.MockMultipartFile;
import java.io.ByteArrayOutputStream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import pe.gob.mtc.walletprovider.config.SecurityConfig;
import pe.gob.mtc.walletprovider.identity.HolderIdentityCrypto;
import pe.gob.mtc.walletprovider.institutional.MtcOperatorAccess;
import pe.gob.mtc.walletprovider.institutional.MtcOperatorDirectory;
import pe.gob.mtc.walletprovider.institutional.MtcPortalAdminController;
import pe.gob.mtc.walletprovider.institutional.MtcPortalAdministration;
import pe.gob.mtc.walletprovider.institutional.MtcPortalImportService;
import pe.gob.mtc.walletprovider.institutional.MtcWorkRequestService;
import pe.gob.mtc.walletprovider.service.EnrollmentService;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration of real HTTP security filters, signed bearer JWTs, controller RBAC and PostgreSQL.
 * Runs ONLY against the disposable/guarded Docker DB, never against AWS/Cognito or shared DBs.
 * The lab public key simulates a trusted issuer; production still uses Cognito JWKS.
 */
@EnabledIfEnvironmentVariable(named = "WALLET_PG_IT", matches = "true")
@WebAppConfiguration
@SpringJUnitConfig(classes = {MtcPortalHttpSecurityPostgresIntegrationTest.HttpLabConfig.class, SecurityConfig.class})
@TestPropertySource(properties = {
    "wallet.cognito.enabled=true",
    "wallet-provider.portal.enabled=true",
    "wallet-provider.portal.client-ids=mtc-portal-qa-client",
    "wallet-provider.portal.origins=https://portal.mtc.example"
})
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MtcPortalHttpSecurityPostgresIntegrationTest {
    private static final String ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_MtcLab";
    private static final String CLIENT = "mtc-portal-qa-client";
    private static final String API = "/api/v1/mtc/portal";
    private static final KeyPair KEY_PAIR = keyPair();

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @EnableWebSecurity
    @EnableTransactionManagement
    static class HttpLabConfig {
        @Bean DataSource dataSource() {
            LabPostgresGuard.Target lab = LabPostgresGuard.verify();
            return new DriverManagerDataSource(lab.url(), lab.user(), lab.password());
        }
        @Bean JdbcTemplate jdbc(DataSource dataSource) { return new JdbcTemplate(dataSource); }
        @Bean PlatformTransactionManager transactionManager(DataSource ds) {
            return new DataSourceTransactionManager(ds);
        }
        @Bean HolderIdentityCrypto identityCrypto() {
            byte[] hmac = new byte[32], aes = new byte[32];
            SecureRandom random = new SecureRandom();
            random.nextBytes(hmac); random.nextBytes(aes);
            return new HolderIdentityCrypto(Base64.getEncoder().encodeToString(hmac),
                Base64.getEncoder().encodeToString(aes), 1);
        }
        @Bean ObjectMapper objectMapper() { return new ObjectMapper().findAndRegisterModules(); }
        @Bean EnrollmentService enrollmentService() { return mock(EnrollmentService.class); }
        @Bean MtcPortalAdministration administration(JdbcTemplate jdbc, HolderIdentityCrypto crypto,
                                                       EnrollmentService enrollment) {
            return new MtcPortalAdministration(jdbc, crypto, enrollment);
        }
        @Bean MtcWorkRequestService requests(JdbcTemplate jdbc, HolderIdentityCrypto crypto,
                                              MtcPortalAdministration admin, ObjectMapper mapper) {
            return new MtcWorkRequestService(jdbc, crypto, admin, mapper);
        }
        @Bean MtcPortalImportService imports(JdbcTemplate jdbc, HolderIdentityCrypto crypto,
                                              MtcPortalAdministration admin) {
            return new MtcPortalImportService(jdbc, crypto, admin);
        }
        @Bean MtcOperatorDirectory operators(JdbcTemplate jdbc, MtcPortalAdministration admin) {
            return new MtcOperatorDirectory(jdbc, admin);
        }
        @Bean MtcOperatorAccess access(JdbcTemplate jdbc) { return new MtcOperatorAccess(jdbc); }
        @Bean MtcPortalAdminController portal(MtcOperatorAccess access, MtcPortalAdministration admin,
                                               MtcPortalImportService imports, MtcWorkRequestService requests,
                                               MtcOperatorDirectory operators) {
            return new MtcPortalAdminController(access, admin, imports, requests, operators);
        }
        @Bean JwtDecoder jwtDecoder() {
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey((RSAPublicKey) KEY_PAIR.getPublic()).build();
            OAuth2TokenValidator<Jwt> accessOnly = jwt ->
                "access".equals(jwt.getClaimAsString("token_use"))
                    && jwt.getClaimAsString("client_id") != null
                    ? OAuth2TokenValidatorResult.success()
                    : OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Access token required", null));
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(ISSUER), accessOnly));
            return decoder;
        }
    }

    @Autowired private DataSource dataSource;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private WebApplicationContext webContext;
    private MockMvc mvc;
    private String entity;
    private UUID entityId;
    private String registrar;
    private String approver;
    private String combined;
    private String superAdmin;

    @BeforeAll void prepare() {
        Flyway flyway = Flyway.configure().dataSource(dataSource)
            .schemas("wallet_provider").defaultSchema("wallet_provider")
            .createSchemas(false).table("flyway_schema_history")
            .locations("classpath:db/migration").load();
        flyway.migrate();
        flyway.validate();
        mvc = MockMvcBuilders.webAppContextSetup(webContext).apply(springSecurity()).build();
    }
    @BeforeEach void seed() {
        entityId = UUID.randomUUID();
        entity = "HTTP" + UUID.randomUUID().toString().replace("-", "").substring(0, 10).toUpperCase();
        jdbc.update("INSERT INTO wallet_provider.wp_entity (id,code,name,status) VALUES (?,?,'HTTP LAB','ACTIVE')",
            entityId, entity);
        registrar = operator(Set.of(MtcOperatorAccess.REGISTRADOR));
        approver = operator(Set.of(MtcOperatorAccess.APROBADOR));
        combined = operator(Set.of(MtcOperatorAccess.REGISTRADOR, MtcOperatorAccess.APROBADOR));
        superAdmin = operator(Set.of(MtcOperatorAccess.SUPER_ADMIN));
    }
    private String operator(Set<String> roles) {
        String subject = UUID.randomUUID().toString();
        UUID id = UUID.randomUUID();
        jdbc.update("INSERT INTO wallet_provider.wp_mtc_operator (id,issuer,subject,role,status) " +
            "VALUES (?,?,?,?, 'ACTIVE')", id, ISSUER, subject,
            roles.contains(MtcOperatorAccess.SUPER_ADMIN) ? "SUPER_ADMIN" : "MESA_DE_PARTES");
        roles.forEach(role -> jdbc.update("INSERT INTO wallet_provider.wp_mtc_operator_role (operator_id,role) VALUES (?,?)",
            id, role));
        return subject;
    }

    @Test void anonymousInvalidSignatureExpiredOrWrongIssuerReturn401() throws Exception {
        mvc.perform(get(API + "/me")).andExpect(status().isUnauthorized());
        mvc.perform(get(API + "/me").header("Authorization", alteredSignature(bearer(registrar))))
            .andExpect(status().isUnauthorized());
        // Spring's default JwtTimestampValidator accepts short clock skew (60 seconds).
        // This token expired well beyond that tolerance and MUST be rejected.
        mvc.perform(get(API + "/me").header("Authorization", bearer(registrar, CLIENT, ISSUER, true, -300)))
            .andExpect(status().isUnauthorized());
        mvc.perform(get(API + "/me").header("Authorization", bearer(registrar, CLIENT,
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Wrong", true, 600)))
            .andExpect(status().isUnauthorized());
    }

    @Test void portalRequiresAuthorizedClientScopeAndLocalOperator() throws Exception {
        mvc.perform(get(API + "/me").header("Authorization", bearer(registrar, "other-client", ISSUER, true, 600)))
            .andExpect(status().isForbidden());
        mvc.perform(get(API + "/me").header("Authorization", bearer(registrar, CLIENT, ISSUER, false, 600)))
            .andExpect(status().isForbidden());
        mvc.perform(get(API + "/me").header("Authorization", bearer(UUID.randomUUID().toString(), CLIENT, ISSUER, true, 600)))
            .andExpect(status().isForbidden());
        mvc.perform(get(API + "/me").header("Authorization", bearer(registrar, CLIENT, ISSUER, true, 600)))
            .andExpect(status().isOk()).andExpect(jsonPath("$.roles[0]").value(MtcOperatorAccess.REGISTRADOR));
    }

    @Test void registrarCanStageButCannotApproveWhileApproverCannotStage() throws Exception {
        String path = API + "/entities/" + entity + "/requests/grants";
        String payload = grantPayload();
        mvc.perform(post(path).header("Authorization", bearer(approver)).header("Idempotency-Key", key())
            .contentType(MediaType.APPLICATION_JSON).content(payload))
            .andExpect(status().isForbidden());
        String id = mvc.perform(post(path).header("Authorization", bearer(registrar)).header("Idempotency-Key", key())
            .contentType(MediaType.APPLICATION_JSON).content(payload))
            .andExpect(status().isCreated()).andExpect(jsonPath("$.id").exists())
            .andReturn().getResponse().getContentAsString();
        String requestId = new ObjectMapper().readTree(id).get("id").asText();
        assertEquals(0, countGrants());
        mvc.perform(post(API + "/requests/" + requestId + "/approve")
            .header("Authorization", bearer(registrar)))
            .andExpect(status().isForbidden());
        assertEquals(0, countGrants());
        mvc.perform(post(API + "/requests/" + requestId + "/approve")
            .header("Authorization", bearer(approver)))
            .andExpect(status().isNoContent());
        assertEquals(1, countGrants());
    }

    @Test void combinedRolesMayRegisterAndApproveSameRequestAndOldDirectMutationRouteIsBlocked() throws Exception {
        mvc.perform(post(API + "/entities/" + entity + "/grants")
            .header("Authorization", bearer(superAdmin)).contentType(MediaType.APPLICATION_JSON)
            .content(grantPayload())).andExpect(status().isMethodNotAllowed());
        String body = mvc.perform(post(API + "/entities/" + entity + "/requests/grants")
            .header("Authorization", bearer(combined)).header("Idempotency-Key", key())
            .contentType(MediaType.APPLICATION_JSON).content(grantPayload()))
            .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        String id = new ObjectMapper().readTree(body).get("id").asText();
        mvc.perform(post(API + "/requests/" + id + "/approve")
            .header("Authorization", bearer(combined))).andExpect(status().isNoContent());
        assertEquals(1, countGrants());
    }

    @Test void duplicateRequestReturnsConflictAndDoesNotCreateSecondRow() throws Exception {
        String path = API + "/entities/" + entity + "/requests/grants";
        String idempotency = key();
        mvc.perform(post(path).header("Authorization", bearer(registrar))
            .header("Idempotency-Key", idempotency).contentType(MediaType.APPLICATION_JSON)
            .content(grantPayload())).andExpect(status().isCreated());
        mvc.perform(post(path).header("Authorization", bearer(registrar))
            .header("Idempotency-Key", idempotency).contentType(MediaType.APPLICATION_JSON)
            .content(grantPayload())).andExpect(status().isConflict())
            .andExpect(jsonPath("$.code").value("PORTAL_REQUEST_REJECTED"));
        assertEquals(1, jdbc.queryForObject("SELECT count(*) FROM wallet_provider.wp_mtc_work_request WHERE entity_id = ? AND request_key = ?", Integer.class, entityId, idempotency));
        assertEquals(0, countGrants());
    }

    @Test void superAdminCanReadOperatorsButMesaDePartesCannot() throws Exception {
        mvc.perform(get(API + "/operators").header("Authorization", bearer(registrar)))
            .andExpect(status().isForbidden());
        mvc.perform(get(API + "/operators").header("Authorization", bearer(approver)))
            .andExpect(status().isForbidden());
        mvc.perform(get(API + "/operators").header("Authorization", bearer(superAdmin)))
            .andExpect(status().isOk());
    }

    @Test void preflightIsRestrictedToConfiguredOrigin() throws Exception {
        mvc.perform(options(API + "/requests").header("Origin", "https://portal.mtc.example")
            .header("Access-Control-Request-Method", "GET"))
            .andExpect(status().isOk())
            .andExpect(header().string("Access-Control-Allow-Origin", "https://portal.mtc.example"));
        mvc.perform(options(API + "/requests").header("Origin", "https://external.example")
            .header("Access-Control-Request-Method", "GET"))
            .andExpect(status().isForbidden());
    }

    @Test void multipartExcelCannotBypassIndependentApproval() throws Exception {
        byte[] workbook;
        try (XSSFWorkbook wb = new XSSFWorkbook(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            var sheet = wb.createSheet("PADRON");
            var header = sheet.createRow(0);
            String[] names = {"DNI", "CODIGO_INSTITUCIONAL", "UNIDAD", "VIGENCIA_HASTA"};
            for (int i = 0; i < names.length; i++) header.createCell(i).setCellValue(names[i]);
            var row = sheet.createRow(1);
            row.createCell(0).setCellValue("00000000");
            row.createCell(1).setCellValue("LAB-HTTP");
            row.createCell(2).setCellValue("Pruebas");
            row.createCell(3).setCellValue(LocalDate.now().plusDays(45).toString());
            wb.write(out); workbook = out.toByteArray();
        }
        String path = API + "/entities/" + entity + "/imports";
        MockMultipartFile file = new MockMultipartFile("file", "padron.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", workbook);
        mvc.perform(multipart(path).file(file).header("Authorization", bearer(approver))
            .header("Idempotency-Key", key())).andExpect(status().isForbidden());
        String json = mvc.perform(multipart(path).file(file).header("Authorization", bearer(registrar))
            .header("Idempotency-Key", key())).andExpect(status().isCreated())
            .andExpect(jsonPath("$.status").value("VALIDATED"))
            .andReturn().getResponse().getContentAsString();
        String batchId = new ObjectMapper().readTree(json).get("id").asText();
        assertEquals(0, countGrants());
        mvc.perform(post(path + "/" + batchId + "/apply")
            .header("Authorization", bearer(registrar))).andExpect(status().isForbidden());
        mvc.perform(post(path + "/" + batchId + "/apply")
            .header("Authorization", bearer(approver))).andExpect(status().isOk())
            .andExpect(jsonPath("$.status").value("APPLIED"))
            .andExpect(jsonPath("$.created").value(1));
        assertEquals(1, countGrants());
    }

    @Test void bearerIdTokenCannotAuthorizeAdministrativeOperation() throws Exception {
        mvc.perform(get(API + "/me").header("Authorization", bearer(registrar, CLIENT, ISSUER, true, 600, "id")))
            .andExpect(status().isUnauthorized());
    }

    private int countGrants() {
        return jdbc.queryForObject("SELECT count(*) FROM wallet_provider.wp_verifier_grant WHERE entity_id = ?",
            Integer.class, entityId);
    }
    private String grantPayload() {
        return "{\"dni\":\"00000000\",\"institutionalCode\":\"HTTP-1\",\"unit\":\"Pruebas\",\"validUntil\":\""
            + LocalDate.now().plusDays(45) + "\"}";
    }
    private String key() { return "http-" + UUID.randomUUID(); }
    /** Structurally valid JWT with a deliberately corrupted signature, not a malformed bearer. */
    private String alteredSignature(String bearer) {
        int offset = bearer.lastIndexOf('.') + 1;
        char first = bearer.charAt(offset);
        return bearer.substring(0, offset) + (first == 'A' ? 'B' : 'A') + bearer.substring(offset + 1);
    }
    private String bearer(String subject) throws Exception { return bearer(subject, CLIENT, ISSUER, true, 600); }
    private String bearer(String subject, String client, String issuer, boolean hasScope, long ttl) throws Exception {
        return bearer(subject, client, issuer, hasScope, ttl, "access");
    }
    private String bearer(String subject, String client, String issuer, boolean hasScope, long ttl,
                          String tokenUse) throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .issuer(issuer).subject(subject).issueTime(Date.from(now.minusSeconds(120)))
            .expirationTime(Date.from(now.plusSeconds(ttl))).claim("token_use", tokenUse)
            .claim("client_id", client)
            .claim("scope", hasScope ? "mtc-wallet-provider/wallet.portal" : "openid")
            .build();
        SignedJWT signed = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
        signed.sign(new RSASSASigner((RSAPrivateKey) KEY_PAIR.getPrivate()));
        return "Bearer " + signed.serialize();
    }
    private static KeyPair keyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) { throw new IllegalStateException("Test signing key unavailable", e); }
    }
}
