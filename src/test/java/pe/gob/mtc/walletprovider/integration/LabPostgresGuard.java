package pe.gob.mtc.walletprovider.integration;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;

/**
 * Control EXCLUSIVO de src/test/java: falla antes de ejecutar Flyway o cualquier escritura.
 * El marcador de laboratorio debe existir previamente en una BD desechable.
 */
final class LabPostgresGuard {
    private static final String EXPECTED_DB = "wallet_provider_it";
    private static final String EXPECTED_USER = "wallet_provider_it";
    private static final String SERVICE = "wallet-provider";
    private static final String ACK = "I_CONFIRM_DISPOSABLE_DB_ONLY";

    private LabPostgresGuard() { }

    record Target(String url, String user, String password) { }

    static Target verify() {
        String url = env("WALLET_PG_JDBC_URL");
        String user = env("WALLET_PG_USER");
        String password = env("WALLET_PG_PASSWORD");
        String marker = env("WALLET_PG_LAB_TOKEN");

        validateTarget(System.getenv("WALLET_PG_LAB_ACK"), url, user, marker,
                System.getenv("KUBERNETES_SERVICE_HOST"),
                System.getenv("SPRING_PROFILES_ACTIVE"), System.getenv("DEPLOY_ENV"));

        // Conexión únicamente de lectura: nunca se invoca Flyway antes de pasar este control.
        try (Connection connection = DriverManager.getConnection(url, user, password)) {
            connection.setReadOnly(true);
            try (PreparedStatement identity = connection.prepareStatement(
                    "SELECT current_database(), current_user");
                 ResultSet result = identity.executeQuery()) {
                if (!result.next() || !EXPECTED_DB.equals(result.getString(1))
                        || !EXPECTED_USER.equals(result.getString(2))) {
                    throw denied("identidad real de la base o usuario no autorizados");
                }
            }
            try (PreparedStatement check = connection.prepareStatement(
                    "SELECT guard_token FROM public.mtc_integration_test_guard "
                    + "WHERE service_name = ? AND environment = 'LOCAL_INTEGRATION'")) {
                check.setString(1, SERVICE);
                try (ResultSet result = check.executeQuery()) {
                    if (!result.next()) {
                        throw denied("no existe la marca de laboratorio para este servicio");
                    }
                    byte[] expected = marker.getBytes(StandardCharsets.UTF_8);
                    byte[] actual = result.getString(1).getBytes(StandardCharsets.UTF_8);
                    if (!MessageDigest.isEqual(expected, actual) || result.next()) {
                        throw denied("marca de laboratorio incorrecta o ambigua");
                    }
                }
            }
        } catch (SQLException ex) {
            // Evitar volcar URL, usuario o credenciales de bases institucionales en logs.
            throw denied("no fue posible verificar la base desechable (conexión/lectura)");
        }
        return new Target(url, user, password);
    }

    static void validateTarget(String acknowledgement, String url, String user, String marker,
                               String kubernetesHost, String profiles, String deploymentEnvironment) {
        if (!ACK.equals(acknowledgement)) {
            throw denied("falta confirmación explícita de laboratorio");
        }
        if (kubernetesHost != null && !kubernetesHost.isBlank()) {
            throw denied("no se permite ejecutar estas pruebas dentro de Kubernetes");
        }
        if (nonLabProfile(profiles) || nonLabProfile(deploymentEnvironment)) {
            throw denied("perfil de despliegue no permitido");
        }
        String url127 = "jdbc:postgresql://127.0.0.1:55432/" + EXPECTED_DB;
        String urlLocal = "jdbc:postgresql://localhost:55432/" + EXPECTED_DB;
        if (!url127.equals(url) && !urlLocal.equals(url)) {
            throw denied("el destino no es la base local exclusiva de integración");
        }
        if (!EXPECTED_USER.equals(user)) {
            throw denied("se requiere la identidad exclusiva de integración");
        }
        if (marker == null || !marker.matches("[a-fA-F0-9-]{36}")) {
            throw denied("falta marca aleatoria de laboratorio con formato UUID");
        }
    }

    private static boolean nonLabProfile(String value) {
        if (value == null || value.isBlank()) return false;
        String normalized = value.toLowerCase(Locale.ROOT);
        // Impedir QA institucional compartido, staging y producción.
        for (String profile : normalized.split("[,;\\s_-]+")) {
            if (profile.equals("prod") || profile.equals("production") || profile.equals("prd")
                    || profile.equals("qa") || profile.equals("staging")
                    || profile.equals("stage") || profile.equals("preprod")) return true;
        }
        return false;
    }

    private static String env(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw denied("falta variable obligatoria de laboratorio: " + name);
        }
        return value;
    }

    private static IllegalStateException denied(String reason) {
        return new IllegalStateException("BLOQUEO DE PRUEBA POSTGRESQL: " + reason);
    }
}
