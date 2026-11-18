# mcs-wallet-provider 0.3.0 — Java 21 · PostgreSQL · AWS EKS

**Estado:** adaptación de fuentes terminada; **NO hay evidencia de compilación Maven, pruebas reales PostgreSQL, integración móvil ni despliegue AWS**. Los contratos criptográficos de 0.2.8 no se alteraron en esta revisión. No declarar homologación ISO/OpenID4VC/HAIP.

## Arquitectura y alcance

- Microservicio Java 21 / Spring Boot 3.4.5 / JPA / Flyway / PostgreSQL 16+.
- `wp_challenge`: desafío y consumo con bloqueo pesimista; tabla convencional con índice para purga.
- `wp_installation`: identidad y estado de instalación; `public_key TEXT` en PostgreSQL, nunca clave privada de Wallet.
- `wp_audit`: eventos de enrolamiento, revocación y atestaciones; particiones RANGE mensuales sobre `created_at` UTC, PK `(id,created_at)`, entidad JPA `@IdClass(AuditId)`.
- Flyway `wallet_provider.flyway_schema_history`; crear esquema PostgreSQL **antes** de Flyway (rol DBA).
- Métodos y rutas HTTP existentes de enrolamiento Android/Apple, atestación de wallet y clave de credencial Android, trust, revocación y JWKS conservados.
- APIs de consulta de confianza y revocación continúan protegidas mediante JWT OAuth2 `wallet.trust.read` / `wallet.admin`; a nivel de red restringir admin mediante gateway/service mesh. Istio por sí solo **no sustituye** el JWT que Spring requiere.
- La firma de atestaciones sigue leyendo PKCS#12; no se reemplazó por SoftHSM/AGA/CloudHSM. Google Play Integrity sigue utilizando Google ADC; raíces de Android/Apple deben ser auténticas y verificadas.

## Construcción

```bash
java -version             # Debe ser JDK 21
mvn -B -ntp clean verify   # Ejecutar en estación/CI con Maven y dependencias disponibles
mvn -B -ntp -DskipTests package
docker build -t mcs-wallet-provider:0.3.0 .
```

Imagen de ejecución con UID/GID 10001, JRE 21, disco raíz de solo lectura y `/tmp` efímero. Dockerfile copia el JAR estable `target/mcs-wallet-provider.jar`.

## Configuración genérica por ambiente

`src/main/resources/application.yml` lee valores de entorno; no contiene hosts institucionales, certificados ni secretos. La URL JDBC PostgreSQL `DB_URL` debe contener `sslmode=verify-full` y ruta a CA RDS, por ejemplo con valores **simbólicos**:

```text
jdbc:postgresql://<RDS_PRIVADO>:5432/<BD>?sslmode=verify-full&sslrootcert=/run/trust/rds/rds-global-bundle.pem
```

- Credenciales PostgreSQL: `DB_URL`, `DB_USER`, `DB_PASSWORD`.
- Administración: `OIDC_ISSUER_URI` (emisor institucional de tokens técnicos).
- Firma: `SIGNING_KEYSTORE_PATH`, `SIGNING_KEYSTORE_PASSWORD`, `SIGNING_KEY_ALIAS`, `SIGNING_KEY_ID`, `ATTESTATION_ISSUER`, `WALLET_CLIENT_ID`.
- Android: `ANDROID_PACKAGE`, `ANDROID_CERT_SHA256`, `PLAY_CLOUD_PROJECT_NUMBER`, `ANDROID_ATTESTATION_ROOTS_PATH`, Google ADC mediante `GOOGLE_APPLICATION_CREDENTIALS`.
- iOS: `IOS_APP_ID`, `IOS_APP_ATTEST_PRODUCTION`, `APPLE_APP_ATTEST_ROOT_PATH`.
- Opcionales: `PORT` (8080), `DB_POOL_MAX_SIZE` (8), `SPRING_FLYWAY_ENABLED` (true), `LOG_FILE` (stdout por defecto).

El despliegue EKS usa Secrets y ConfigMaps externos: `k8s/README_AWS_EKS.md`. No incluye ningún valor productivo ni material privado. Se mantiene JWT administrativo hasta que una arquitectura IAM/mesh validada permita modificarlo explícitamente.

## Datos y escalado

- `wp_installation` se mantiene sin particionar por consultas puntuales y restricciones únicas `(platform,key_id)`.
- `wp_challenge` se mantiene sin particionar por accesos puntuales; implementar job de purga por lotes y medir crecimiento.
- `wp_audit` se particiona mensualmente por UTC, con particiones creadas desde el mes anterior hasta 18 meses futuros al instalar.
- **Obligatorio:** ejecutar `sql/maintenance/ensure_partitions.sql` cada mes con rol DDL. Monitorizar anticipación; si no existe partición al insertar, se rechaza la transacción y el enrolamiento/atestación podría verse afectado.
- El retiro de particiones históricas solo se hará tras aprobar política de retención/archivado; no automatizamos destrucción de auditoría.
- Dimensionar RDS, Hikari, índices, autovacuum y carga E2E antes de incrementar réplicas. Separar roles de migración DDL y ejecución DML en producción.

## Protocolo móvil

1. Wallet solicita `POST /api/v1/enrollments/challenge`.
2. Android genera clave P-256 en Android Keystore, obtiene Key Attestation, firma desafío y obtiene Play Integrity; iOS usa Apple App Attest.
3. Wallet envía a `/api/v1/enrollments/android` o `/ios`; el servidor valida, registra instalación y auditoría.
4. Wallet solicita nuevo desafío y atestaciones firmadas; Android dispone de `/api/v1/attestations/credential-keys/android` para atestación separada de clave de credencial. **No está integrado con Wallet ni exigido todavía por Certify**.
5. Servicios autorizados pueden consultar `/api/v1/installations/{id}/trust`, revocar y validar claves de firma públicas mediante `/api/v1/.well-known/jwks.json`.

El detalle exacto de los mensajes, firmas y restricciones ISO/OpenID4VC del código 0.2.8 se conserva como **documento histórico** en `docs/REFERENCIA_FUNCIONAL_0.2.8.md`; su sección de despliegue Oracle NO se debe utilizar.

## Validación pendiente

- Compilar y ejecutar tests con Maven 3.9 y Java 21.
- PostgreSQL 16+ real: Flyway V1, `ddl-auto=validate`, bloqueos, transacciones, índices, particionamiento mensual y observabilidad.
- EKS: JWT administrativo real, IAM, Secrets, Istio sidecar, RDS TLS verify-full y rutas públicas controladas.
- Pruebas Android/iOS reales, certificados X.509 institucionales, renovación/revocación y flujo E2E con INJI Wallet/Mimoto/Certify.

## 0.4.0 — Vinculación Provider/Diagnostics

Integración mediante clave P-256 dedicada, OAuth2 client_credentials, outbox PostgreSQL y revocaciones idempotentes. **Desactivada por defecto** hasta la configuración de QA. Ver `docs/INTEGRACION_DIAGNOSTICS_0.4.0.md`.


---

## Configuración para Infraestructura — diferencial MTC (17/11/2026)

**Alcance:** solo indicar acciones de configuración que cambian frente al despliegue anterior. **No pedir a Infraestructura que vuelva a configurar variables ya operativas y sin cambios.** Esta sección es documentación de fuentes del 17/11/2026, no una comparación certificada contra el commit efectivamente desplegado; completar esa comparación usando Git antes de poner la etiqueta definitiva «nueva» o «modificada» en los servicios existentes.

**Clasificación:** `EXISTENTE` = conocida del despliegue previo (sin acción salvo variación real); `NUEVA MTC` = incorporada funcionalmente en la implementación reciente, pendiente de contrastar con el último commit desplegado; `CAMBIO DE USO` = misma variable o configuración pero distinta forma de suministrarla; `NUEVA INSTALACIÓN` = toda variable del microservicio nuevo. No confundir parámetros de construcción Docker con variables de ejecución.

**Estado:** servicio nuevo; todas las variables siguientes son `NUEVA INSTALACIÓN` para Infraestructura. Requiere configuración inicial completa; no reutilizar secretos de otros servicios sin aprobación.

| Variable | Valor predeterminado en fuentes | Acción inicial / alcance |
|---|---|---|
| `ANDROID_ATTESTATION_ROOTS_PATH` | `sin valor predeterminado` | Certificados públicos Android confiables montados |
| `ANDROID_CERT_SHA256` | `sin valor predeterminado` | Huella certificado de firma real del APK |
| `ANDROID_PACKAGE` | `sin valor predeterminado` | Package del APK efectivo (DEV/PRD según ambiente) |
| `APPLE_APP_ATTEST_ROOT_PATH` | `sin valor predeterminado` | Certificados públicos Apple confiables montados |
| `ATTESTATION_ISSUER` | `sin valor predeterminado` | Issuer oficial de las atestaciones |
| `ATTESTATION_SECONDS` | `300` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `CHALLENGE_SECONDS` | `180` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `DB_PASSWORD` | `sin valor predeterminado` | Secret; nunca Git |
| `DB_POOL_MAX_SIZE` | `8` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `DB_POOL_MIN_IDLE` | `1` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `DB_URL` | `sin valor predeterminado` | Secret: JDBC RDS privado con TLS validado |
| `DB_USER` | `sin valor predeterminado` | Secret/identidad de base de datos |
| `GOOGLE_APPLICATION_CREDENTIALS` | `sin valor predeterminado` | Credencial Google mediante identidad/montaje autorizado, no archivo en Git |
| `IOS_APP_ATTEST_PRODUCTION` | `true` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `IOS_APP_ID` | `sin valor predeterminado` | Team ID + Bundle ID |
| `LOG_FILE` | `sin valor predeterminado` | Definir configuración institucional por ambiente |
| `LOG_LEVEL` | `INFO` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MAXIMUM_EVIDENCE_AGE_SECONDS` | `120` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `OIDC_ISSUER_URI` | `sin valor predeterminado` | Issuer JWT institucional, no URL ilustrativa |
| `PLAY_CLOUD_PROJECT_NUMBER` | `sin valor predeterminado` | Número Google Cloud/Play Integrity correcto |
| `PORT` | `8080` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `SIGNING_KEYSTORE_PASSWORD` | `sin valor predeterminado` | Secret |
| `SIGNING_KEYSTORE_PATH` | `sin valor predeterminado` | Ruta archivo PKCS#12 montado |
| `SIGNING_KEY_ALIAS` | `sin valor predeterminado` | Alias autorizado |
| `SIGNING_KEY_ID` | `sin valor predeterminado` | Identificador de firma (kid) |
| `SPRING_FLYWAY_ENABLED` | `true` | Deshabilitar en pod cuando la migración corra por Job DBA |
| `SWAGGER_ENABLED` | `false` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `WALLET_CLIENT_ID` | `sin valor predeterminado` | Debe coincidir con cliente de Wallet/Certify |
| `WALLET_DIAG_SYNC_ALLOW_HTTP_IN_MESH` | `false` | `false`: no habilitar HTTP sin política de mTLS/mesh aprobada |
| `WALLET_DIAG_SYNC_BASE_URL` | `sin valor predeterminado` | Endpoint privado HTTPS de Diagnostics, solo si sincronización activa |
| `WALLET_DIAG_SYNC_CLIENT_ID` | `sin valor predeterminado` | Client ID técnico OAuth2, solo si sincronización activa |
| `WALLET_DIAG_SYNC_CLIENT_SECRET` | `sin valor predeterminado` | Secret OAuth2, solo si sincronización activa |
| `WALLET_DIAG_SYNC_ENABLED` | `false` | `false` al inicio; habilitar solo tras interoperabilidad |
| `WALLET_DIAG_SYNC_INITIAL_DELAY_MS` | `ver código / establecer si se requiere` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `WALLET_DIAG_SYNC_INTERVAL_MS` | `ver código / establecer si se requiere` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `WALLET_DIAG_SYNC_TOKEN_URL` | `sin valor predeterminado` | Token endpoint de OAuth2, solo si sincronización activa |

**Dependencias de puesta en servicio:** esquema PostgreSQL, migraciones DBA autorizadas, certificados y permisos de red/Secrets, luego smoke test. `SPRING_FLYWAY_ENABLED=false` en el Deployment EKS previsto requiere ejecutar migraciones previamente; el predeterminado de la aplicación es `true`.

**Criterio de activación:** no activar controles nuevos con valores de ejemplo. Los secretos y certificados se proporcionan por los mecanismos institucionales, no mediante el repositorio. Los flags nuevos desactivados conservan el flujo anterior mientras se ejecutan pruebas E2E.

**Verificación histórica antes de la entrega:** ejecutar `git diff <commit-actualmente-desplegado> HEAD -- .` dentro de este repositorio, revisar cambios de `application.*`, Dockerfile, Helm, `*.env` y referencias de variables en el código. Marcar como `EXISTENTE` cualquier nombre que ya estuviera operativo y no haya cambiado su interpretación.
