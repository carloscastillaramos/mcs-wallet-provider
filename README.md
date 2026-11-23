# mcs-wallet-provider 0.4.0 — Java 21 · PostgreSQL · AWS EKS

> **Para Infraestructura MTC (23/11/2026):** ir primero a [Amazon Cognito — instrucciones de aprovisionamiento](#amazon-cognito--instrucciones-de-aprovisionamiento-qa-y-prd-23112026). Contiene recursos AWS, variables **exactas** del código, Secrets/ConfigMaps, pruebas, criterios de activación y la información que debe retornar Infraestructura. La configuración previa no relacionada con Cognito permanece vigente.

**Estado verificado el 23/11/2026:** `mvn -B -ntp -f mcs-wallet-provider/pom.xml clean verify` = **BUILD SUCCESS**, Java 21, 17 tests contabilizados (13 OK, 4 omitidos de integración PostgreSQL); JAR generado. Esto valida compilación y pruebas locales, **no** equivale a integración Cognito/Redistribución QA/PRD ni homologación de OAuth/HAIP. El código Cognito Lote 1 + hotfix 1.1 está preparado pero **inactivo por defecto**.

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
docker build -t mcs-wallet-provider:0.4.0 .
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

- **Validado:** compilación y 13 tests Maven sobre Java 21 (23/11/2026); faltan 4 pruebas PostgreSQL omitidas y CI institucional.
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
| `OIDC_ISSUER_URI` | `sin valor predeterminado` | Al habilitar Cognito, issuer real del mismo User Pool indicado en `WALLET_COGNITO_ISSUER_URI` |
| `WALLET_COGNITO_ENABLED` | `false` | **Nuevo**: `true` solo tras pruebas en QA; flag opt-in |
| `WALLET_COGNITO_ISSUER_URI` | vacío | **Nuevo**: issuer real obtenido de Infraestructura, no token endpoint |
| `WALLET_COGNITO_TRUST_CLIENT_IDS` | vacío | **Nuevo**: IDs de App Clients autorizados a consultar trust, separados por coma |
| `WALLET_COGNITO_ADMIN_CLIENT_IDS` | vacío | **Nuevo**: IDs de App Clients autorizados a revocar, separados por coma |
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
| `WALLET_DIAG_SYNC_CLIENT_SECRET` | `sin valor predeterminado` | Secret OAuth2, solo si sincronización activa; nunca texto plano en ConfigMap |
| `WALLET_DIAG_SYNC_SCOPE` | `diagnostics.device.sync` | **Ajuste Cognito**: `mtc-wallet-diagnostics/diagnostics.device.sync` al activar M2M |
| `WALLET_DIAG_SYNC_ENABLED` | `false` | `false` al inicio; habilitar solo tras interoperabilidad |
| `WALLET_DIAG_SYNC_INITIAL_DELAY_MS` | `ver código / establecer si se requiere` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `WALLET_DIAG_SYNC_INTERVAL_MS` | `ver código / establecer si se requiere` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `WALLET_DIAG_SYNC_TOKEN_URL` | `sin valor predeterminado` | Token endpoint de OAuth2, solo si sincronización activa |

**Dependencias de puesta en servicio:** esquema PostgreSQL, migraciones DBA autorizadas, certificados y permisos de red/Secrets, luego smoke test. `SPRING_FLYWAY_ENABLED=false` en el Deployment EKS previsto requiere ejecutar migraciones previamente; el predeterminado de la aplicación es `true`.

**Criterio de activación:** no activar controles nuevos con valores de ejemplo. Los secretos y certificados se proporcionan por los mecanismos institucionales, no mediante el repositorio. Los flags nuevos desactivados conservan el flujo anterior mientras se ejecutan pruebas E2E.

**Verificación histórica antes de la entrega:** ejecutar `git diff <commit-actualmente-desplegado> HEAD -- .` dentro de este repositorio, revisar cambios de `application.*`, Dockerfile, Helm, `*.env` y referencias de variables en el código. Marcar como `EXISTENTE` cualquier nombre que ya estuviera operativo y no haya cambiado su interpretación.

---

## Amazon Cognito — instrucciones de aprovisionamiento QA y PRD (23/11/2026)

### 1. Alcance y responsabilidades

**Infraestructura**: crear/reutilizar y documentar un **Amazon Cognito User Pool por ambiente**, recursos OAuth 2.0, App Clients, Secret Manager/External Secrets, variables EKS, salida HTTPS y políticas Istio. **Desarrollo**: comprobar los valores con el código, cubrir pruebas negativas, homologar flujos y activar la sincronización solo después de QA. No reutilizar el login ciudadano RENIEC/SSOIUGO ni confundir OAuth M2M con Wallet Client Attestation o las claves PKCS#12 de firma.

Los App Clients y scopes indicados a continuación son el **contrato propuesto del Lote Cognito 1**; no se declara que ya existan en AWS. Confirmar primero la configuración ya desplegada para no duplicar servicios o sobrescribir valores que estén operativos.

### 2. Recursos que debe configurar Infraestructura (por ambiente)

1. Identificar **cuenta AWS, región, ambiente, User Pool ID e issuer** real; verificar que el User Pool puede emitir tokens OAuth. Un User Pool no equivale a un Identity Pool.
2. Configurar el **dominio Cognito** (o dominio institucional aprobado), de forma que `https://<DOMINIO_COGNITO>/oauth2/token` sea accesible mediante HTTPS desde EKS. El **issuer** y **JWKS** corresponden al User Pool y **no** son esa URL de token: `issuer` habitual `https://cognito-idp.<REGION>.amazonaws.com/<POOL_ID>` y JWKS `issuer + /.well-known/jwks.json`. Copiar valores efectivos del discovery OIDC; no asumir que todos los entornos utilizan la misma región o formato de issuer.
3. Crear/revisar Resource Server con **identifier** exacto `mtc-wallet-provider`, scopes `wallet.trust.read` y `wallet.admin`. Los nombres completos serán `mtc-wallet-provider/wallet.trust.read` y `mtc-wallet-provider/wallet.admin`.
4. Crear/revisar Resource Server `mtc-wallet-diagnostics`, scopes `diagnostics.device.sync`, `diagnostics.read` y `diagnostics.admin`. El scope técnico exacto será `mtc-wallet-diagnostics/diagnostics.device.sync`.
5. Crear App Clients **diferentes** para consultas de confianza (`trust`), administración/revocación y el M2M exclusivo **Provider → Diagnostics**. Si se usarán portales, definir clientes públicos **Authorization Code + PKCE** y URLs callback/logout aprobadas; el portal multi-entidad es un trabajo aparte, no se habilita con este lote. El cliente técnico M2M debe ser **confidencial** y usar **solamente** `client_credentials`, con el **único scope** `mtc-wallet-diagnostics/diagnostics.device.sync`.
6. Aprobar MFA/federación para operadores; mapear usuarios/entidades/roles dentro de la lógica MTC, no únicamente por scopes de Cognito. El `client_id` identifica la aplicación OAuth, **no** identifica una entidad externa ni un usuario por sí mismo.
7. Aprovisionar el client secret M2M con Secrets Manager y la solución corporativa de inyección en EKS (External Secrets o equivalente); aplicar RBAC/IAM de mínimo privilegio y política de rotación; **no comunicar secretos en chat, tickets, correo ni Git**.
8. Confirmar conexión saliente TLS de pods hacia issuer/JWKS/token endpoint, DNS, CA, proxy/VPC endpoint según topología; restringir `/api/v1/installations/*/revoke` y rutas administrativas también en gateway/mesh. No cambiar el mTLS global ni exponer rutas internas por internet.

### 3. Variables EXACTAS de mcs-wallet-provider

Las siguientes variables están implementadas en `src/main/resources/application.yml`, `config/CognitoJwtConfig.java`, `config/SecurityConfig.java`, `sync/DiagnosticsSyncWorker.java` y/o `k8s` del paquete Cognito 1. Se entregan como contrato **por ambiente**:

| Variable | QA inicial antes de habilitar | Valor al activar Cognito QA | Origen de configuración |
|---|---|---|---|
| `OIDC_ISSUER_URI` | Mantener issuer JWT de QA ya operativo | **Mismo issuer del User Pool** que `WALLET_COGNITO_ISSUER_URI` | `k8s/configmap.yaml` → ConfigMap `mcs-wallet-provider-settings` |
| `WALLET_COGNITO_ENABLED` | `false` | `true` después de pruebas | ConfigMap `mcs-wallet-provider-settings` |
| `WALLET_COGNITO_ISSUER_URI` | Vacío/valor no utilizado con flag `false` | URI issuer efectiva del User Pool QA | ConfigMap `mcs-wallet-provider-settings` |
| `WALLET_COGNITO_TRUST_CLIENT_IDS` | Vacío | Lista de App Client IDs para consultas trust, **separada por comas** | ConfigMap `mcs-wallet-provider-settings` |
| `WALLET_COGNITO_ADMIN_CLIENT_IDS` | Vacío | Lista de App Client IDs autorizados para revocación, **separada por comas** | ConfigMap `mcs-wallet-provider-settings` |
| `WALLET_DIAG_SYNC_ENABLED` | `false` | `true` **solo tras** habilitar Diagnostics y validar M2M/E2E | ConfigMap `mcs-wallet-provider-settings` |
| `WALLET_DIAG_SYNC_BASE_URL` | No activa | Base HTTPS **interna** real del servicio Diagnostics; sin ruta final | ConfigMap `mcs-wallet-provider-settings` |
| `WALLET_DIAG_SYNC_TOKEN_URL` | No activa | `https://<DOMINIO_COGNITO>/oauth2/token` real de QA | ConfigMap `mcs-wallet-provider-settings` |
| `WALLET_DIAG_SYNC_SCOPE` | Predeterminado legacy `diagnostics.device.sync` | `mtc-wallet-diagnostics/diagnostics.device.sync` (exacto) | ConfigMap `mcs-wallet-provider-settings` |
| `WALLET_DIAG_SYNC_CLIENT_ID` | Sin valor cuando sync inactivo | **Client ID del M2M Provider→Diagnostics** | Secret K8s `mcs-wallet-provider-diagnostics-sync`, clave `client-id` |
| `WALLET_DIAG_SYNC_CLIENT_SECRET` | Sin valor cuando sync inactivo | Secreto M2M **inyectado**, no publicado | Secret K8s `mcs-wallet-provider-diagnostics-sync`, clave `client-secret` |
| `WALLET_DIAG_SYNC_ALLOW_HTTP_IN_MESH` | `false` | Mantener `false` (HTTPS); cambiar solo con aprobación explícita de mesh/mTLS | ConfigMap `mcs-wallet-provider-settings` |

**Observaciones de implementación:** `WALLET_COGNITO_ENABLED` está desactivado por defecto. En Cognito activo, la API de consulta de confianza exige **scope + client ID permitido**; el endpoint de revocación también exige ambos. Las listas vacías **deniegan** el acceso. `WALLET_DIAG_SYNC_ENABLED` es **independiente**: no activarlo en la misma operación si aún no existe la identidad de servicio ni la conectividad QA. `WALLET_CLIENT_ID`/`ATTESTATION_ISSUER` pertenecen a la firma/atestación de billetera; **no** sustituirlos automáticamente por el App Client M2M de Cognito.

### 4. Archivos EKS que debe tocar Infraestructura

- `k8s/configmap.yaml`: plantilla **no aplicable sin renderizar**. Renderizar en pipeline y comprobar los once nombres de variables de la tabla; **nunca** depositar client secrets aquí.
- `k8s/deployment.yaml`: el deployment ya referencia el Secret `mcs-wallet-provider-diagnostics-sync` con las claves `client-id` y `client-secret` (opcionales al inicio). Gestionar la materialización con External Secrets/Secrets Manager según política institucional. Verificar que `envFrom: mcs-wallet-provider-settings` se conserva.
- **Config existente** `OIDC_ISSUER_URI`: si al habilitar Cognito no coincide con el nuevo issuer, el decodificador/validación no estará alineado. Gestionar el cambio por despliegue, no editar pods a mano.
- Mantener las variables previas de DB, Flyway, Play Integrity, certificados de firma y claves de atestación **sin cambios** salvo diferencia aprobada y rastreada en Git.

### 5. Evidencias que Infraestructura debe devolver a Desarrollo (sin secretos)

| Campo solicitado | Respuesta requerida por ambiente |
|---|---|
| AWS / despliegue | Cuenta/alias, región, cluster EKS, namespace, ambiente QA/PRD, responsable |
| Cognito User Pool | User Pool ID, issuer **exacto**, URL `/.well-known/openid-configuration`, URL JWKS, dominio y URL `/oauth2/token` |
| Resource Server | Identificadores exactos de Provider y Diagnostics y lista completa de scopes habilitados |
| App Clients | IDs **diferenciados** para trust, administración/revocación y sincronización M2M, grant autorizado de cada uno, scopes permitidos |
| Secrets / red | ARN/nombre de Secret de credencial M2M, ruta de inyección EKS, políticas IAM/IRSA/Pod Identity, confirmación TLS/DNS/mTLS, **sin valor del secret** |
| Portal/federación | IdP aprobado (si aplica), callbacks/logout por ambiente, MFA, y decisión de claims/roles/tenant. Indicar claramente si aún está **pendiente** |
| Pruebas | Confirmación de que JWT QA de prueba trae `iss`, `token_use=access`, `client_id` y `scope` esperados; **solo claims ficticios/saneados, jamás JWT firmado real** |
| Compatibilidad | Confirmar si issuer usa el formato clásico `cognito-idp.<REGION>.amazonaws.com/<POOL>` o variante `issuer-cognito-idp...`; informar antes de activar, ya que el código del lote valida un patrón concreto |

### 6. Orden de habilitación, criterios de aceptación y retorno

1. **Preparación**: importar y compilar el código de Provider 0.4.0, mantener `WALLET_COGNITO_ENABLED=false` y `WALLET_DIAG_SYNC_ENABLED=false`. Registrar valores actuales para rollback.
2. **Infra QA**: confirmar User Pool, scopes, App Clients, Secrets y red. Infraestructura devuelve los valores no secretos de la tabla; Desarrollo revisa diferencias de issuer, claims, política de MFA y alcance de los clientes.
3. **Activar Cognito en Diagnostics QA primero**, comprobando los rechazos de ID Token, client ID no autorizado, scope incorrecto, emisor incorrecto, expirado y firma alterada.
4. **Activar Cognito en Provider QA**, comprobar `GET /api/v1/installations/{id}/trust` con scope/client adecuados y `POST .../revoke` solo con privilegios administrativos; revisar 401/403 negativos y auditoría.
5. **Activar sincronización M2M** solo después: el token debe provenir de `/oauth2/token` con `client_credentials` y el único scope `mtc-wallet-diagnostics/diagnostics.device.sync`; Diagnostics debe aceptar únicamente el client ID exacto del M2M. Probar altas, revocación, reintentos/idempotencia y TLS interno.
6. Validar migraciones PostgreSQL, atestación Android/iOS y flujos E2E separados. Luego promoción PRD con User Pool/clients/secrets **propios del ambiente**, evidencias y plan de rollback (`WALLET_DIAG_SYNC_ENABLED=false` primero; reversión de modo Cognito conforme ventana aprobada).

**Pendientes explícitos de Desarrollo dependientes de respuesta de Infraestructura**: adecuar el validador de formato de issuer si Cognito usa un formato actualizado; incorporar/mantener pruebas JWT reales y negativas con cliente y scopes; integrar el portal multi-entidad y autorización por entidad cuando exista el diseño de identidad; homologar la aceptación de Wallet Client Attestation con el Authorization Server de emisión (Cognito no la sustituye por defecto).

Documentación AWS: [Resource servers y scopes](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-define-resource-servers.html), [Endpoints OIDC/JWKS](https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints.html), [Token endpoint](https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html), [Validación de JWT](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html).
