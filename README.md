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


---

## 24/11/2026 — MTC Portal de Enrolamiento: entrega 01 (diseño y persistencia)

**Alcance nuevo:** Flyway V3/V4, diez tablas nuevas de titular acreditado, entidades, padrones, operadores MTC, importación y auditoría; más evaluación **interna** de autorización institucional y pruebas JUnit. Leer [contratos y límites de la entrega](docs/MTC_PORTAL_ENTREGA01_ARQUITECTURA_Y_CONTRATOS.md).

**Portal Angular exclusivamente MTC:** roles `SUPER_ADMIN` y `MESA_DE_PARTES`. Las entidades externas envían Excel; **no** reciben cuentas del portal. No confundir con la propuesta multi-entidad con autoservicio de la especificación anterior.

**Variables de entorno:** este lote **no incorpora variables nuevas** en `application.yml`, Docker/Kubernetes ni las ya inventariadas arriba. La protección de DNI requerirá clave HMAC y cifrado de producción en un lote posterior; no se habilitan ni se solicitan secretos nuevos todavía. Cuando se incorporen, se actualizarán este README, el manifiesto de Kubernetes y las instrucciones a Infraestructura con nombres y valores predeterminados concretos.

**Despliegue:** las migraciones V3/V4 son aditivas y se ejecutarían automáticamente con `SPRING_FLYWAY_ENABLED=true` al desplegar una imagen que incluya este lote. Coordinar ventana y respaldo antes de promover; no están validadas todavía en PostgreSQL real. No modificar V1/V2. No se abren endpoints nuevos y se mantiene `.anyRequest().denyAll()` para rutas no existentes. Las pruebas `LabPostgresGuard` siguen deshabilitadas por defecto para la integración real.

**Estado de pruebas anterior a esta entrega:** 24/11/2026 `mvn clean verify`: Provider **23 OK, 4 omitidas**; Diagnostics **29 OK, 5 omitidas**; validación local del Lote 01 pendiente (en este entorno de generación no se dispone de Maven). Esos totales son histórico previo, no resultados de los archivos nuevos.


## Validación aislada del esquema institucional V3/V4 — entrega 01.1 (24/11/2026)

**Estado del último `clean verify` reportado:** 42 pruebas totales, 38 aprobadas, 4 omitidas (PostgreSQL), 0 fallas, `BUILD SUCCESS` (24/11/2026). Las 15 pruebas institucionales nuevas aprobaron. La prueba `PersistenceSmokeTest` usa H2 en memoria, **no valida las migraciones V3/V4 de PostgreSQL**.

Antes de integrar datos de identidad o desplegar V3/V4, ejecutar en la estación de desarrollo (Ubuntu con Docker) la comprobación aislada:

```bash
cd ~/fuentes/mtc/billetera/iugo/v2/repositorio
bash mcs-wallet-provider/tools/validate_portal_db_lab.sh
```

El script crea un contenedor efímero `postgres:16-alpine` con `--network none`, sin puertos publicados ni volúmenes del host. Solo ejecuta V1→V4 y pruebas de restricciones sobre `wallet_provider_lab`, creada dentro del contenedor; al salir, elimina el contenedor. Se bloquea si faltan Docker o los SQL necesarios. **No requiere credenciales ni URLs de RDS/QA/PRD**, y no las consume.

**Alcance:** valida DDL SQL y restricciones reales de PostgreSQL, pero **no es una ejecución del motor Flyway**, ni prueba `ddl-auto=validate`, concurrencia, ni integración con MiMoto/ID Perú. Las nueve pruebas PostgreSQL de Provider/Diagnostics permanecen omitidas por defecto y siguen protegidas por sus guardas anti-PRD. Las migraciones V3/V4 deben probarse adicionalmente por Flyway y contra un entorno autorizado antes de promover.

**Variables nuevas de ejecución del microservicio:** ninguna. El script usa únicamente Docker local y genera una contraseña efímera para su propio contenedor. Se conserva íntegra la documentación previa de Cognito, Provider/Diagnostics y los secretos existentes.

## 25/11/2026 — MTC Portal: entrega 02, núcleo de acreditación DNI–instalación (inactivo por defecto)

**Objetivo:** preparar en `mcs-wallet-provider` el servicio transaccional para asociar un DNI **autenticado por RENIEC/ID Perú** con la clave/instalación inscrita. **No crea endpoints y no modifica los flujos actuales de emisión/Verify.** Las tablas V3/V4 ya fueron validadas con PostgreSQL 16 aislado (script SQL, no motor Flyway).

### Variables nuevas (obligatorio revisar en cada entrega)

| Variable | Predeterminado | Uso / custodia |
|---|---|---|
| `WALLET_IDENTITY_ENABLED` | `false` | Interruptor **desactivado** hasta tener el adaptador M2M de evidencia real RENIEC/MiMoto. `true` sin adaptador/claves debe impedir el arranque. |
| `WALLET_IDENTITY_HMAC_KEY_B64` | Vacío | Clave HMAC-SHA-256 de **32 bytes** codificada en Base64. Secret, **nunca** ConfigMap, logs, repo o chat. |
| `WALLET_IDENTITY_ENCRYPTION_KEY_B64` | Vacío | Clave AES-256-GCM **independiente** de 32 bytes codificada en Base64. Secret, no ConfigMap. |
| `WALLET_IDENTITY_KEY_VERSION` | `1` | Versión de cifrado/HMAC. **No modificar durante la vida de los registros sin plan de migración/rotación.** |

Para QA/PRD: Infraestructura debe inyectar las dos claves desde Secrets Manager/External Secrets en el Deployment, **únicamente cuando se vaya a habilitar el servicio y exista el adaptador probado**. No habilitar el flag en AWS en esta entrega. Las claves deben ser persistentes por ambiente, no regeneradas en cada despliegue. Rotación de clave HMAC exige reindexar titulares/padrones coordinadamente y mantener capacidad de descifrado de registros antiguos. La entrega 02 no implementa rotación automática ni descifrado administrativo expuesto.

### Código incluido

- `identity/HolderIdentityCrypto.java`: índice HMAC SHA-256 determinista del DNI (sin SHA-256 simple); ciphertext AES-256-GCM con IV aleatorio, etiqueta de autenticidad y AAD estable.
- `identity/TrustedReniecEvidenceVerifier.java`: **interfaz, no implementación**. El adaptador MiMoto/RENIEC validará firma/origen, audiencia, expiración, propósito, nonce, sesión e instalación antes de devolver un DNI.
- `identity/IdentityAccreditationService.java`: crea sesión de acreditación de 10 minutos con nonce aleatorio, coteja evidencia confiable y vincula DNI–instalación mediante transacción. No reasigna una instalación ya acreditada ni reactiva vínculos institucionales revocados. Rechaza reuso de sesión.
- `identity/IdentityAccreditationConfig.java`: registra servicios solo si `WALLET_IDENTITY_ENABLED=true`; falla si faltan secretos o adaptador confiable. Se mantiene `false`.
- Pruebas JUnit de criptografía y rechazos; otras verificaciones E2E quedan pendientes de integración real.

**Precondición de seguridad fundamental:** `beginForProvenInstallation(...)` NO valida por sí mismo prueba de posesión. Solo se invocará desde una ruta futura que haya comprobado la clave registrada (Android/iOS) y correlación de sesión. `completeFromTrustedEvidence(...)` requiere adaptador servidor-a-servidor **autenticado**; el móvil no puede suministrar `biometriaOK`, DNI ni resultado de `userinfo` como verdad. Los métodos no son endpoints HTTP en este incremento.

**Límites pendientes:** no existe aún adaptador MiMoto/RENIEC a `TrustedReniecEvidenceVerifier`; no hay autenticación de la ruta de inicio/cierre de sesión, desbloqueo de Wallet, propagación de Diagnostics ni autorización de Verify. No crear valores de claves en el repositorio. No ejecutar en QA/PRD. Se preserva el ingreso de DNI y controles previos en cada emisión de credencial.

**Prueba local de la entrega 02:**

```bash
mvn -B -ntp -f mcs-wallet-provider/pom.xml -Dtest=HolderIdentityCryptoTest,IdentityAccreditationServiceTest test
mvn -B -ntp -f mcs-wallet-provider/pom.xml clean verify
```

**Estado reportado de entrega 01/01.1:** `42 total / 38 aprobadas / 4 PostgreSQL omitidas / BUILD SUCCESS`, V1–V4 ejecutadas por `psql` sobre PostgreSQL 16 temporal, ocho restricciones verificadas, rollback exitoso y contenedor eliminado. **No confundir ejecución directa de SQL con prueba del motor Flyway ni con aprobación de este código nuevo.**


## 25/11/2026 — Portal MTC: Entrega 03.1 (validador de evidencia MiMoto firmado)

Se incorpora `SignedMimotoReniecEvidenceVerifier` como adaptador de la interfaz interna de la Entrega 02. Valida JWS **RS256/ES256**, certificado X.509 fijado, issuer/audience, sesion/instalacion/nonce, DNI acreditado, proposito `HOLDER_ENROLLMENT`, resultado `SUCCESS` y vigencia corta. **Todavia NO hay emisor de evidencia en MiMoto ni endpoint HTTP nuevo en Provider.** `WALLET_IDENTITY_ENABLED=false` debe mantenerse en todos los despliegues. Ver `docs/MTC_PORTAL_ENTREGA03_1_EVIDENCIA_MIMOTO_FIRMADA.md`.

**Variables nuevas de `application.yml` (obligatorias solo al habilitar identidad):**

| Variable | Default | Procedencia |
|---|---|---|
| `WALLET_IDENTITY_MIMOTO_EVIDENCE_ISSUER` | Vacio | identificador del servicio MiMoto por ambiente; no usar issuer RENIEC |
| `WALLET_IDENTITY_MIMOTO_EVIDENCE_AUDIENCE` | Vacio | audiencia exclusiva de Provider, distinta de Cognito/Wallet |
| `WALLET_IDENTITY_MIMOTO_SIGNER_CERT_PATH` | Vacio | ruta al certificado publico X.509 del firmante MiMoto; montar por archivo de infraestructura |

No confundir estas variables con las 4 variables `WALLET_IDENTITY_*` de Entrega 02. El cliente M2M/certificado no esta provisionado aun, y **no debe crearse un valor de ejemplo para ambientes QA/PRD**. El archivo `k8s/deployment.yaml` actual no inyecta ni monta dicho certificado; Infraestructura debera ajustar Secret/volume en un lote de habilitacion posterior, despues de acordar la ruta real.

**Pruebas locales (despues de Entrega 01+02):**

```bash
mvn -B -ntp -f mcs-wallet-provider/pom.xml -Dtest=SignedMimotoReniecEvidenceVerifierTest test
mvn -B -ntp -f mcs-wallet-provider/pom.xml clean verify
```

El contrato no sustituye el requerimiento de DNI por cada emision de credencial, ni cambia los endpoints de Verify web.

## 25/11/2026 — Entrega 03.1.1: ajuste del contrato de pruebas de evidencia

Se corrigio una asercion **desactualizada** de `SignedMimotoReniecEvidenceVerifierTest`: `sub` es una referencia opaca de la sesion RENIEC y no incluye ni depende del DNI. Si MiMoto firma una evidencia valida correspondiente a otro DNI de 8 digitos, Provider debe aceptar ese DNI **como resultado acreditado por MiMoto**, sujeto a la correlacion de sesion, instalacion, nonce, proposito, vigencia y firma. No existe en este punto un DNI fijo previo que deba coincidir con `sub`.

Se incorporaron las pruebas negativas de **mismatch `sub`/`reniec_session_id`** y **modificacion del DNI despues de firmar el JWT**. No se cambia el verificador productivo, la base de datos, la configuracion ni los flujos de emision/verificacion web. Las pruebas deberan ejecutarse en el entorno con Maven.

**Variables de entorno:** se revisaron las de Entrega 03.1 (`WALLET_IDENTITY_MIMOTO_EVIDENCE_ISSUER`, `WALLET_IDENTITY_MIMOTO_EVIDENCE_AUDIENCE`, `WALLET_IDENTITY_MIMOTO_SIGNER_CERT_PATH`) y de Entrega 02. Esta correccion **no introduce variables nuevas**. Mantener `WALLET_IDENTITY_ENABLED=false` hasta completar y verificar la integracion real MiMoto/Provider.



## 25/11/2026 — Portal MTC: Entrega 03.4 (correlacion de clave con instalacion)

Se incorpora `HolderInstallationBindingVerifier`, servicio **interno** para verificar que el thumbprint
JWK SHA-256 de la clave que MiMoto acreditó coincide con la clave publica de la instalacion
registrada en Provider. Tambien verifica `identity_session_id`, `nonce`, estado `PENDING`,
proposito `HOLDER_ENROLLMENT`, vencimiento de la sesion, estado `ACTIVE` del dispositivo
y que aun no exista un titular asociado a esa instalacion. Compara hashes y thumbprints
en tiempo constante. **No publica nuevas rutas HTTP.**

La entrada `attestedKeyThumbprint` solo puede provenir del futuro intercambio backend-to-backend
autenticado con MiMoto, nunca de un campo de la billetera ni de una consulta web abierta.
La validacion no consume la sesion ni representa por si sola autorizacion de emitir evidencia:
se requiere despues enlazar este control con la sesion RENIEC, el marcador atomico y
`IdentityAccreditationService.completeFromTrustedEvidence`.

**Variables:** ninguna nueva. Se revisaron todas las variables `WALLET_IDENTITY_*` de
Entregas 02/03.1; conservar `WALLET_IDENTITY_ENABLED=false` hasta las pruebas E2E.

**Pruebas**: `mvn -B -ntp -f mcs-wallet-provider/pom.xml -Dtest=HolderInstallationBindingVerifierTest test`
y `mvn -B -ntp -f mcs-wallet-provider/pom.xml clean verify`.
Ver `docs/MTC_PORTAL_ENTREGA03_4_VINCULACION_SESIONES.md`.


## Entrega 03.5 — API privada MiMoto → Provider (25/11/2026)

**Estado:** preparada para QA. La funcionalidad permanece **desactivada**. No altera emisión, el formulario DNI, Verify web ni rutas de enrolamiento existentes.

Rutas internas nuevas (solo POST), disponibles únicamente cuando `WALLET_IDENTITY_ENABLED=true` y `WALLET_IDENTITY_MIMOTO_M2M_ENABLED=true`:

- `/api/v1/internal/identity/mimoto/verify-binding`: valida una sesión `HOLDER_ENROLLMENT` pendiente, nonce, instalación ACTIVE y thumbprint P-256 con la clave enrolada. Respuesta 204 sin datos personales.
- `/api/v1/internal/identity/mimoto/complete`: repite comprobación de vínculo y consume evidencia MiMoto firmada, aplicando cifrado/HMAC, asociación de titular y transacción con bloqueo en BD; respuesta 204 sin DNI.

**Seguridad estricta:** ambas rutas requieren JWT **access** Cognito válido, scope exacto `mtc-wallet-provider/wallet.identity.mimoto` y `client_id` de MiMoto incluido en `WALLET_IDENTITY_MIMOTO_M2M_CLIENT_IDS`. A diferencia del modo legacy de trust/admin, este acceso nunca se habilita cuando `WALLET_COGNITO_ENABLED=false`. El gateway/mesh debe permitir las rutas solo desde MiMoto y exigir TLS/mTLS según arquitectura aprobada. No usar `wallet.admin` ni una cuenta de operador humano.

| Variable NUEVA | Default | Descripción |
|---|---|---|
| `WALLET_IDENTITY_MIMOTO_M2M_ENABLED` | `false` | Permite registrar API M2M solo si también están configurados identidad y Cognito. **Mantener false** hasta pruebas QA. |
| `WALLET_IDENTITY_MIMOTO_M2M_CLIENT_IDS` | vacío | IDs de app-client Cognito **M2M MiMoto**, separados por coma, autorizados para el scope institucional. Sin valores = denegar. |

**Dependencias preexistentes**: `WALLET_IDENTITY_ENABLED`, claves HMAC y AES, certificados de evidencia firmada MiMoto, `WALLET_COGNITO_ENABLED`, `WALLET_COGNITO_ISSUER_URI` y `OIDC_ISSUER_URI` correctos. La configuración Cognito del Pool debe exponer scope `mtc-wallet-provider/wallet.identity.mimoto` en app-client de MiMoto. No se ha desplegado ni validado ese scope en AWS.

**No está incluido aún:** adaptador HTTP de MiMoto con `client_credentials`, creación segura de la sesión por Wallet con PoP, ni confirmación biométrica E2E. La `verify-binding` es solo comprobación preliminar; la confirmación final vuelve a validar estado, sesión y firma. No habilitar flags hasta culminar integración y homologación.

Pruebas locales: `mvn -B -ntp -Dtest=MimotoIdentityM2mSecurityContractTest,MimotoIdentityM2mControllerTest test` y `mvn -B -ntp clean verify` desde el directorio de Provider. Las pruebas utilizan tokens sintéticos/no firmados **solo para probar la política de autorización**, nunca sustituyen pruebas de JWT real con Cognito.

## Entrega 03.8 — Inicio de sesión HOLDER_ENROLLMENT por M2M (25/11/2026)

**Estado:** paquete de código preparado, **no desplegado ni validado E2E**. La API nueva permanece deshabilitada hasta completar Cognito y el circuito Wallet–RENIEC–Provider.

- **Ruta interna nueva:** `POST /api/v1/internal/identity/mimoto/start`. Solo accesible al cliente MiMoto con JWT access Cognito, `scope=mtc-wallet-provider/wallet.identity.mimoto`, `client_id` autorizado en `WALLET_IDENTITY_MIMOTO_M2M_CLIENT_IDS`, y los dos flags de identidad/M2M activos.
- Petición: `installationId` (UUID) y `keyThumbprint` (JWK SHA-256 P-256, obtenido **obligatoriamente** por MiMoto de `MtcWalletSessionGate.authorize(attestation, PoP)`). Un encabezado arbitrario del móvil **no constituye prueba**.
- Provider comprueba que la instalación está `ACTIVE`, no tiene titular vinculado y que la clave registrada coincide exactamente con el thumbprint confiable. Después, en una transacción distinta que vuelve a bloquear/verificar el estado, crea `wp_identity_session` con propósito `HOLDER_ENROLLMENT`, `sessionId`, `nonce` aleatorio y vencimiento.
- Respuesta HTTP **201**: `{ "sessionId": "<uuid>", "nonce": "<43 caracteres URL-safe>", "expiresAt": "<ISO-8601>" }`. No hay DNI ni dato biométrico en esta operación.
- `verify-binding` y `complete` **no cambian**; solo pueden utilizar sesiones iniciadas correctamente. El control transaccional de Provider vuelve a comprobar estado y ausencia de titular al crear la sesión.
- El endpoint NO debe incluirse en allowlist pública de gateway/mesh; restringir red a MiMoto, usar TLS/mTLS según infraestructura y auditar acceso M2M.

**Variables nuevas: ninguna.** Se reutilizan `WALLET_IDENTITY_ENABLED=false`, `WALLET_IDENTITY_MIMOTO_M2M_ENABLED=false`, `WALLET_IDENTITY_MIMOTO_M2M_CLIENT_IDS` (vacío) y `WALLET_COGNITO_ENABLED=false` de manera fail-closed. No aportar valores ficticios a AWS.

Pruebas focalizadas:

```bash
mvn -B -ntp -f mcs-wallet-provider/pom.xml \
  -Dtest=HolderInstallationBindingVerifierTest,MimotoIdentityM2mControllerTest,MimotoIdentityM2mSecurityContractTest test
mvn -B -ntp -f mcs-wallet-provider/pom.xml clean verify
```

**Pendiente de la próxima entrega:** exponer en MiMoto una ruta exclusiva con atestación/PoP obligatorios y conectar `client.start(...)` con el orquestador de acreditación. También falta consulta de estado confiable e integración real en Wallet. No se altera la solicitud de DNI al emitir cada credencial ni Verify Web.

## Entrega 03.10 — Estado de acreditación exclusivo de MiMoto (24/11/2026)

`POST /api/v1/internal/identity/mimoto/status` recibe `installationId` y `keyThumbprint` provenientes de una petición móvil cuya atestación y prueba de posesión ya fueron verificadas por MiMoto. La ruta exige el scope Cognito M2M `mtc-wallet-provider/wallet.identity.mimoto` y un `client_id` autorizado, sin abrir una API pública. Comprueba contra la clave P-256 almacenada en `wp_installation`, el estado de la instalación y el vínculo con `wp_identity_session` **COMPLETED** (evidencia, consumo y propósito `HOLDER_ENROLLMENT`).

Respuesta mínima JSON (`Cache-Control: no-store`): `state`, `walletAccessAllowed`, `checkedAt`. Estados: `ACCREDITED`, `IDENTITY_REQUIRED`, `IDENTITY_PENDING`, `IDENTITY_BLOCKED`, `INSTALLATION_INACTIVE`. **Solo `ACCREDITED` permite acceso**; la respuesta es informativa y no sustituye una validación por operación en backend. No expone DNI ni tokens, holderId, sesión RENIEC o datos biométricos.

La API permanece ausente si `WALLET_IDENTITY_ENABLED=false` o `WALLET_IDENTITY_MIMOTO_M2M_ENABLED=false`; incluso si alguien define una ruta equivalente, SecurityConfig exige Cognito activo y permisos M2M. **No hay nuevas variables**: se reutilizan `WALLET_IDENTITY_ENABLED`, `WALLET_IDENTITY_MIMOTO_M2M_ENABLED`, `WALLET_IDENTITY_MIMOTO_M2M_CLIENT_IDS` y `WALLET_COGNITO_ENABLED`, todas ya documentadas. No modifica V1–V4 ni la emisión.

---

## Entrega 03.15 — Precondición de identidad en atestación de claves de emisión (24/11/2026)

**Estado:** entregable para prueba local, **desactivado por defecto**. No despliega ni activa controles en AWS. Se añade `HolderCredentialAttestationPolicy` al camino de emisión de atestaciones de claves en `EnrollmentService`, sin modificar las rutas HTTP.

La política se evalúa **después** de que Provider haya comprobado la prueba de posesión (PoP) de la clave de instalación. Para `/attestations/credential-keys/android`, además se comprueban antes la PoP independiente de la clave de credencial y la evidencia de atestación hardware. El identificador y la clave usados para la consulta de identidad salen de `wp_installation`, **no** de una cabecera ni de un DNI enviado por el cliente.

Con obligatoriedad activa, Provider consulta `HolderIdentityStatusService` en PostgreSQL y **solo autoriza la firma de key attestations con `ACCREDITED` y `walletAccessAllowed=true`**. El proceso se deniega ante instalación revocada, DNI/titular no acreditado, sesión inconclusa, inconsistencia de estado, error de BD o clave almacenada inválida. No se altera la emisión de `wallet_attestation` usada para el enrolamiento técnico inicial, que debe existir antes de la acreditación biométrica.

La política cubre la ruta Android de clave de credencial y las rutas legacy `attestations/keys/android` y `attestations/keys/ios` a través de `EnrollmentService.issue(..., "key_attestation")`. No se han modificado las firmas de atestaciones ni el contrato de las credenciales.

**Variable nueva:**

| Variable | Valor predeterminado | Descripción |
|---|---|---|
| `WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED` | `false` | Si es `true`, la emisión de toda `key_attestation` requiere identidad acreditada en Provider. Requiere `WALLET_IDENTITY_ENABLED=true`; la aplicación falla al arrancar si falta esa condición. Mantener `false` en QA/PRD hasta pruebas E2E. |

**Pruebas de esta entrega:**

```bash
mvn -B -ntp -f mcs-wallet-provider/pom.xml -Dtest=HolderCredentialAttestationPolicyTest,CredentialKeyAttestationTest,EnrollmentServiceTest test
mvn -B -ntp -f mcs-wallet-provider/pom.xml clean verify
```

**Límite de seguridad decisivo:** esta precondición de Provider **NO** es todavía una autorización online en Certify. Una atestación emitida antes de revocar una instalación podría ser aceptada en Certify hasta su expiración. Tampoco se ha demostrado todavía que todos los canales y claves utilizadas por Certify pasan obligatoriamente por estos endpoints. El siguiente incremento debe implementar una validación **Certify → Provider** con client credentials **propias de Certify**, vínculo criptográfico a la clave del proof OpenID4VCI, audiencia/nonce/TTL y revocación vigente, antes de habilitar `WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED` o la obligatoriedad global. No activar la exigencia global de Wallet ni la guarda RENIEC por el solo resultado de estas pruebas.


## Entrega 03.16 — Registro de vínculo de clave de credencial (24/11/2026)

**Estado:** implementación local pendiente de validación Maven y PostgreSQL real; control
**desactivado por defecto**. Flyway agrega `V5__credential_key_issuance_binding.sql` sin
alterar V1–V4. Registra un `credential_key_thumbprint` RFC 7638 de la clave P-256,
huella SHA-256 del `c_nonce` del emisor, instalación, caducidad y fecha de emisión.
No persiste DNI, nonce en claro, claves privadas ni biometría.

`EnrollmentService.attestAndroidCredentialKey` inserta el registro **después**
de validar clave de instalación, PoP de ambas claves, hardware y acreditación
actual, y después de firmar; ocurre en la misma transacción. Un fallo de BD
impide completar la respuesta. El constraint UNIQUE evita reutilizar el mismo
par (clave, nonce) en instalaciones distintas.

La consulta interna `CredentialKeyBindingRegistry.activeAccreditedBinding` solo
autoriza si la instalación continúa ACTIVE, el vínculo de titular está ACTIVE,
la sesión HOLDER_ENROLLMENT está COMPLETED y la atestación sigue vigente.
Esta es una clase interna, **NO una API pública o M2M** y aún no integra Certify.

| Variable NUEVA | Default | Requisitos |
|---|---|---|
| `WALLET_IDENTITY_CREDENTIAL_BINDING_ENABLED` | `false` | Requiere `WALLET_IDENTITY_ENABLED=true` y `WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED=true` o falla el arranque. Mantener `false` en producción. |

**Pruebas**: `mvn -B -ntp -f mcs-wallet-provider/pom.xml -Dtest=CredentialKeyBindingRegistryTest,CredentialKeyAttestationTest,EnrollmentServiceTest test` y
`mvn -B -ntp -f mcs-wallet-provider/pom.xml clean verify`.

**Límite:** la entrega no añade todavía verificación online Certify → Provider;
no activar flags de protección global. El próximo incremento debe crear una
ruta de autorización exclusiva de Certify con OAuth2 client_credentials y
verificar criptográficamente la prueba OpenID4VCI contra el thumbprint
consultado y el c_nonce emitido por Certify.


## Entrega 03.17 — Autorización en línea Certify → Provider (M2M, OFF)

La API interna `POST /api/v1/internal/identity/certify/authorize-issuance` está
**desactivada por defecto** y solo es invocable por `inji-certify`, después de
validar criptográficamente el proof JWT OpenID4VCI (firma, audiencia, c_nonce),
la key attestation y la correspondencia exacta de la clave pública de la credencial.
Certify debe obtener `credentialKeyThumbprint` de **la clave probada** y `issuerNonce`
de **la sesión del emisor**; nunca de cabeceras o parámetros arbitrarios de la app.

Ejemplo de estructura JSON (sin datos reales):
`{"credentialKeyThumbprint":"<RFC7638_P256_43_CHARS>","issuerNonce":"<C_NONCE_DEL_EMISOR>"}`.
Una respuesta **204 No Content** y `Cache-Control: no-store` autoriza la solicitud;
**403** indica acreditación o vínculo no vigente, y cualquier otra respuesta,
error, timeout o fallo de Cognito/BD también **DEBE bloquear la emisión**.
El endpoint NO recibe DNI ni installationId, ni retorna información del ciudadano.
Las operaciones públicas anteriores de Provider no cambian.

### Variables nuevas de Provider (todas OFF, no crear valores simulados en AWS)

| Variable | Valor por defecto | Descripción |
|---|---|---|
| `WALLET_IDENTITY_CERTIFY_M2M_ENABLED` | `false` | Expone la API solo con identidad, binding V5, key attestation y Cognito habilitados. |
| `WALLET_IDENTITY_CERTIFY_M2M_CLIENT_IDS` | vacío | Allowlist de app-client IDs Cognito exclusivamente de Certify; sin IDs no autoriza. |

**Dependencias preexistentes:** `WALLET_IDENTITY_ENABLED=true`,
`WALLET_IDENTITY_CREDENTIAL_BINDING_ENABLED=true`,
`WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED=true`,
`WALLET_COGNITO_ENABLED=true`, firma/verificación de tokens Cognito válida y
Flyway V5 aplicada. Registrar en Cognito el scope exacto
`mtc-wallet-provider/wallet.issuance.certify` y concederlo únicamente al
cliente Certify por OAuth2 `client_credentials`. No concederle el scope MiMoto
`mtc-wallet-provider/wallet.identity.mimoto` ni `wallet.admin`. TLS y
restricción de red en ingress/mesh son controles de despliegue adicionales.

**Cambio complementario:** el SQL de `CredentialKeyBindingRegistry` se calificó
con el esquema `wallet_provider` para no depender del `search_path` JDBC.

**NO habilitar en producción:** falta integrar el cliente Certify, cubrir todos
los paths de emisión mDL/SD-JWT, ejecutar PostgreSQL V1–V5 y probar revocación
con un flujo real. Actualmente la API no autoriza solicitudes reales de Certify
porque éste todavía no la llama.

## Entrega 03.19 — Laboratorio PostgreSQL 16 aislado para V5

Antes de habilitar autorización Certify, ejecutar desde la raíz del repositorio:

```bash
bash mcs-wallet-provider/tools/validate_credential_binding_db_lab.sh
```

El script usa un PostgreSQL 16 efímero con `--network none`, sin puertos ni volúmenes
de la máquina host. Ejecuta migraciones V1–V5 con `search_path=wallet_provider,public`
y verifica integridad/consultas de habilitación, bloqueo y revocación con datos
ficticios, revirtiéndolos. **No se conecta a QA ni a PRD.** Requiere Docker
y una imagen `postgres:16-alpine` disponible localmente (o descargada por
el operador en entorno autorizado). No sustituye al plan Flyway de AWS.

**Validación Certify en Ubuntu sin firma GPG local:**

```bash
mvn -B -ntp -f inji-certify/pom.xml clean verify -Dgpg.skip=true
```

Conservar GPG exigido para builds publicables; el `skip` es solo para la
validación local. Flags M2M y de identidad siguen `false` hasta E2E.


## MTC · Entrega 03.21 — Laboratorio previo a homologación M2M QA (24/11/2026)

El script `tools/mtc_certify_m2m_preflight.py` realiza verificaciones locales de
contratos sin red, y opcionalmente peticiones **exclusivamente de lectura** sobre
la API interna Certify–Provider de un QA expresamente aprobado. Solicita token
Cognito `client_credentials` mediante HTTPS, nunca imprime ni persiste el
access_token o los secretos y exige `204` solo en la comprobación positiva opcional.

```bash
python3 -m unittest discover -s mcs-wallet-provider/tools/tests -p 'test_mtc_certify_m2m_preflight.py' -v
python3 mcs-wallet-provider/tools/mtc_certify_m2m_preflight.py --offline
```

Las pruebas con red requieren configuración separada del entorno QA, aprobación
expresa y los flags existentes ya habilitados allí. Ver
`docs/MTC_ENTREGA03_21_PREFLIGHT_CERTIFY_QA.md`.
No cambia las variables ni activa ninguna política en PRD.

---

## 24/11/2026 — MTC Entrega 03.22: control integrado de preparación local

Se incluye `tools/mtc_integrated_readiness.py` con `--plan`, `--run`, `--with-postgres` opcional y generación de evidencia JSON sanitizada. Ejecuta de manera local los controles de Wallet/Jest, MiMoto, Provider, Certify, contratos OAuth2 y, si se solicita, migraciones V1–V5 en PostgreSQL efímero. Los estados `qa_e2e=PENDING` y `production_release=NOT_AUTHORIZED` se mantienen incluso ante resultado local exitoso. **No hay cambios de código productivo, flags ni rutas HTTP.**

Comandos, límites, prerrequisitos, matriz de aceptación y pendientes de QA: [MTC_ENTREGA03_22_CONTROL_INTEGRADO_LOCAL.md](docs/MTC_ENTREGA03_22_CONTROL_INTEGRADO_LOCAL.md).

## Entrega 03.23 — Matriz y evidencia de homologación QA

Se incluye la herramienta **sin red** `tools/mtc_qa_e2e_evidence.py` y el catálogo versionado `tools/mtc_qa_e2e_cases.json` con **34 pruebas E2E QA**. A partir de `mtc_e0322_readiness_con_pg.json` con PASS comprueba el baseline local, genera la matriz de verificación y un manifiesto documental inicialmente pendiente; **no** inicia conexiones con AWS, Cognito, Android, ID Perú, bases de datos ni activa flags. La cobertura documental comprende acreditación, atestación, emisión mDL/SD-JWT, fallos de seguridad, revocación, compatibilidad y rollback QA.

**Ejecución:** `python3 -m unittest discover -s mcs-wallet-provider/tools/tests -p test_mtc_qa_e2e_evidence.py -v` (31 pruebas). Luego `python3 mcs-wallet-provider/tools/mtc_qa_e2e_evidence.py --init --local-report ./mtc_e0322_readiness_con_pg.json --out-dir ./mtc_qa_e0323`. Documentación completa en `docs/MTC_ENTREGA03_23_EXPEDIENTE_E2E_QA.md`.

**Estado:** `qa_e2e=PENDING` hasta ejecutar y revisar escenarios reales; incluso con evidencias documentales completas, `production_release=NOT_AUTHORIZED` requiere decisión institucional independiente.

## Entrega 03.24 — Registro versionado de evidencias QA (24/11/2026)

La herramienta complementaria `tools/mtc_qa_e2e_register.py` evita editar manualmente el
manifiesto E03.23. Sus operaciones `configure` y `record` crean un **archivo nuevo**,
nunca sobrescriben el expediente anterior y exigen baseline E03.22 válido. Calcula
SHA-256 de soportes `.md`, `.txt` o `.json` ya sanitizados (permisos `0600`);
solo conserva la huella, ticket, resultado **declarado por el operador** y fecha.
Para repetir escenarios `FAIL`/`BLOCKED` se exige `--retest` y el ticket sustituido;
no permite cambiar un `PASS` anterior dentro del mismo expediente.

```bash
python3 -m unittest discover -s mcs-wallet-provider/tools/tests \
  -p test_mtc_qa_e2e_register.py -v
python3 mcs-wallet-provider/tools/mtc_qa_e2e_register.py --help
```

Las opciones, el flujo completo de registro, las restricciones de seguridad y
el formato para evaluar el resultado se describen en
`docs/MTC_ENTREGA03_24_REGISTRO_INCREMENTAL_QA.md`.
**No** conecta a AWS ni da por aprobada una ejecución E2E sin evidencia real;
`production_release=NOT_AUTHORIZED` sigue siendo obligatorio.

## Entrega 03.25 — Resumen de avance y pendientes de homologación QA

`tools/mtc_qa_e2e_progress.py` produce, **sin red ni modificación de expedientes**, un
reporte JSON y una matriz Markdown del avance documental de los 34 escenarios QA,
agrupados en sus 11 áreas. Valida primero el readiness E03.22, el catálogo E03.23
y la integridad estructural del expediente E03.23/E03.24. Exige referencia, SHA-256
y fecha válidos también en registros `FAIL` y `BLOCKED` para que el avance no
contabilice ejecuciones sin soporte documental.

```bash
python3 -m unittest discover -s mcs-wallet-provider/tools/tests \
  -p test_mtc_qa_e2e_progress.py -v
python3 mcs-wallet-provider/tools/mtc_qa_e2e_progress.py \
  --local-report ./mtc_e0322_readiness_con_pg.json \
  --evidence ./mtc_qa_e0323/mtc_qa_e0323_evidencias.json \
  --out-dir ./mtc_qa_e0325_resumen_inicial
```

Tras registrar casos mediante E03.24, sustituir `--evidence` por la ruta **más
reciente** del expediente versionado y utilizar un directorio nuevo en `--out-dir`.
No se aceptan sobrescrituras. Los resultados `PASS` son declaraciones del operador,
no una validación automatizada E2E. Incluso con 34/34 declarados PASS,
**QA E2E no es certificada por la herramienta y PRD permanece NOT_AUTHORIZED**.
Ver `docs/MTC_ENTREGA03_25_AVANCE_QA.md`.

---

## 25/11/2026 — Entrega 03.26: Inventario declarativo de QA y dependencias de flags

Se incorpora `tools/mtc_qa_deployment_inventory.py`, sin conexiones a QA/PRD y
sin cambios productivos. Genera una plantilla de 13 flags sin valores inventados
(`UNRECORDED`), comprueba precedencias entre Wallet/MiMoto/Provider/Certify y
permite producir un **nuevo** expediente E03.23 configurado con cuatro revisiones
QA y un ticket de cambio. Reutiliza la verificación E03.22, el catálogo E03.23
y las reglas de configuración E03.24. **No verifica despliegues reales**: los
valores son declaraciones de Infraestructura que deberán contrastarse con AWS QA.

**Variables de entorno nuevas de servicios: ninguna.** No se activan flags
ni se conectan recursos. Mantener homologación E2E pendiente y producción
`NOT_AUTHORIZED`. Instrucciones y reglas:
[Entrega 03.26](docs/MTC_ENTREGA03_26_INVENTARIO_FLAGS_QA.md).
