> DOCUMENTO HISTÓRICO 0.2.8: configuración Oracle y Kubernetes MTC ya NO aplican. Consulte README.md y k8s/README_AWS_EKS.md para v0.3.0.

# MCS Wallet Provider 0.2.8 — MTC

> Imagen y configuración genéricas para todos los ambientes. Se utiliza el historial Flyway `WP_FLYWAY_SCHEMA_HISTORY` en el esquema Oracle compartido. La versión 0.2.8 no activa por sí sola el enrolamiento móvil ni obliga a Certify a exigir atestaciones.

Servicio de enrolamiento y confianza de instalaciones de **Billetera MTC**, Android e iOS. Java 21, Spring Boot 3.4.5, Oracle 19c, Flyway. Esta versión es una **base técnica para integración y homologación**, NO una liberación productiva certificada.

## Alcance implementado

1. Desafíos criptográficamente aleatorios, vigencia limitada, consumo transaccional mediante bloqueo pesimista en Oracle.
2. Enrolamiento Android mediante prueba ECDSA P-256, certificado Android Key Attestation encadenado a raíces configuradas y veredicto Play Integrity validado en el backend de Google.
3. Enrolamiento iOS mediante Apple App Attest, certificado encadenado a raíz configurada, nonce, RP ID, AAGUID, identificador y clave pública. Assertions posteriores: firma y contador estrictamente creciente.
4. Registro de instalación con estado, confianza básica y revocación administrativa; JWT con firma RS256/ES256 y JWKS público.
5. OAuth2 Resource Server para acceso entre servicios, endpoints abiertos limitados a desafíos/enrolamiento y prueba de posesión; sin claves privadas de dispositivos en la BD.
6. Audit trail de registros, revocaciones y emisiones. Docker/Kubernetes con montajes de solo lectura; secretos de despliegue gestionables por Sealed Secrets.

## Estado de estándares

**No afirmar conformidad OpenID4VCI/HAIP todavía:** desde v0.2.0, los JWT de Wallet Attestation incorporan `typ=oauth-client-attestation+jwt`, `cnf.jwk` y un `sub` común al tipo de billetera, evitando un identificador de instalación transversal. Los de Key Attestation incorporan `typ=key-attestation+jwt` y `attested_keys`. Desde v0.2.8, la firma de Key Attestation **rechaza** PKCS#12 que no aporte una cadena institucional X.509 no autofirmada; omite la raíz de `x5c`. Estos son avances hacia los apéndices D/E, pero las políticas del emisor, certificados de confianza, OAuth Client Attestation PoP, renovación y revocación de tokens requieren homologación. **Los endpoints antiguos `/attestations/keys/*` siguen refiriéndose a la clave de instalación**. El nuevo `/attestations/credential-keys/android` verifica una clave de credencial separada. Para iOS, App Attest demuestra una clave de instancia de aplicación, no por sí misma la protección hardware de cualquier clave mdoc/SD-JWT. No presentar tokens a emisores externos como atestaciones homologadas.

El proyecto **no incluye** cambios a INJI Wallet, Mimoto BFF ni `mcs-wallet-diagnostics`. La integración de este último permanece en standby.

## Cambios v0.2.8 — atestación de claves de credencial Android

Se incorpora un contrato independiente `POST /api/v1/attestations/credential-keys/android`. Solo está preparado del lado servidor; **no hay aún un cliente INJI Wallet que lo invoque**, por lo que no debe activarse como política obligatoria del emisor. Sin nuevos objetos Oracle ni variables por ambiente.

Requiere una instalación Android previamente enrolada y ACTIVE, un desafío no consumido, la cadena de Key Attestation de la **clave de credencial nueva** generada con `setAttestationChallenge(nonce.getBytes(UTF_8))`, y dos firmas sobre el mismo mensaje: la de la clave de instalación y la de la clave de credencial. La cadena se verifica contra las raíces confiables existentes y el certificado hoja debe contener esa misma clave. El campo `issuerNonce` lleva el `c_nonce` real recibido de Certify; se incluye en el JWT de Key Attestation.

Solicitud JSON, cuyos valores son ilustrativos y **no contienen secretos ni URLs reales**:

```json
{
  "installationId": "<id-entregado-en-enrolamiento>",
  "challengeId": "<id-desafio-ANDROID>",
  "credentialPublicKeyPem": "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----",
  "credentialKeyAttestationChain": ["<base64-certificado-hoja>", "<base64-certificado-intermedio>"],
  "issuerNonce": "<c_nonce-recibido-del-emisor>",
  "installationProofSignature": "<firma-ecdsa-der-base64url>",
  "credentialProofSignature": "<firma-ecdsa-der-base64url>"
}
```

El mensaje firmado por **ambas** claves es la concatenación UTF-8 exacta:

```text
wp-credential-key:v1:<challengeId>:<challengeNonce>:<installationId>:<sha256Base64Url(DER-SPKI-credentialKey)>:<sha256Base64Url(UTF8(issuerNonce))>
```

`sha256Base64Url` significa SHA-256 y codificación Base64URL sin padding. El servidor no confía en la cadena ni en el `issuerNonce` por sí solos; debe superar ambas firmas, el desafío activo y las comprobaciones hardware. Un fallo impide que se emita el JWT. Las rutas antiguas de atestación no cambian de contrato; **no son sustitutos** de la ruta nueva para claves de credenciales.

El endpoint solo cubre Android. En iOS se necesita diseñar la atestación de una clave de credencial genuinamente protegida en Secure Enclave y su asociación con App Attest; no afirmar garantías hardware a partir de una aserción de instalación solamente. Tampoco se declaran por ahora niveles certificados `iso_18045_*` en el JWT.

**Secuencia pendiente antes de usarlo en emisión:** adecuar generación nativa de claves sin invalidar credenciales existentes; consumir este endpoint desde INJI Wallet; pasar `key_attestation` en el proof JWT generado por Mimoto/Wallet; hacer cumplir la cadena X.509, c_nonce y correspondencia de clave en Certify; probar en dispositivos reales y con certificados institucionales. Mantener la integración bajo bandera desactivada durante estas etapas.

## Construcción

Requisitos: JDK 17, Maven 3.9+, Oracle 19c y PKCS#12 de firma para ejecución. El desarrollador valida con `mvn clean install`; el pipeline MTC debe repetir pruebas y construir la imagen. Flyway crea el esquema al arrancar el servicio con permisos adecuados. La compilación Maven por sí sola no necesita conexión Oracle ni secretos institucionales.

### JAR estable e imagen Docker versionada

`pom.xml` define `<finalName>mcs-wallet-provider</finalName>`, por lo que la compilación genera siempre `target/mcs-wallet-provider.jar` aunque cambie la versión Maven. El `Dockerfile` usa `COPY target/mcs-wallet-provider.jar app.jar` y **no necesita actualizarse en cada release**. El archivo `.dockerignore` elimina del contexto código fuente, ficheros IDE, artefactos de pruebas y patrones de secretos; conserva el JAR necesario.

```bash
mvn clean install
```

`docker build` **no es un paso obligatorio para el desarrollador**. CI/CD debe construir y publicar la imagen en el registry institucional, registrar el digest inmutable y establecer `IMAGE_REF` durante el despliegue. No introducir nombres de registries ni URLs de ambiente en las fuentes.

El servicio falla al iniciar si falta el PKCS#12 o su contraseña. Nunca incluir claves ni contraseñas en Git. Configurar también una fuente OAuth2 válida (`OIDC_ISSUER_URI`) antes de iniciar. Para las credenciales de Google usar Application Default Credentials mediante cuenta de servicio restringida, montada en el pod.

## Protocolo Android

1. `POST /api/v1/enrollments/challenge` `{"platform":"ANDROID"}` → `challengeId`, `nonce`.
2. Generar una **nueva clave P-256 no exportable** en AndroidKeyStore con `setAttestationChallenge(nonce.getBytes(UTF_8))`. Recoger la cadena DER X.509 de `getCertificateChain(alias)`, codificar cada certificado en Base64 estándar.
3. Firmar con la clave privada los bytes UTF-8 exactos `wp-enroll:<challengeId>:<nonce>:<keyId>` mediante `SHA256withECDSA`, codificar firma DER en Base64URL sin padding.
4. Solicitar Play Integrity **Standard** con `requestHash=BASE64URL(SHA256(UTF8("wp-enroll:"+challengeId+":"+nonce+":"+keyId+":"+BASE64URL(SHA256(UTF8(publicKeyPem))))))`. El PEM debe coincidir byte por byte con el enviado al servidor.
5. `POST /api/v1/enrollments/android`: `challengeId`, `keyId`, `publicKeyPem` (SPKI PEM), `proofSignature`, `playIntegrityToken`, `keyAttestationChain` (array Base64 DER). El servidor verifica todo y devuelve `installationId`.
6. Para atestación posterior, otro desafío Android y firmar `wp-attest:<purpose>:<challengeId>:<nonce>:<installationId>`. `purpose` será `wallet_attestation` o `key_attestation`.

La cadena raíz Google debe obtenerse de la documentación oficial Android, mantenerse actualizada e incluir solamente raíces explícitamente confiables. Exigir `PLAY_RECOGNIZED`, coincidencia de package y digest certificado y al menos `MEETS_DEVICE_INTEGRITY`; adaptar la política institucional si se exige `MEETS_STRONG_INTEGRITY`. La configuración `ANDROID_CERT_SHA256` utiliza el digest Base64URL/Base64 que entregue Play Integrity (no asumir formato hexadecimal).

## Protocolo iOS

1. `POST /api/v1/enrollments/challenge` `{"platform":"IOS"}`.
2. Invocar `DCAppAttestService.generateKey`, obtener `keyId` y `attestKey(keyId, clientDataHash: SHA256(UTF8(nonce)))`.
3. Enviar `challengeId`, `keyId` (Base64URL) y `attestationObject` (Base64 estándar de CBOR) a `/api/v1/enrollments/ios`.
4. Para nueva atestación, desafío iOS y `generateAssertion(keyId, clientDataHash: SHA256(UTF8(nonce)))`; enviar el objeto CBOR Base64 estándar a `/api/v1/attestations/wallet/ios` o `/api/v1/attestations/keys/ios` con `installationId` y `challengeId`.
5. El servidor valida la firma y un contador creciente; las credenciales `App Attest` no son necesariamente las mismas claves de credenciales mdoc/SD-JWT. Su vinculación adicional será una fase posterior.

`IOS_APP_ID` es `TEAM_ID.BUNDLE_ID`; usar raíz App Attest auténtica suministrada mediante ConfigMap y alternar `IOS_APP_ATTEST_PRODUCTION=false` solo en QA. Validar sobre dispositivo real. App Attest no soporta Simulator como dispositivo válido.

## Contrato para Mimoto y Diagnostics

- `GET /api/v1/installations/{id}/trust` requiere JWT con scope `wallet.trust.read`.
- `POST /api/v1/installations/{id}/revoke` requiere scope `wallet.admin`.
- `GET /api/v1/.well-known/jwks.json` publica la clave pública de firma.
- Los JWT de v0.2.0 tienen encabezado `typ` específico según Appendix D/E y una vigencia `exp`. El `sub` de Wallet Attestation usa `WALLET_CLIENT_ID` común a todas las instalaciones; la clave en `cnf.jwk` representa la instancia. **Los consumidores deben consultar el estado de instalación mediante una vinculación local con la clave** si necesitan revocación inmediata: un JWT todavía válido no implica que la instalación siga activa. No se exporta un `installationId` global dentro de la Wallet Attestation.
- No usar `installationId` o `keyId` como autenticación por sí mismos.
- La identidad del ciudadano y el cambio de dispositivo requieren autenticación del titular a través de Mimoto/IdP, no solo un nuevo enrolamiento técnico.

## Sealed Secrets y PKCS#12

Preparar en un ambiente seguro (nunca en el repositorio) tres secretos Kubernetes: `mcs-wallet-provider-runtime` (`db-password`, `signing-password`), `mcs-wallet-provider-signing` (`signing.p12`) y `mcs-wallet-provider-google` (`application-credentials.json`). Sellar cada uno mediante `kubeseal --format yaml --cert <certificado-publico-del-controlador>`. El certificado público debe pertenecer al controlador del clúster objetivo. Guardar solo los objetos SealedSecret resultantes; **este repositorio no incluye secretos ni SealedSecrets simulados**.

El PKCS#12 estará disponible en memoria para el proceso Java; Sealed Secrets **no proporciona las garantías de no exportabilidad de un HSM**. Asegurar RBAC, aislamiento de nodos, cifrado en reposo de Secrets/etcd, acceso restringido al namespace y rotación de claves. No se ha implementado aún la coexistencia automática de claves históricas: planificar `kid` antiguos en JWKS para rotar sin invalidar tokens activos.

## Pendientes para producción (bloqueantes)

- Ejecutar `mvn clean verify` con dependencias disponibles y resolver cualquier incompatibilidad de compilación; ejecutar migración y concurrencia con Oracle 19c real.
- QA físico Android e iOS, cadenas de atestación de plataformas, Google/Apple y pruebas negativas.
- Endurecer y homologar las atestaciones con OpenID4VCI 1.0 Appendices D/E y HAIP, certificados y política de confianza interinstitucional.
- Añadir validación de revocación de certificados en cadena de Android/Apple cuando esté disponible, y sincronización de trust anchors con proveedores.
- Integrar el Client Attestation PoP JWT y su validación en el servidor de autorización de Mimoto; definir audience por emisor y requisitos X.509 conforme al perfil seleccionado.
- Atestar de manera independiente las claves de credenciales. El proceso actual de enrolamiento atesta la clave de instalación; no otorgar niveles ISO 18045 sin certificación.
- Completar ciclo de cambio de dispositivo, reactivación legítima, rotación JWKS, política de privacidad, rate limiting y protección de abuso en endpoints públicos.
- Añadir manejo integral de auditoría de rechazos en transacción independiente y métricas; incorporar `trackingId/timestamp/executionTimeMs` al contrato de respuesta MTC cuando se estabilice la integración.
- Integrar `wallet-provider` con INJI Wallet, Mimoto y Diagnostics después de aprobar el protocolo definitivo; no aplicar aún el parche previo.

## Despliegue institucional MTC: configuración única por ambiente

Esta sección consolida la guía de despliegue en el propio README. **No existen archivos de aplicación por ambiente ni YAML `.example`.** `k8s/configmap.yaml` y `k8s/ingress.yaml` se conservan como plantillas genéricas sin usuarios ni URLs concretas. La misma imagen se utiliza en cualquier ambiente; Kubernetes inyecta la configuración institucional correspondiente.

### Responsabilidades y límites

| Responsable | Entrega | Ubicación |
| --- | --- | --- |
| Desarrollo | Código, `application.yml` genérico, `V1__initial.sql`, imagen versionada | Repositorio de fuentes |
| Infraestructura MTC | Conexión Oracle, URLs, namespace, ingress/TLS, identidad OIDC y parámetros no sensibles | ConfigMaps del ambiente, fuera de este repositorio |
| Operador Sealed Secrets MTC | Password Oracle, PKCS#12 y password, credenciales Google | SealedSecrets sellados para el clúster/namespace MTC |
| Seguridad MTC | Trust anchors Android/iOS, certificados, política de atestación y rotación | PKI/administración de secretos |

Se confirmó que el servicio se desplegará en Kubernetes MTC, con Oracle MTC, mientras Mimoto y Certify permanecen en AWS. Para bases con **esquema compartido**, cada microservicio debe utilizar su propia tabla de historial Flyway y prefijos de objetos. Este servicio usa `WP_FLYWAY_SCHEMA_HISTORY`, `WP_CHALLENGE`, `WP_INSTALLATION` y `WP_AUDIT`; no se debe ejecutar a mano su DDL. No habilitar `baselineOnMigrate` automáticamente.

### Flujo de entrega por Git y CI/CD MTC

1. Desarrollo valida `mvn clean install`, revisa `git status` y publica el código fuente en Git; **no necesita construir ni subir Docker desde su portátil**.
2. El pipeline MTC ejecuta Maven y pruebas, genera `target/mcs-wallet-provider.jar`, y después `docker build` con el Dockerfile incluido.
3. El pipeline publica la imagen versionada en el registry institucional y conserva su digest inmutable. La variable `IMAGE_REF` debe referenciar la imagen aprobada, preferentemente por digest.
4. Infraestructura prepara los valores del entorno objetivo por ConfigMap y SealedSecrets **externos al repositorio de fuentes**. El pipeline renderiza los manifiestos o los adapta a su herramienta institucional.
5. Kubernetes despliega la **misma imagen** en cada ambiente; Flyway migra el esquema durante el primer arranque controlado, sin ejecutar SQL manual de las tablas WP.

La versión Maven define la etiqueta lógica; el digest acredita la imagen exacta promovida entre ambientes. Nunca reconstruir una imagen distinta para la misma promoción QA/PRD.

### Contrato de variables de configuración

**Lista obligatoria para infraestructura MTC.** No colocar valores reales en el repositorio. Los elementos marcados como ConfigMap se entregan mediante `mcs-wallet-provider-config`; los marcados como SealedSecret deben existir previamente en el namespace destino.

| Variable | Qué debe proporcionar el responsable del ambiente | Procedencia | Requerida |
| --- | --- | --- | --- |
| `DB_URL` | JDBC Oracle con host, puerto y servicio del ambiente | ConfigMap | Sí |
| `DB_USER` | Usuario autorizado del esquema Oracle | ConfigMap (o Secret si la política lo exige) | Sí |
| `DB_PASSWORD` | Contraseña correspondiente a `DB_USER` | SealedSecret `mcs-wallet-provider-runtime` / `db-password` | Sí |
| `OIDC_ISSUER_URI` | Emisor OAuth2/JWT confiable para llamadas entre servicios | ConfigMap | Sí |
| `ATTESTATION_ISSUER` | Identificador público del emisor Wallet Provider | ConfigMap | Sí |
| `WALLET_CLIENT_ID` | Identificador de cliente Wallet definido institucionalmente | ConfigMap | Sí |
| `ANDROID_PACKAGE` | Application ID exacto de la variante Android MTC autorizada | ConfigMap | Sí |
| `ANDROID_CERT_SHA256` | Huella de la firma autorizada en el formato exigido por Play Integrity | ConfigMap | Sí |
| `PLAY_CLOUD_PROJECT_NUMBER` | Número del proyecto Google Cloud habilitado para Play Integrity | ConfigMap | Sí |
| `IOS_APP_ID` | Apple Team ID y Bundle ID autorizados | ConfigMap | Sí |
| `IOS_APP_ATTEST_PRODUCTION` | `true`/`false` según entorno App Attest | ConfigMap | Sí |
| `SIGNING_KEY_ID` | Identificador público de la clave institucional de atestación | ConfigMap | Sí |
| `SIGNING_KEY_ALIAS` | Alias de la clave privada dentro del PKCS#12 | ConfigMap | Sí |
| `SIGNING_KEYSTORE_PASSWORD` | Contraseña del PKCS#12 | SealedSecret `mcs-wallet-provider-runtime` / `signing-password` | Sí |
| `SIGNING_KEYSTORE_PATH` | Ruta de montaje de `signing.p12` | Deployment | Sí, predefinida |
| `ANDROID_ATTESTATION_ROOTS_PATH` | Ruta de trust anchors Android públicos | Deployment | Sí, predefinida |
| `APPLE_APP_ATTEST_ROOT_PATH` | Ruta de trust anchor Apple público | Deployment | Sí, predefinida |
| `GOOGLE_APPLICATION_CREDENTIALS` | Ruta del JSON de cuenta Google con permisos mínimos | Deployment | Sí, predefinida |
| `PORT` | Puerto HTTP dentro del pod | Valor técnico `8080` | No, tiene default |
| `LOG_FILE` | Ruta local de log, con volumen escribible | Deployment | No para Maven; sí en pod actual |

**Variables exclusivas del pipeline (no son propiedades Java):**

| Variable | Qué controla | Responsable |
| --- | --- | --- |
| `IMAGE_REF` | Imagen del registry MTC con tag/digest aprobado | CI/CD |
| `PUBLIC_HOST` | Host público HTTPS sin esquema ni ruta | Infraestructura |
| `INGRESS_CLASS` | Clase del controlador Ingress del clúster | Infraestructura |
| `TLS_SECRET_NAME` | Nombre del Secret de certificado TLS | Infraestructura |
| `MTC_NAMESPACE` | Namespace donde existen ConfigMaps y Secrets | Infraestructura/CI/CD |

**Recursos preexistentes requeridos antes de arrancar:**

| Recurso | Claves / archivos exactos | Administración |
| --- | --- | --- |
| `mcs-wallet-provider-runtime` | `db-password`, `signing-password` | SealedSecrets MTC |
| `mcs-wallet-provider-signing` | `signing.p12` | SealedSecrets MTC |
| `mcs-wallet-provider-google` | `application-credentials.json` | SealedSecrets MTC |
| `mcs-wallet-provider-android-roots` | `roots.pem` | ConfigMap MTC, confianza verificada |
| `mcs-wallet-provider-ios-roots` | `roots.pem` | ConfigMap MTC, confianza verificada |
| `mcs-wallet-provider-config` | Todas las claves no sensibles indicadas arriba | ConfigMap MTC |

No sustituir `OIDC_ISSUER_URI` por SSO IUGO sin decisión expresa de arquitectura: la autenticación de servicios y la del ciudadano son flujos distintos. La atestación de una clave de instalación no sustituye la atestación de las claves de credenciales.

**ConfigMap `mcs-wallet-provider-config`**: `DB_URL`, `DB_USER`, `OIDC_ISSUER_URI`, `ATTESTATION_ISSUER`, `WALLET_CLIENT_ID`, `ANDROID_PACKAGE`, `ANDROID_CERT_SHA256`, `PLAY_CLOUD_PROJECT_NUMBER`, `IOS_APP_ID`, `IOS_APP_ATTEST_PRODUCTION`, `SIGNING_KEY_ID`, `SIGNING_KEY_ALIAS`.

**SealedSecret → Kubernetes Secret `mcs-wallet-provider-runtime`**: claves `db-password` y `signing-password`, que llegan como `DB_PASSWORD` y `SIGNING_KEYSTORE_PASSWORD`.

**SealedSecret → Secret `mcs-wallet-provider-signing`**: archivo `signing.p12` montado en `/run/secrets/provider-signing.p12`.

**SealedSecret → Secret `mcs-wallet-provider-google`**: `application-credentials.json` montado en `/run/secrets/google/application-credentials.json` para Google ADC.

**ConfigMaps de raíces públicas**: `mcs-wallet-provider-android-roots` y `mcs-wallet-provider-ios-roots`, ambos con clave `roots.pem`, obtenidos de fuentes oficiales verificadas.

**Variables técnicas definidas por el Deployment**: `SIGNING_KEYSTORE_PATH`, `ANDROID_ATTESTATION_ROOTS_PATH`, `APPLE_APP_ATTEST_ROOT_PATH`, `LOG_FILE` y `GOOGLE_APPLICATION_CREDENTIALS`, correspondientes a las rutas de volumen montadas. `PORT` tiene valor técnico predeterminado `8080`.

`LOG_FILE` es opcional fuera de Kubernetes: si no se define, Spring Boot registra por consola y las pruebas Maven no necesitan una ruta de archivo. En el Deployment MTC, `LOG_FILE` se establece explícitamente con la ruta del volumen de logs. No se ha relajado la obligatoriedad de `DB_URL`, `DB_USER`, `DB_PASSWORD`, `OIDC_ISSUER_URI` ni de las variables criptográficas del arranque real.

El `Deployment` usa `envFrom` para el ConfigMap y `secretKeyRef` para contraseñas. Los nombres de objetos Kubernetes son un contrato genérico. Infraestructura proporciona `PUBLIC_HOST`, `INGRESS_CLASS`, `TLS_SECRET_NAME` e `IMAGE_REF` (imagen aprobada del registry MTC) durante el despliegue.

### Renderizado genérico de ConfigMap, Deployment e Ingress

Kubernetes no interpreta expresiones `${VARIABLE}` dentro de un YAML. **No aplicar directamente las plantillas `k8s/configmap.yaml`, `k8s/deployment.yaml` o `k8s/ingress.yaml` sin renderizarlas**. Infraestructura suministra las variables no sensibles desde su sistema de configuración y utiliza `envsubst` (paquete `gettext-base`). `k8s/render.sh` valida que las variables existan y genera los manifiestos en stdout, sin escribir valores en las fuentes:

```bash
bash k8s/render.sh | kubectl --namespace "$MTC_NAMESPACE" apply -f -
```

El comando requiere que infraestructura haya definido `MTC_NAMESPACE` y todas las variables listadas en el script. En MTC debe revisarse primero la salida renderizada con el procedimiento institucional de aprobación, y preferiblemente `kubectl diff`, sin publicarla en logs abiertos. **El script no genera ni expone contraseñas, PKCS#12 ni Google credentials**: los SealedSecrets se gestionan independientemente. `deployment.yaml` ya contiene su Service.

Si quedan archivos antiguos después de copiar fuentes, retirar manualmente `k8s/configmap.example.yaml`, `k8s/ingress.example.yaml` y `k8s/GUIA_DESPLIEGUE_MTC.md`. No borrar los nuevos `configmap.yaml`, `ingress.yaml`, `deployment.yaml` ni los SealedSecrets que administra MTC.

No guardar Secrets sin sellar, contraseñas, certificados privados, ficheros `.env` ni tokens en Git. El SealedSecret depende de las claves del controlador y del namespace/nombre de destino; no reutilizar un sellado de otro clúster. Sealed Secrets no equivale a un HSM ni evita por sí mismo la extracción de material disponible para el proceso.

### Secuencia de primera instalación / Flyway

**Checklist previo a autorizar el primer despliegue:**

- [ ] Pipeline conectado al repositorio y permisos de lectura del código definidos.
- [ ] JDK 17 y Maven disponibles en CI/CD; pruebas Maven satisfactorias.
- [ ] Dockerfile construye `target/mcs-wallet-provider.jar`; imagen publicada y digest registrado.
- [ ] Todas las variables obligatorias del ConfigMap proporcionadas para el ambiente destino.
- [ ] SealedSecrets sellados para **ese mismo clúster y namespace**, materializados en los tres Kubernetes Secrets requeridos.
- [ ] Archivos `roots.pem` Android/Apple verificados y ConfigMaps de confianza creados.
- [ ] Ingress HTTPS, DNS, TLS y autenticación entre servicios autorizados.
- [ ] Tráfico del pod al listener Oracle autorizado; usuario con permisos y cuota adecuados.
- [ ] Primera migración Flyway planificada en ventana controlada; aún sin objetos `WP_%` ajenos.
- [ ] `WALLET_PROVIDER_ENABLED=false` en INJI Wallet hasta pruebas de enrolamiento reales.

1. Verificar que el usuario Oracle autorizado tenga `CREATE SESSION`, `CREATE TABLE` y cuota en tablespace; comprobar que no existen objetos `WP_%` antes de la primera migración.
2. Desde el **pod Kubernetes**, validar DNS/ruta TCP hacia Oracle; una conexión desde DBeaver no demuestra conectividad del clúster.
3. Infraestructura inyecta el ConfigMap y los SealedSecrets reales; configurar un OIDC issuer funcional, PKCS#12 de desarrollo y raíces auténticas de Android/iOS antes de arrancar. Ausencia de cualquiera de estos elementos puede impedir el arranque.
4. Construir con `mvn clean verify`. Publicar la imagen versionada y realizar el primer despliegue controlado con **una réplica** mientras se comprueba la migración inicial. Después evaluar dos réplicas.
5. Verificar logs Flyway y `WP_FLYWAY_SCHEMA_HISTORY`, tres tablas, índice y restricciones. Hibernate usa `ddl-auto=validate`; no modifica el esquema.
6. Verificar liveness/readiness, HTTPS, controles 401/403, ausencia de datos personales en logs y pruebas negativas de enrolamiento.
7. Mantener `WALLET_PROVIDER_ENABLED=false` en INJI Wallet hasta QA Android/iOS. No activar el parche de diagnostics ni presentar atestaciones como homologadas.

### Consultas Oracle de verificación (solo lectura)

```sql
SELECT table_name FROM user_tables
WHERE table_name LIKE 'WP_%' ORDER BY table_name;

SELECT installed_rank, version, description, success
FROM WP_FLYWAY_SCHEMA_HISTORY ORDER BY installed_rank;

SELECT index_name, table_name FROM user_indexes
WHERE table_name LIKE 'WP_%' ORDER BY table_name, index_name;
```

### Protección de Git y verificación antes del push

`.gitignore` excluye salidas de Maven, archivos de IDE, logs, configuraciones locales, claves, PKCS#12, credenciales Google y volcados. **No es una barrera de seguridad ni elimina archivos que ya estuvieran versionados**. Antes de publicar, ejecutar `git status --short` y comprobar los archivos que realmente entrarán al commit con `git diff --cached --name-only`. Revisar los cambios con un detector de secretos institucional antes del push. Si una credencial real ya entró al historial, revocarla/rotarla y coordinar su eliminación del historial según el procedimiento de seguridad; añadirla a `.gitignore` no resuelve la exposición.

### Pendientes de homologación y operación

- La v0.2.4 falló en `PersistenceSmokeTest` por ausencia de `LOG_FILE`; la v0.2.5 corrigió este punto y el usuario confirmó `mvn install` exitoso. También se confirmó `mvn install` de la v0.2.6; **la v0.2.8 requiere ejecutar `mvn clean install` en el entorno del desarrollador y en CI/CD**, y QA con atestaciones auténticas. La generación del artefacto en este entorno no ejecuta Maven.
- Falta la migración real Oracle, configuración OIDC, llaves PKCS#12 institucionales, Google/Apple y QA físico Android/iOS.
- La atestación de instalación no acredita automáticamente las claves de credenciales mDL/SD-JWT.
- La conexión entre AWS (Mimoto/Certify) y MTC deberá usar APIs autenticadas; no acceso Oracle cruzado directo.
- El bloqueo de SSO IUGO/FEE, si persiste, afecta la emisión/descarga E2E, pero no impide las pruebas aisladas de Wallet Provider.
