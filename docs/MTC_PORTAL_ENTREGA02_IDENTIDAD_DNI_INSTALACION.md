# MTC-BD-ESP-ENR-002 · Entrega 02 · Núcleo de acreditación DNI–instalación

## Alcance entregado

Implementación interna transaccional y protección criptográfica de la identidad acreditada en Provider. Se trabaja sobre las tablas V3/V4 ya validadas con SQL PostgreSQL 16 aislado. No se incluyen migraciones nuevas.

### Precondiciones obligatorias para integrar

1. El enrolamiento criptográfico Android/iOS ya debe haber producido una instalación **ACTIVE** y una prueba reciente de posesión de su clave. El usuario sin acreditar sigue bloqueado cuando se implemente el gate en Wallet.
2. MiMoto/RENIEC debe entregar a un adaptador **backend a backend autenticado** la identidad acreditada: DNI de 8 dígitos, emisor, sesión externa única y momento de autenticación, junto con correlación verificable de sesión, nonce, propósito `HOLDER_ENROLLMENT` e instalación.
3. Un adaptador implementará `TrustedReniecEvidenceVerifier`, validando la autenticidad de la evidencia **antes** de devolver `VerifiedIdentity`. Este contrato aún NO existe en las fuentes. Nunca confiar en parámetros del móvil ni en una respuesta booleana sin evidencia.
4. Al habilitar las APIs, requerir prueba de posesión por plataforma y permisos M2M con auditoría. Estas rutas **no existen** en entrega 02.

### Comportamiento del servicio

- `beginForProvenInstallation(installationId)` (servicio interno, **no HTTP**): comprueba instalación activa sin titular, bloquea fila para evitar carreras, expira sesiones vencidas, rechaza otra pendiente y crea nonce aleatorio de 32 bytes/TTL de 600 segundos (almacena hash, no nonce claro).
- `completeFromTrustedEvidence(sessionId, nonce, evidence)` (interno): bloquea instalación y sesión; exige nonce, vigencia, estado PENDING y el resultado del adaptador de evidencia. Verifica issuer `RENIEC_ID_PERU`, DNI, instalación, sesión, nonce, edad de la autenticación y referencia externa; crea/reutiliza `wp_holder` cifrado/HMAC, completa la sesión, crea `wp_installation_holder` y asocia permisos `wp_verifier_grant` importados para el DNI. Toda la escritura es transaccional y la sesión no puede consumirse dos veces.
- **No concede** derechos de verificación por sí solo: el permiso institucional sigue requiriendo vínculo `wp_verifier_installation` y comprobación online de Provider. No sustituye la autenticación por credencial de emisión.

### Protección de DNI

- HMAC-SHA-256 sobre el DNI con clave de 256 bits independiente y prefijo de dominio; conserva ceros iniciales.
- AES-256-GCM con IV aleatorio, AAD de propósito, etiqueta de 128 bits; no se almacena DNI en claro.
- Las claves se reciben desde secretos inyectados por ambiente. La falta de claves, el mismo material para ambas o la falta del adaptador impiden arrancar **si** el servicio está habilitado.
- La versión de clave se registra en BD. No se soporta rotación transparente en este lote. El cambio de clave HMAC sin migración rompería la comparación de padrones.

### Validaciones y pendientes

Se incorporan JUnit para cifrado autenticado, unicidad/determinismo del HMAC, rechazo de entradas inválidas, claves mal configuradas y rechazo de solicitudes incompletas. La compilación Maven y los tests deberán ejecutarse en el repositorio del usuario. La prueba de migraciones V1–V4 con PostgreSQL aislado ya es satisfactoria, pero **no prueba este servicio Java ni Flyway real**.

Pendientes de Entrega 03: contrato y adaptador M2M MiMoto/RENIEC, pruebas reales de evidencia, endpoints protegidos de inicio/estado/consumo, Diagnostics, gate de INJI Wallet. El portal Angular y los controles de Verify se desarrollarán en lotes separados.
