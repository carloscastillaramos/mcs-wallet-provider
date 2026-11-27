# MTC-BD-ESP-ENR-001 | Entrega de desarrollo 01 | 24/11/2026

## Decisiones funcionales vigentes

- **Toda INJI Wallet** permanece bloqueada hasta acreditar por ID Perú al titular de la instalación; solo onboarding/reintento/ayuda indispensable antes de completar.
- Acreditación inicial una vez por instalación/vínculo vigente. No sustituye el DNI ni la autenticación que actualmente solicita **cada emisión** de credencial.
- Portal administrativo **exclusivo del MTC**, frontend **Angular**, roles `SUPER_ADMIN` y `MESA_DE_PARTES` (N usuarios). **No hay cuentas de entidades externas**. Las entidades remiten padrones al MTC.
- Verificación web actual se mantiene, sin acreditación institucional del verificador; la verificación móvil institucional requiere autorización de Provider, titular acreditado e instalación activa. El canal móvil debe autenticarse criptográficamente, no mediante un tag confiado al cliente.
- Una baja institucional no revoca toda la Wallet; la revocación global de instalación queda reservada al MTC.

## Implementado en la entrega 01

- Flyway `V3__holder_and_mtc_operators.sql`: estructuras `wp_holder`, `wp_identity_session`, `wp_installation_holder`, `wp_entity`, `wp_mtc_operator`.
- Flyway `V4__verifier_grants_and_imports.sql`: estructuras `wp_verifier_grant`, `wp_verifier_installation`, `wp_import_batch`, `wp_import_row`, `wp_admin_audit`.
- `InstitutionalAuthorizationService`: consulta de autorización **solo interna**, sin publicar endpoint ni alterar la política de seguridad HTTP; responde `ALLOW` únicamente si existe una identidad acreditada, instalación y entidad activas, permiso vigente y vínculo activo. No acepta DNI del solicitante. Excepciones de base no se convierten en permiso positivo.
- Pruebas JUnit/H2 de consultas de autorización. Estas no reemplazan las pruebas PostgreSQL reales en laboratorio aislado.

## No implementado todavía (importante)

- No se ha integrado MiMoto/RENIEC con Provider; no existe aún una evidencia técnica nueva ni se ha alterado el flujo actual de emisión.
- No se ha creado API de identidad, vínculo DNI–instalación, importación o revocación administrativa. La estructura `wp_holder` **solo podrá recibir DNI cifrados/HMAC válidos** mediante servicios futuros, nunca insertando DNI en claro.
- No se han habilitado autorizaciones móviles ni nuevos permisos en Verify. **La mera existencia de las tablas no habilita el rol verificador**.
- No se ha creado portal Angular ni autenticación de sus operadores con Cognito. `wp_mtc_operator` no se auto-puebla; el bootstrap del primer SUPER_ADMIN será un procedimiento protegido posterior, con auditoría.
- No se ha implementado creación automática de vínculos de autorizaciones, límites de equipos o revocación de vínculos en transacciones. El evaluador interno denegará mientras no exista el vínculo acreditado y aprobado.
- No se han ejecutado migraciones en QA/PRD; revisar el orden de despliegue y realizar respaldo antes de Flyway.

## Contratos para etapas siguientes (propuesta, no API vigente)

1. `POST /api/v1/identity-sessions`: instalación autenticada por prueba de posesión fresca; crear sesión `HOLDER_ENROLLMENT` vinculada a installationId y nonce.
2. MiMoto/RENIEC → Provider M2M: correlacionar sesión, contexto y resultado biométrico; verificar DNI recibido por canal confiable antes de crear `wp_holder` y `wp_installation_holder`; consumir evidencia una vez; nunca permitir reasignar instalación.
3. `GET /api/v1/me/capabilities`: titular acreditado, instalación activa, permisos institucionales; no reemplaza la autorización del backend.
4. Verify móvil → Provider: solicitud autenticada con proof de instalación + M2M, respuesta `ALLOW`/`DENY` por entidad y operación; control de ownership en Verify; mantener el flujo WEB separado.
5. `GET/POST/PATCH /api/v1/admin/*`: admin MTC por `issuer`+`sub`, permisos de rol, ámbito del lote y operación, auditoría; BFF/PKCE acorde al contrato Cognito confirmado.

## Datos y controles de seguridad

- El DNI ingresado es solo referencia. La identidad se obtiene del resultado verificado ID Perú/MiMoto. Para búsquedas exactas usar HMAC con clave independiente del cifrado; **no usar SHA-256 simple** ni escribir valores en log.
- El material de cifrado/HMAC se provisionará en KMS/Secrets Manager; las variables concretas se añadirán al README en la etapa en que se implemente el servicio consumidor, sin inventar valores hoy.
- Sesiones: nonce 32 bytes aleatorios, expiración, consumo único, replay bloqueado. Concurrencia y matching titular–dispositivo deben comprobarse bajo transacción con bloqueo.
- En la primera etapa se implementa **base de datos e infraestructura interna**; no se altera `SecurityConfig`, `ProviderController`, `EnrollmentService`, `App.tsx` ni componentes MiMoto/Verify/Diagnostics.

## Criterios para el siguiente lote

- Validar primero V3/V4 en PostgreSQL aislado con las guardas existentes `LabPostgresGuard` (nunca en QA/PRD compartidos).
- Cerrar el contrato de resultado de identidad de MiMoto/RENIEC con evidencia vinculada; entonces implementar el servicio de acreditación y el gate de Wallet.
- Configurar autenticación Cognito para operadores **MTC** (cliente humano independiente del M2M) cuando Infraestructura entregue parámetros; no exponer `wallet.admin` al navegador.
