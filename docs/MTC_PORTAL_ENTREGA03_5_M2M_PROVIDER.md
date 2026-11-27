# MTC Portal — Entrega 03.5: endpoints M2M Provider

**Fecha:** 25/11/2026. **Estado:** listo para validar en local; SIN habilitar QA/PRD.

## Alcance realizado

Se agregan dos endpoints POST exclusivamente backend-to-backend para MiMoto:

- `/api/v1/internal/identity/mimoto/verify-binding`: entrada `identitySessionId` (UUID), `installationId`, `nonce`, `keyThumbprint`. Respuesta HTTP 204. Usa `HolderInstallationBindingVerifier` de la Entrega 03.4. No consume la sesion.
- `/api/v1/internal/identity/mimoto/complete`: entrada anterior más `signedEvidence` (JWT firmado por MiMoto). Respuesta HTTP 204. Valida de nuevo el vínculo; dentro de `IdentityAccreditationService` verifica la evidencia y completa la transacción de asociación. Un segundo consumo resulta rechazado.

## Autorización (obligatoria)

Las dos rutas requieren:

1. `WALLET_COGNITO_ENABLED=true` y JWT Access firmado/verificado por Cognito mediante la configuración existente.
2. Scope exacto `mtc-wallet-provider/wallet.identity.mimoto` registrado como Resource Server scope Cognito.
3. `client_id` incluido en `WALLET_IDENTITY_MIMOTO_M2M_CLIENT_IDS` (lista privada de app-client MiMoto).
4. `WALLET_IDENTITY_ENABLED=true` y `WALLET_IDENTITY_MIMOTO_M2M_ENABLED=true` para registrar y autorizar la API.
5. Canal privado permitido solo desde MiMoto; TLS/mTLS/políticas de red deben implementarse en Infraestructura.

**Fallo cerrado:** nunca se autoriza con Cognito deshabilitado, un token de identidad, un scope de `wallet.admin` ni un JWT de cliente desconocido.

**El backend MiMoto debe usar `MtcWalletSessionGate.authorize` y `requireBoundHolderSession` antes de llamar a estas APIs**, y debe consultar el estado de la sesión RENIEC en Redis. Nunca enviar estos endpoints directamente a la aplicación móvil. No se devuelve DNI ni JWT en las respuestas.

## Lo que sigue pendiente

- Conectar cliente HTTP MiMoto por OAuth2 `client_credentials` a Provider, incluyendo timeouts, errores, reintentos controlados y obtención de token Cognito.
- Consumir marca de éxito RENIEC de forma única, firmar evidencia y llamar a `/complete` desde MiMoto.
- Implementar endpoints wallet para iniciar sesión de acreditación con PoP y consultar estado.
- Activar el bloqueo total de Wallet únicamente tras pruebas E2E.
- Probar seguridad JWT real, gateway, Redis compartido, TLS, Flyway y PostgreSQL aislado.

La aplicación actual sigue solicitando DNI por credencial y Verify web no cambia.
