# MTC · Entrega 03.17 — API de autorización Certify–Provider

**Versión:** 03.17  | **Fecha:** 24/11/2026  | **Estado:** Implementación Provider, pendiente Maven/E2E

## Objetivo y contrato

`POST /api/v1/internal/identity/certify/authorize-issuance`  
`Authorization: Bearer <access_token_Cognito_client_credentials>`  
`Content-Type: application/json`  
`{ "credentialKeyThumbprint": "<RFC7638_de_la_clave_verificada>", "issuerNonce": "<c_nonce_de_la_sesion_emisora>" }`

El servidor Provider NO admite un `installationId` enviado por Wallet. El thumbprint
es RFC 7638 del **JWK P-256 validado por Certify**, y el nonce viene de la sesión
del propio emisor. Certify debe comprobar previamente firma de proof, `aud`, nonce,
`key_attestation` firmada y vínculo criptográfico entre ambas claves. Provider
verifica la asociación de esa pareja con el registro V5, su vencimiento y el
estado actual de la instalación/sesión/titular. Sin coincidencia ⇒ DENEGAR.

**Éxito:** `204` sin cuerpo, `Cache-Control: no-store`.  
**Binding no vigente:** `403`.  
**Error de BD, identidad, credenciales M2M, timeout u otra respuesta:** NO EMITIR.
Nunca convertir un 500 o timeout en autorización por defecto.

## Seguridad M2M

Scope Cognito **exclusivo** `mtc-wallet-provider/wallet.issuance.certify`;
validación JWT de Cognito, `token_use=access`, `client_id` en allowlist exclusiva
`WALLET_IDENTITY_CERTIFY_M2M_CLIENT_IDS`, banderas habilitadas. `wallet.admin` y
`wallet.identity.mimoto` no autorizan. Sin Cognito: SIEMPRE denegar. Exponer
solo desde red de servicios y con HTTPS/mTLS cuando esté disponible. Ningún
endpoint de uso ciudadano utiliza este scope.

## Persistencia y compatibilidad

Reutiliza migración V5 (sin migraciones nuevas). Corrección explícita de esquema:
consultas de `CredentialKeyBindingRegistry` ahora apuntan a `wallet_provider.*`
sin asumir el search_path de JDBC. No persiste DNI ni nonce en claro. No
modifica contrato móvil, emisión ni verificación web existentes.

## Limitaciones pendientes / secuencia

1. Validar Maven en Ubuntu y migración PostgreSQL V1–V5 con rollback aislado.
2. Implementar cliente OAuth2/HTTPS en `inji-certify`, que solicite esta autorización
   **después** de comprobar el proof OpenID4VCI y **antes** de emitir mDL o SD-JWT.
3. Asegurar la vinculación de `c_nonce` también en los paths vd11/vd12, verificar
   exhaustivamente el formato de proof, Key Attestation y todos los endpoints.
4. Pruebas E2E reales: credencial válida, clave ajena, cambio de nonce, estado revocado,
   sesión vencida, doble petición, errores de red/BD y retorno de ID Perú.
5. Homologar y aprovisionar el cliente Cognito Certify; mantener flags en `false`
   hasta completar validación institucional.
