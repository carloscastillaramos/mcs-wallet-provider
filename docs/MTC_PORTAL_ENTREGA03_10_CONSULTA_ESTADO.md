# MTC — Entrega 03.10 — Consulta segura de acreditación

Fecha: 24/11/2026. Estado: preparado para pruebas Maven, **no desplegar en AWS todavía**.

## Objetivo

Permitir que MiMoto consulte a Provider para conocer si una instalación ya tiene titular acreditado, sin transmitir DNI en claro ni admitir una decisión de la Wallet.

## Contrato M2M

`POST /api/v1/internal/identity/mimoto/status` (HTTPS privado)

Solicitud JSON: `{"installationId":"<UUID>","keyThumbprint":"<thumbprint JWK P-256>"}`. El thumbprint debe proceder del control `MtcWalletSessionGate.authorize` y jamás de un campo no autenticado de la app. El controlador sólo se habilita con flags de identidad/M2M y la misma autenticación Cognito con scope y client_id existente para las otras rutas M2M.

Respuesta 200 JSON: `{"state":"ACCREDITED","walletAccessAllowed":true,"checkedAt":"2026-11-24T23:00:00Z"}` (fecha ejemplificativa). Header: `Cache-Control: no-store`. Estados: `ACCREDITED`, `IDENTITY_REQUIRED`, `IDENTITY_PENDING`, `IDENTITY_BLOCKED`, `INSTALLATION_INACTIVE`.

Solo `ACCREDITED` produce `walletAccessAllowed=true`. En todos los otros casos, **denegar acceso** y no interpretar timeout o HTTP no-200 como acreditación. No es token de autorización ni sustituye las comprobaciones obligatorias en otros endpoints.

## Comprobaciones

- Clave real vinculada a la instalación mediante thumbprint JWK P-256.
- Instalación `ACTIVE`.
- Vínculo de titular `ACTIVE`.
- Sesión de acreditación asociada `COMPLETED`, con `purpose=HOLDER_ENROLLMENT`, `consumed_at` y resumen de evidencia de 32 bytes.
- Estado `IDENTITY_PENDING` solo cuando exista una sesión pendiente sin vencer.
- Instalación inexistente, thumbprint ajeno o inconsistencias: fail-closed.

## Compatibilidad

No cambia rutas RENIEC de emisión, pregunta DNI por credencial, verificación web ni migraciones V1–V4. No añade variables; README de ambos componentes actualizado. **Pendiente**: ruta MiMoto autenticada para la consulta desde Wallet y pruebas en dispositivos reales. Datos de laboratorio o simulación no equivalen a acreditación RENIEC.
