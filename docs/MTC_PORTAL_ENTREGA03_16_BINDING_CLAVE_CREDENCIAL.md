# MTC · Entrega 03.16 — Vínculo de clave de emisión a instalación acreditada

**Versión:** 03.16 (24/11/2026)  
**Componentes:** `mcs-wallet-provider`, PostgreSQL `wallet_provider`, futuro `inji-certify`

## Problema resuelto

La atestación de clave no conservaba un registro consultable del enlace entre
la clave **realmente probada y atestada por hardware**, la instalación cuyos
secretos verificó Provider y el `c_nonce` generado por el emisor. Este
registro se necesita para permitir una comprobación de estado vigente en Certify.

## Comprobaciones y persistencia

1. Provider obtiene `installationId` mediante su sesión de enrolamiento y
   valida la instalación existente y activa.
2. Verifica la firma PoP de la clave de instalación sobre la solicitud, la
   firma de la clave de credencial y la evidencia de atestación hardware.
3. Evalúa la política de acreditación de titular vigente.
4. Firma `key_attestation` con el `c_nonce` suministrado por Certify.
5. En la misma transacción escribe `wp_credential_key_binding`: thumbprint
   SHA-256 de JWK P-256, hash SHA-256 de `c_nonce`, instalación, instante de
   emisión/vencimiento. No registra DNI ni nonce en claro.
6. `activeAccreditedBinding` vuelve a consultar instalación, titular y sesión
   biométrica COMPLETED con estado actual; no da por vigente una atestación
   solo por tener firma válida.

## Antirreplay y revocación

Constraint único `(credential_key_thumbprint, issuer_nonce_sha256)`; rechazo
de mezcla de claves entre instalaciones; TTL igual o más estricto que el JWT
de atestación. Revocar una instalación o bloquear el vínculo de identidad
invalida las futuras autorizaciones online, sin depender del vencimiento
pendiente de una atestación. La persistencia se confirma o revierte con
la transacción completa.

## Obligaciones aún pendientes

- Agregar endpoint Certify-M2M en Provider con scope/client_id exclusivos.
- Certify debe verificar primero firma del proof JWT OpenID4VCI, audiencia,
  `c_nonce` y vínculo del JWK del proof con su `key_attestation` firmada.
  Solo la clave obtenida de dicho proof será consultada.
- Asegurar la cobertura de los tres endpoints de emisión y canales adicionales.
- Aprobar alcance de política para integraciones externas, pruebas PostgreSQL
  Flyway V1–V5 y dispositivo Android físico, incluyendo revocación y concurrencia.
- Rechazar siempre errores de red/BD cuando la guarda final esté habilitada.

## Protección de despliegue

`WALLET_IDENTITY_CREDENTIAL_BINDING_ENABLED=false` (default).
Solo puede activarse junto con
`WALLET_IDENTITY_ENABLED=true` y `WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED=true`.
No configurar activos hasta pruebas E2E, Cognito y Certify.
