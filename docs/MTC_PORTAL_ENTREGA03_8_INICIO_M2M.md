# Contrato 03.8 — Inicio de sesión de acreditación

Secuencia de uso futuro: Wallet atestada + PoP -> MiMoto obtiene thumbprint -> MiMoto solicita Provider /start con token M2M -> Provider valida clave y crea sesión -> MiMoto inicia RENIEC dedicado -> MiMoto concluye con /verify-binding y /complete. El endpoint móvil específico está **pendiente** de implementar.

POST /api/v1/internal/identity/mimoto/start

Request JSON: `{ "installationId": "UUID", "keyThumbprint": "base64url(43)" }`

Response HTTP 201: `{ "sessionId": "UUID", "nonce": "base64url(43)", "expiresAt": "ISO-8601 UTC" }`

Guardas: Cognito JWT de acceso exclusivo MiMoto, scope y client_id allowlisted; identidad/M2M habilitados, clave coincide con registro de Provider, instalación ACTIVE sin titular asociado, transacción de inicio con bloqueo de instalación y no duplicidad de sesión activa. Sin DNI en request/response.

La validación de la firma de MiMoto, estado RENIEC y asociación de titular se realiza después, en /complete. No activar para usuarios sin pruebas E2E.
