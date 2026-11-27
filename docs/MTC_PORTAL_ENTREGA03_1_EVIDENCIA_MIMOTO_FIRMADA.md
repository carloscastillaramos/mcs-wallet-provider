# MTC-BD-ESP-ENR-003.1 · Verificación de evidencia firmada MiMoto/RENIEC

## Alcance

Esta entrega implementa **solo en Provider** el adaptador `SignedMimotoReniecEvidenceVerifier` del contrato `TrustedReniecEvidenceVerifier` introducido en Entrega 02. Sustituye el bean ausente (al habilitar el feature flag) por un validador JWT con certificado público MiMoto fijado; **no crea endpoints HTTP, no firma evidencias en MiMoto y no habilita el feature flag**. No altera V1–V4, emisión, Wallet, Verify ni Diagnostics.

## Contrato MTC-HOLDER-EVIDENCE-1, versión propuesta

Evidencia JWT **JWS RS256/ES256**, `typ=mtc-holder-identity+jwt`, firmada por **MiMoto con clave propia de firma** y verificada mediante certificado público X.509 provisionado de forma segura en Provider. Nunca reutilizar la clave de firma de wallet-provider ni confiar en certificados o JWK incluidos por el emisor en el propio encabezado.

Claims obligatorios:

| Campo | Significado |
|---|---|
| `iss` | Identificador MiMoto exacto configurado en Provider |
| `aud` | Identificador exacto del consumidor Provider; una única audiencia |
| `sub` | `MIMOTO_RENIEC_SESSION:<reniec_session_id>`; referencia opaca, **no contiene DNI** |
| `jti` | ID único de evidencia, 16–128 caracteres permitidos |
| `iat`, `nbf`, `exp` | Emisión, inicio de validez, caducidad (máximo 120 segundos de vigencia) |
| `purpose` | `HOLDER_ENROLLMENT` exclusivamente |
| `outcome` | `SUCCESS` exclusivamente, luego de terminar flujo RENIEC |
| `authority` | `RENIEC_ID_PERU` |
| `dni` | DNI acreditado de 8 dígitos (incluidos ceros iniciales) |
| `auth_time` | Momento UTC Unix de confirmación biométrica efectiva, no más de 5 minutos de antigüedad |
| `reniec_session_id` | Identificador único comprobado en backend MiMoto, 16–128 caracteres |
| `identity_session_id` | UUID de sesión Provider recibido y autenticado por el backend MiMoto |
| `installation_id` | UUID de instalación Provider, validado criptográficamente en el inicio |
| `nonce` | Desafío Provider sin alteraciones; correlación exacta de sesión |

La evidencia debe generarse **únicamente** cuando MiMoto haya corroborado el estado RENIEC exitoso y el DNI devuelto por RENIEC, y haya validado la relación entre esa sesión RENIEC, la clave de instalación y el `identity_session_id`/`nonce` recibido. **El estado `SUCCESS` aislado del móvil o una coincidencia de DNI NO es suficiente**.

Provider compara en tiempo de verificación el identificador de sesión, instalación y nonce contra sus propios datos bajo transacción. Se exige vigencia temporal, firma del certificado fijado y contexto `HOLDER_ENROLLMENT` distinto del flujo de emisión habitual. El servicio existente consume la sesión una sola vez y usa `external_ref` único en PostgreSQL. Todas las rutas nuevas deberán tener pruebas de posesión de clave/M2M antes de habilitarse.

## Variables nuevas del archivo `application.yml`

| Variable | Predeterminado | Uso |
|---|---|---|
| `WALLET_IDENTITY_MIMOTO_EVIDENCE_ISSUER` | Vacío | `iss` esperado en evidencia MiMoto |
| `WALLET_IDENTITY_MIMOTO_EVIDENCE_AUDIENCE` | Vacío | Audiencia exclusiva Provider |
| `WALLET_IDENTITY_MIMOTO_SIGNER_CERT_PATH` | Vacío | Ruta local al certificado público X.509 de la nueva clave MiMoto |

Las tres son **obligatorias si `WALLET_IDENTITY_ENABLED=true`**. Si falta una, el servicio no arranca. El certificado no es secreto, pero su origen y rotación requieren controles de infraestructura y validación de cadena/pinning organizacional. No introducir DNI/JWT en logs o documentación. Claves privadas MiMoto gestionadas con Secret Manager/HSM según política institucional, nunca en Git.

## Pruebas y límites

`SignedMimotoReniecEvidenceVerifierTest`: pruebas RS256 con claves efímeras de laboratorio; cubren firma válida, clave ajena, propósito incorrecto, emisor/audiencia, nonce, instalación, sesión, DNI, caducidad, antigüedad biométrica, respuesta fallida y JSON enviado por móvil. No constituye integración real RENIEC/MiMoto.

**Pendiente antes de activar:** el emisor JWT correspondiente en MiMoto, endpoint autenticado backend–backend o canal seguro equivalente, correlación con atestación y PoP de instalación, controles de replay cruzado, pruebas E2E y despliegue del certificado + claves; después publicar las rutas protegidas Provider y conectar INJI Wallet. No tocar el flujo de emisión que solicita DNI por cada credencial ni el Verify web existente.

## Correccion de pruebas — Entrega 03.1.1 (25/11/2026)

La prueba inicial `rejectsDniAndSubjectMismatch` estaba basada en una asociacion incorrecta entre `sub` y DNI. El campo `sub` es la referencia opaca `MIMOTO_RENIEC_SESSION:<reniec_session_id>`, independiente del DNI acreditado.

- Un DNI diferente y valido **firmado por MiMoto confiable** puede ser legitimo; Provider no tiene un DNI preexistente con el cual contrastarlo en la primera acreditacion.
- El contrato rechaza `sub` distinto de `reniec_session_id`, `reniec_session_id` inconsistente con `sub` y alteracion del DNI **sin volver a firmar** (firma invalida).
- MiMoto sigue obligado a obtener `dni` del resultado confiable de RENIEC, no de un parametro arbitrario de Wallet. Esto se validara con pruebas de integracion del futuro emisor de evidencia.
- Sin cambios en el codigo productivo, V1-V4, `application.yml` o variables de ambiente.

