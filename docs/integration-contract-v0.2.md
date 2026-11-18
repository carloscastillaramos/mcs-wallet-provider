# Contrato preliminar de integración — Provider 0.2.8

## Funciones principales

- Android: una clave P-256 no exportable de instalación, Android Key Attestation y Play Integrity Standard enlazados al mismo desafío y material público.
- iOS: App Attest con clave de instancia y assertions monotónicas. La clave App Attest no reemplaza las claves de credenciales.
- Mimoto: validar Wallet Attestation y demostración de posesión adicional (OAuth Client Attestation PoP) antes de autorizar flujos de emisión; la integración todavía **no está implementada**.
- Diagnostics: validar un token o estado de instalación para autorizar la clave pública de diagnóstico y el intercambio cifrado; la integración de Wallet continúa en standby.

## Tabla de endpoints

| Operación | URI | Autorización |
|---|---|---|
| Desafío | `POST /api/v1/enrollments/challenge` | Público; proteger con gateway/rate limit |
| Enrolar Android | `POST /api/v1/enrollments/android` | Evidencia Google + cadena X.509 + PoP |
| Enrolar iOS | `POST /api/v1/enrollments/ios` | Evidencia App Attest X.509 |
| Wallet Attestation Android | `POST /api/v1/attestations/wallet/android` | PoP + desafío Android |
| Wallet Attestation iOS | `POST /api/v1/attestations/wallet/ios` | App Attest assertion + contador |
| Key Attestation Android | `POST /api/v1/attestations/keys/android` | PoP + desafío Android; **solo clave instalación** |
| Key Attestation iOS | `POST /api/v1/attestations/keys/ios` | App Attest assertion + contador; **solo clave instancia** |
| Key Attestation de credencial Android | `POST /api/v1/attestations/credential-keys/android` | Instalación ACTIVE + desafío + firma de instalación + firma de clave de credencial + cadena Android Key Attestation de esa clave + `issuerNonce`; **aún sin cliente móvil** |
| Estado confianza | `GET /api/v1/installations/{id}/trust` | Scope `wallet.trust.read` |
| Revocar | `POST /api/v1/installations/{id}/revoke` | Scope `wallet.admin` |
| JWKS | `GET /api/v1/.well-known/jwks.json` | Público |

## Formatos JOSE

- Wallet Attestation: `typ=oauth-client-attestation+jwt`, `iss` Wallet Provider, `sub` tipo común configurado en `WALLET_CLIENT_ID`, `cnf.jwk` clave de instalación, `nbf`, `exp` y `wallet_name`.
- Key Attestation: `typ=key-attestation+jwt`, `iss`, `iat`, `exp`, `attested_keys`. Las rutas `keys/*` atestan la clave de instalación; `credential-keys/android` atesta la clave de credencial validada e incorpora `nonce` del emisor.
- La firma de Key Attestation requiere una cadena de certificado institucional en el PKCS#12; `x5c` publica la cadena salvo el certificado raíz autofirmado. Una CA institucional confiable y su configuración en Certify siguen siendo necesarias para interoperabilidad. Una cadena sintética de QA no acredita HAIP.
- `key_storage`/`user_authentication` ISO 18045 intencionalmente omitidos: el nivel de certificación no puede inferirse de TEE/StrongBox/App Attest.

## Seguridad y privacidad

Los desafíos expiran a los 180 segundos y son de un solo uso. El nivel de integridad debe validarse remotamente y las pruebas de posesión deben incluir el desafío. No trasladar datos personales del titular a atestaciones. La identidad del ciudadano pertenece a Mimoto. La revocación se refleja en consultas de estado, pero un JWT emitido anteriormente solo expira al finalizar su ventana de validez. Para clientes con revocación inmediata, requerir introspección o validación complementaria.

## Pruebas pendientes

- Maven/JDK 17 de la v0.2.8, comprobación real de certificados Android y Apple y escenarios negativos.
- Validación de cadenas de firma institucional, transición de `kid` y root rotation.
- OAuth Client Attestation PoP en Mimoto; emisión efectiva con Certify, presentación en Verifier y pruebas SD-JWT VC / mdoc.
- Registro de claves de credenciales y garantías por clave (no solo por instalación).
- Configuración productiva de Google Play Console/Cloud y Apple Developer Team.
