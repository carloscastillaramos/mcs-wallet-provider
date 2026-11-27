# MTC · Entrega 03.21 — Preflight QA Certify → Provider

**Versión:** 03.21  
**Fecha:** 24/11/2026  
**Estado:** validación local de contratos y script QA opcional. No habilitar en PRD.

## 1. Alcance y límites

Prueba el perímetro de autorización M2M **sin generar credenciales**, sin usar DNI,
sin escribir directamente en PostgreSQL y sin llamar al emisor RENIEC/ID Perú.
El comando local no necesita red. El comando `--qa` requiere un ambiente QA
aprobado y configura explícitamente los dos hosts: Provider y Cognito.

Este laboratorio **no demuestra** que una billetera real haya acreditado a su
titular ni que mDL/SD-JWT se emitan correctamente: lo debe completar la prueba E2E.
En el modo QA, únicamente el intercambio `client_credentials` crea un token de
servicio temporal y se ejecutan `POST` de **consulta autorizadora** de Provider,
que no insertan ni modifican datos de negocio. No ejecutar contra PRD.

## 2. Dependencias de configuración en QA

### Wallet Provider

| Variable | Valor requerido para este preflight en QA |
|---|---|
| `WALLET_IDENTITY_ENABLED` | `true` |
| `WALLET_IDENTITY_CREDENTIAL_BINDING_ENABLED` | `true` |
| `WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED` | `true` |
| `WALLET_IDENTITY_CERTIFY_M2M_ENABLED` | `true` |
| `WALLET_IDENTITY_CERTIFY_M2M_CLIENT_IDS` | client_id de Certify QA, nunca el de MiMoto |
| `WALLET_COGNITO_ENABLED` | `true` |
| `WALLET_COGNITO_ISSUER_URI` | issuer HTTPS real del User Pool de **QA** |

Además, migraciones V1–V5 aplicadas, esquema `wallet_provider`, JWKS
accesible por el servicio, configuración criptográfica válida y TLS confiable.
El permiso registrado en Cognito debe ser **exactamente**
`mtc-wallet-provider/wallet.issuance.certify`. La aplicación Certify debe recibir
ese permiso por `client_credentials` y el cliente MiMoto no debe recibirlo.

### Certify

| Variable | Valor para homologación QA |
|---|---|
| `MTC_CERTIFY_PROVIDER_ISSUANCE_REQUIRED` | `false` para preflight de API; `true` solo durante la prueba integral autorizada |
| `MTC_KEY_ATTESTATION_VALIDATION_ENABLED` | `true` antes de activar la obligatoriedad en Certify |
| `MTC_KEY_ATTESTATION_REQUIRED` | `true` antes de activar la obligatoriedad en Certify |
| `MTC_CERTIFY_PROVIDER_BASE_URL` | origen HTTPS QA de Provider |
| `MTC_CERTIFY_PROVIDER_TOKEN_URL` | URL Cognito QA `/oauth2/token` |
| `MTC_CERTIFY_PROVIDER_CLIENT_ID` | cliente exclusivo Certify QA |
| `MTC_CERTIFY_PROVIDER_CLIENT_SECRET` | secreto de QA, en almacén institucional |
| `MTC_CERTIFY_PROVIDER_SCOPE` | `mtc-wallet-provider/wallet.issuance.certify` |

**Orden seguro:** preparar QA PG/Cognito → activar las dependencias Provider
solo en QA → ejecutar preflight de autorización → activar en Certify QA para
pruebas de emisión reales. Revertir Certify primero, Provider después.
Ninguna de estas activaciones forma parte del script.

## 3. Pruebas locales (sin red)

Desde la raíz del repositorio:

```bash
python3 -m unittest discover \
  -s mcs-wallet-provider/tools/tests \
  -p test_mtc_certify_m2m_preflight.py -v

python3 mcs-wallet-provider/tools/mtc_certify_m2m_preflight.py --offline
```

Esperado: **11 unit tests** y **4 comprobaciones estáticas**. Estas últimas
verifican contratos en el checkout actual, sin ejecutar Java/Spring.

## 4. Prueba QA opcional — no ejecutar hasta habilitación de infraestructura

**Primero verificar fuera del script** que el DNS, el TLS y los ingress apuntan a
QA, nunca a producción. Las siguientes variables pertenecen **solo al ejecutor
del laboratorio**, no a la aplicación Spring. No se guardan en el ZIP:

```bash
# Ejemplo ilustrativo de valores; reemplazar por configuración QA autorizada.
export MTC_E321_QA_CONFIRM='CONFIRMO_QA_NO_PRODUCCION'
export MTC_E321_QA_PROVIDER_URL='https://provider-qa.ejemplo.gob.pe'
export MTC_E321_APPROVED_PROVIDER_HOST='provider-qa.ejemplo.gob.pe'
export MTC_E321_QA_COGNITO_TOKEN_URL='https://auth-qa.ejemplo.gob.pe/oauth2/token'
export MTC_E321_APPROVED_COGNITO_HOST='auth-qa.ejemplo.gob.pe'
export MTC_E321_QA_CERTIFY_CLIENT_ID='ID_CLIENTE_QA_APROBADO'

# Introducir el secreto sin dejarlo en el historial de la shell.
read -r -s -p 'Secret Certify QA: ' MTC_E321_QA_CERTIFY_CLIENT_SECRET
printf '\n'
export MTC_E321_QA_CERTIFY_CLIENT_SECRET

python3 mcs-wallet-provider/tools/mtc_certify_m2m_preflight.py --qa
unset MTC_E321_QA_CERTIFY_CLIENT_SECRET
```

Sustituir las URL de ejemplo por las autorizadas y verificar el host por canal
institucional. El script comprueba coincidencia literal con hosts preaprobados,
requiere HTTPS, no sigue redirecciones y rechaza nombres típicamente productivos.
La confirmación de QA y el host pinning no sustituyen la revisión de DNS/ingress.

### Salida y expectativa

| Caso | Respuesta esperada |
|---|---|
| Solicitud sin bearer | 401 o 403 |
| Obtención token OAuth2 Certify | token Bearer válido (no se imprime) |
| Body con thumbprint malformado y token Certify | 400 |
| Thumbprint RFC7638 aleatorio sin vínculo y nonce nuevo | 403 |
| Token de MiMoto para API Certify (`--cross-client`, opcional) | 403 |
| Vínculo vigente conocido (`--positive`, opcional) | 204 |

La prueba positiva necesita `MTC_E321_QA_KNOWN_THUMBPRINT` y
`MTC_E321_QA_KNOWN_NONCE` **de una sesión de prueba reciente ya acreditada**;
no crea vínculos ni genera sesiones. La modalidad `--cross-client` necesita
`MTC_E321_QA_MIMOTO_CLIENT_ID` y `MTC_E321_QA_MIMOTO_CLIENT_SECRET` de QA.
La herramienta no muestra ni conserva JWT, secretos, thumbprints o nonces.
Evitar `set -x` y herramientas de captura de tráfico con cuerpos HTTP.

## 5. Criterios de paso y pendientes

Un resultado correcto en modo QA significa **solo** que la API responde
adecuadamente a los casos ejecutados, sin concluir E2E. Pendientes para
homologación: Key Attestation real P-256, identidad vigente, `c_nonce` emitido por
Certify idéntico al vinculado por Provider, 204 positivo previo a emisión,
revocación antes de emitir, nueva instalación, ambos formatos de credencial,
ambas variantes de servicio, latencias, timeout y denegación durante caída de PG.

Todas las nuevas políticas permanecen apagadas en AWS hasta autorización
institucional y pruebas integrales. El flag de la app
`WALLET_HOLDER_IDENTITY_REQUIRED=false` no debe considerarse control suficiente
de backend.
