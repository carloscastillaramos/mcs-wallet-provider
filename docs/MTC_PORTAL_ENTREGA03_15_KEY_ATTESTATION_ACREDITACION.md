# MTC · Entrega 03.15 — Precondición para atestación de claves de emisión

**Versión:** E03.15 · 2026-11-24  
**Componente:** `mcs-wallet-provider`  
**Estado:** desarrollo local, apagado de forma predeterminada; sin despliegue QA/PRD.

## Problema y objetivo

La Wallet puede superar o eludir una pantalla local, pero Certify debe poder decidir con evidencia de servidor si una clave de credencial pertenece a una instalación activa con titular acreditado. Ya existe una atestación de clave hardware emitida por Provider, pero antes de este incremento la atestación se podía obtener para una instalación técnicamente enrolada y aún no acreditada biométricamente.

Esta entrega impone la **precondición de identidad en Provider** cuando se solicita una key attestation. No equivale a que Certify ya valide la identidad en tiempo real.

## Flujo protegido

1. Wallet obtiene desafío técnico de Provider.
2. Wallet presenta PoP de instalación, PoP de clave de credencial y evidencia hardware (para Android credential key).
3. `EnrollmentService` valida las firmas y el hardware en el orden existente.
4. `HolderCredentialAttestationPolicy` calcula el JWK thumbprint de la clave pública **persistida** de instalación.
5. `HolderIdentityStatusService` verifica la relación instalación–titular–sesión RENIEC en PostgreSQL (sesión `COMPLETED`, propósito correcto, evidencia y consumo registrados, titular/instalación activos).
6. Solo cuando el estado es `ACCREDITED` y `walletAccessAllowed=true` se solicita firmar la atestación de clave de credencial; los demás estados dan denegación genérica.

Para key attestation legacy de clave de instalación, el control aplica también luego de PoP Android o App Attest iOS. `wallet_attestation` no se bloquea, para permitir el enrolamiento técnico inicial y evitar un ciclo de dependencias.

## Seguridad y alcance temporal

- `WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED=false`: flujo anterior, sin consulta obligatoria de identidad.
- `...=true` y `WALLET_IDENTITY_ENABLED=false`: error al iniciar, y denegación si el control es invocado fuera de configuración válida.
- `...=true` y identidad disponible: consultar PostgreSQL en cada emisión de atestación. Sin caché, sin fallback permisivo.
- Errores de red/BD y estados desconocidos: denegar la atestación.
- Datos biométricos/DNI: no se transmiten a Certify ni forman parte del mensaje de denegación.
- No se alteran Flyway V1–V4, endpoints de emisión de credenciales, formatos mDL/SD-JWT ni verificación web.

## Cobertura del lote

| Caso | Comportamiento |
|---|---|
| Titular acreditado, PoP válidas y atestación hardware válida | Permitir firmar key attestation |
| Titular pendiente/no encontrado/bloqueado | Denegar |
| Instalación revocada o inconsistente | Denegar |
| BD no disponible o clave instalada ilegible | Denegar |
| Política desactivada | Conservar comportamiento anterior |
| Wallet attestation técnica | Continuar sin depender de acreditación previa |
| Proof OpenID4VCI de clave diferente / expiración / revocación tras la atestación | **Pendiente de control en Certify** |

## Pendientes para habilitación

1. Certify debe validar en un control de emisión **online**, con un servicio Provider de autorización de claves, la relación probada entre instalación, titular acreditado y JWK firmante del proof OpenID4VCI; nunca confiar en `X-MTC-Installation-Id` aislado.
2. Scope OAuth2 M2M exclusivo de Certify, client allowlist, TLS, audiencia de issuer, `nonce` firmado, anti-replay y expiración corta.
3. Cubrir las tres rutas `/issuance/credential`, `/issuance/vd11/credential`, `/issuance/vd12/credential` y otros caminos que emitan credenciales.
4. Pruebas PostgreSQL reales (las cuatro pruebas omitidas por configuración del runner no bastan), pruebas multicomponente y homologación en Android físico.
5. Revisar revocación concurrente, claves rotadas y emisión justo antes/después de una revocación.

**No afirmar** que Certify está protegido por esta entrega. La emisión actual y la comprobación de DNI por cada credencial permanecen sin cambios.
