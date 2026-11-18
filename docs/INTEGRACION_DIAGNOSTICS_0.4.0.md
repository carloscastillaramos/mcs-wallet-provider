# MTC — Vinculación segura de claves Diagnostics, Provider 0.4.0

## Alcance y estado

Esta entrega implementa el **backend**, NO el código del cliente INJI Wallet. La sincronización se habilita **solamente** después de disponer de identidad OAuth2 `client_credentials`, red interna EKS con mTLS y migraciones V2 aplicadas en ambos servicios. Por defecto `WALLET_DIAG_SYNC_ENABLED=false`. Nunca se envían claves privadas ni credenciales de cliente al móvil.

**Decisión de seguridad:** la clave Apple App Attest de la instalación iOS NO se trata como clave de firma ECDSA arbitraria para Diagnostics. La Wallet debe generar y guardar una **clave ES256 P-256 dedicada** para firmar los sobres JWE de Diagnostics. En Android e iOS esta nueva clave demuestra posesión, y la instalación existente autoriza criptográficamente su vinculación. Esta versión valida posesión y vinculación, **no atestación de hardware independiente de la clave Diagnostics**. Si se exige ese nivel de garantía debe ampliarse la validación de origen y custodia de esta nueva clave.

## Protocolo del móvil (implementación pendiente)

1. Solo tras completar el enrolamiento legítimo, persistir el `installationId` ya existente de Wallet Provider.
2. Generar una nueva clave EC `secp256r1` de firma en almacenamiento seguro del sistema (no exportar clave privada), definir `keyId` único de 1–64 caracteres `[A-Za-z0-9_-]` y exportar **solo** la parte pública SPKI DER en Base64 estándar (`publicKeySpkiBase64`). No reutilizar la clave de App Attest iOS para firmar lotes.
3. Llamar a `POST /api/v1/enrollments/challenge` con `{"platform":"ANDROID"}` o `{"platform":"IOS"}` para obtener `challengeId`, `nonce`.
4. Construir exactamente el texto UTF-8 (sin saltos, sin espacios):
   `wp-diagnostics-bind:v1:{installationId}:{challengeId}:{nonce}:{keyId}:{base64url_no_padding(SHA256(publicKeySPKI_DER))}`.
5. `keyProofSignature` = Base64URL sin padding de una firma **SHA256withECDSA ASN.1 DER** de ese texto por la clave dedicada.
6. Android: `installationProofSignature` = firma igual del texto por la clave de la instalación ya atestada. iOS: `appAttestAssertion` = assertion de App Attest usando **SHA256(texto UTF-8)** como `clientDataHash` (el servidor reutiliza la verificación existente y exige contador creciente); el parámetro `installationProofSignature` no se usa.
7. `POST /api/v1/installations/{installationId}/diagnostics-keys`, cuerpo:

```json
{
  "challengeId": "uuid-desafio",
  "keyId": "diagnostics_key_local_01",
  "publicKeySpkiBase64": "base64-spki-der",
  "keyProofSignature": "base64url-firma-der",
  "installationProofSignature": "base64url-firma-der-android-o-null",
  "appAttestAssertion": "base64-assertion-ios-o-null"
}
```

8. Respuesta `{"installationId":"...","keyId":"...","syncStatus":"PENDING_SYNC"}`: el servidor guardó la intención de sincronización **en su propia transacción**, NO que Diagnostics ya recibió la clave. La Wallet debe gestionar el estado pendiente y reintentar el envío de diagnósticos sin descartar su cola local si obtiene 401 temporal.
9. Una vez registrada en Diagnostics, el móvil firma cada lote JWE con su nueva clave usando el contrato `docs/wallet-jwe-contract.md` de Diagnostics. `X-MCS-Device-ID` será el `installationId` de Provider y `X-MCS-Key-ID` será el `keyId` de la clave Diagnostics. Ambos identificadores deben mantenerse estables para conservar idempotencia.

## Sincronización entre microservicios

- Provider confirma la vinculación bajo una transacción que escribe `wp_diagnostics_key` y `wp_diagnostics_outbox` de forma atómica. La revocación de una instalación crea eventos `REVOKE` para todas sus claves activas.
- Un trabajador posterior al commit hace `PUT /api/v1/internal/devices/{installationId}/keys/{keyId}` con `{"platform":"ANDROID|IOS","publicKeySpkiBase64":"..."}` o `DELETE` de la misma ruta. Son peticiones privadas entre servicios, **no se publican en el Gateway**.
- El token de acceso para esta ruta se obtiene vía **OAuth2 client_credentials** con scope `diagnostics.device.sync`. Diagnostics valida firma del token, issuer, audience, scope y `client_id` o `azp` explícitamente permitidos.
- Diagnostics es idempotente; una revocación crea un **tombstone** incluso si el registro todavía no ha llegado. Un registro tardío jamás debe reactivar una clave revocada. Se serializan las operaciones por `(deviceId,keyId)` con advisory locks transaccionales PostgreSQL.
- **Advertencia: la revocación es eventual**, no inmediata. Durante una caída de Diagnostics o del emisor OAuth, la clave puede continuar aceptándose allí hasta que se entregue el evento `REVOKE`. Definir con Seguridad MTC el máximo retraso admisible; si se exige revocación inmediata, añadir consulta de confianza al Provider o mecanismo fail-closed antes de producción.
- Outbox usa leases y reintentos con backoff; ante timeout puede repetir la petición y se espera una respuesta idempotente. No usa SQS/Kafka. **Alertar** sobre pendientes con más de 15 minutos; las revocaciones nunca se descartan por alcanzar un número de intentos.

## Variables de entorno Provider

| Variable | Uso |
|---|---|
| `WALLET_DIAG_SYNC_ENABLED` | `false` por defecto. Activar solo después de migrar y configurar identidad |
| `WALLET_DIAG_SYNC_BASE_URL` | HTTPS privado o `http://mcs-wallet-diagnostics:8080` en mesh mTLS verificado |
| `WALLET_DIAG_SYNC_TOKEN_URL` | Token endpoint del emisor OAuth2 institucional |
| `WALLET_DIAG_SYNC_CLIENT_ID` | Cliente de servicio exclusivo de Provider (desde Secret) |
| `WALLET_DIAG_SYNC_CLIENT_SECRET` | Secreto rotativo del cliente (desde Secret) |
| `WALLET_DIAG_SYNC_ALLOW_HTTP_IN_MESH` | `false` por defecto; `true` solo si el sidecar Istio mTLS está confirmado |
| `WALLET_DIAG_SYNC_INTERVAL_MS` | Frecuencia de despacho, por defecto 5000 ms |

Diagnostics debe configurar `MCS_PROVIDER_SYNC_CLIENT_ID` con el identificador exacto autorizado; sin esa variable, todas las peticiones internas se rechazan por diseño. El mismo emisor OAuth debe validar un `aud` permitido para Diagnostics mediante `MCS_ADMIN_JWT_AUDIENCE`, sin otorgar el scope interno a usuarios humanos. Exigir también políticas Istio AuthorizationPolicy / NetworkPolicy que limiten el origen al workload Provider.

## Esquemas y migraciones

**No modificar V1**. Las migraciones V2 introducen:

- `wallet_provider.wp_diagnostics_key`: relación entre instalación legítima y clave pública dedicada.
- `wallet_provider.wp_diagnostics_outbox`: cola transaccional para altas y revocaciones, con leases reintentables.
- `wallet_diagnostics.mcs_diag_device_tombstone`: protección permanente contra reactivación por mensajes fuera de orden.

Flyway aplicará V2 tras V1; en QA usar roles DDL controlados y verificar versión `2` en ambos historiales antes de habilitar el trabajador.

## Verificaciones y pruebas

```bash
cd ~/fuentes/mtc/billetera/iugo/v2/repositorio/mcs-wallet-provider
mvn clean verify
cd ../mcs-wallet-diagnostics
mvn clean verify
```

Tests añadidos: vinculación Android con dos firmas, rechazo de firma inválida, vinculación iOS con App Attest, revocación y outbox, registro idempotente, tombstone, conflicto de claves y revocación adelantada. **Es indispensable ejecutar Maven en Ubuntu: la revisión de sintaxis aislada del JDK no prueba tipos ni runtime**.

Base QA: al activar los servicios, validar un flujo integrado con dispositivo real, token client_credentials, inyección controlada de fallos entre servicios, firma de lotes JWE, cambio de dispositivo y revocación. Medir p95 HTTP y traza completa en EKS/RDS; NO extrapolar pruebas SQL locales.

### Consultas de observabilidad (solo QA / lectura)

```sql
SELECT action,state,COUNT(*) AS total,MAX(attempts) AS reintentos_maximos,
       MIN(created_at) AS mas_antiguo
FROM wallet_provider.wp_diagnostics_outbox
GROUP BY action,state ORDER BY action,state;

SELECT COUNT(*) AS pendientes_antiguos
FROM wallet_provider.wp_diagnostics_outbox
WHERE state <> 'DONE' AND created_at < CURRENT_TIMESTAMP - INTERVAL '15 minutes';
```

No capturar cuerpo, `Authorization`, tokens, PEM privados ni contenido sensible de diagnóstico en logs.

## Pendientes explícitos

1. Adaptar fuentes INJI Wallet de Android/iOS para crear la clave de diagnósticos dedicada y efectuar el binding y los envíos offline/JWE. **No se entrega esa modificación en este paquete**.
2. Verificar con infraestructura el emisor OAuth2 que soporte `client_credentials`, `aud` de Diagnostics, scope dedicado, identidad de cliente, secretos rotativos e Istio mTLS.
3. Probar el despliegue real EKS/RDS (incluidas V2), recuperación del outbox con caída de Diagnostics, permisos de esquema y alertas.
4. Definir rotación independiente de una clave Diagnostics y tratamiento de pérdida/cambio de dispositivo. La revocación de instalación ya propaga todas las claves vinculadas.
5. Acordar tratamiento de claves huérfanas / DLQ lógica cuando un error 409 por conflicto de material sea permanente; el outbox actual reintentará hasta que el incidente sea resuelto.
