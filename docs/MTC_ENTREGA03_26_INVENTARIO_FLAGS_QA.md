# Entrega 03.26 — Inventario declarativo QA y dependencias de habilitación

**Versión:** 03.26  
**Fecha:** 25/11/2026  
**Objetivo:** cerrar la acción documental `REGISTRAR_VERSIONES_QA` identificada
por la Entrega 03.25 sin inventar el contenido de los despliegues en AWS.

## Contexto y alcance

La Entrega 03.22 aprobó Wallet 43, MiMoto 46, Provider 172 (4 omitidas), Certify
710 (4 omitidas), preflight local, laboratorio PostgreSQL V1–V5 y herramientas.
Las Entregas 03.23–03.25 gestionan 34 casos QA E2E, resultados versionados y
resúmenes. El primer expediente sigue con cero escenarios ejecutados.

Este incremento utiliza exclusivamente un snapshot **sanitizado y manual** de
13 flags, cuatro revisiones declaradas y un ticket QA. El archivo de entrada
no debe contener identificadores de ciudadanos, direcciones internas, tokens,
client IDs Cognito, claves, secretos ni binarios de despliegue. La plantilla
no asume que todos los controles estén apagados: exige observación explícita.

## Dependencias codificadas

Los nombres y reglas provienen de la documentación acumulada de Wallet,
MiMoto, Wallet Provider (E03.15–03.17) y Certify (E03.18–03.21).

| Control activado | Prerrequisitos booleanos exigidos |
|---|---|
| `WALLET_IDENTITY_MIMOTO_M2M_ENABLED` | `WALLET_IDENTITY_ENABLED`, `WALLET_COGNITO_ENABLED` |
| `WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED` | `WALLET_IDENTITY_ENABLED` |
| `WALLET_IDENTITY_CREDENTIAL_BINDING_ENABLED` | `WALLET_IDENTITY_ENABLED`, `WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED` |
| `WALLET_IDENTITY_CERTIFY_M2M_ENABLED` | Identidad, Cognito, Key Attestation y Credential Binding activados |
| `MTC_KEY_ATTESTATION_REQUIRED` | `MTC_KEY_ATTESTATION_VALIDATION_ENABLED` |
| `MTC_CERTIFY_PROVIDER_ISSUANCE_REQUIRED` | Validación y obligatoriedad Key Attestation en Certify y M2M Certify + binding de Provider |
| `MIMOTO_HOLDER_ISSUANCE_ENFORCEMENT_ENABLED` | Evidencia MiMoto, cliente Provider M2M, identidad Provider y endpoint Provider MiMoto M2M |
| `WALLET_HOLDER_IDENTITY_REQUIRED` | Guarda de emisión MiMoto e identidad Provider activadas |

**Son reglas necesarias, nunca suficientes.** No comprueban configuración de
certificados, alcance exclusivo Cognito `mtc-wallet-provider/wallet.issuance.certify`,
allowlist de clientes, política Key Attestation, seguridad de ingress, credenciales
Secrets Manager, vigencia de Redis, estado de Flyway real ni dispositivos Android.
Esos controles están en la matriz QA y deben documentarse con evidencia real.

Los flags `MTC_MIMOTO_ATTESTATION_ENABLED` y `WALLET_PROVIDER_MIMOTO_GUARD_ENABLED`
no se incluyen en esta instantánea mínima porque su configuración puede depender
del canal de build Spring/React Native y se comprueban en el plan integral QA;
**su ausencia no significa que esos controles sean opcionales**.

## Estado y salida

`BASELINE_ALL_DISABLED`: todo declarado `false`, aún sin control obligatorio.
`PARTIAL_STAGING_QA_E2E_PENDING`: subconjunto sin contradicciones, aún sin
homologación. `ENFORCEMENT_CONFIGURED_QA_E2E_PENDING`: se declaran activas
obligatoriedad Wallet y autorización Certify, con las precedencias revisadas,
pero NO existe certificación E2E. `DEPENDENCY_CONFLICT`: incongruencias; no se
permite configurar un expediente a partir de ese snapshot.

No se sobrescriben expedientes. La operación reutiliza `configure` E03.24,
`assess` E03.23 y validación de readiness E03.22. Exige que el baseline local
sea vigente (14 días), íntegro y referido al mismo checkout de fuentes.
Al caducar, repetir la validación E03.22 y conciliar formalmente el baseline;
no alterar hash en JSON manualmente.

## Secuencia institucional sugerida (solo QA autorizado)

1. Infraestructura confirma cambio, revisiones desplegadas, artefactos,
   restricciones de red y esquema V1–V5 de PostgreSQL QA.
2. Responsable crea la instantánea sanitizada de flags reales y ejecuta el
   analizador; registra y corrige cualquier dependencia incoherente.
3. Se genera inventario versionado y expediente E03.23 configurado sin modificar
   el original. La correlación es documental: no hay firma remota de AWS.
4. Se ejecuta el preflight QA E03.21 solo si existe aprobación institucional
   expresa, hosts autorizados y método seguro de suministro de credenciales.
5. Se ejecutan los 34 escenarios con casos negativos, mDL y SD-JWT, revocación,
   ID Perú y resiliencia; se registran pruebas mediante E03.24 y se revisan
   periódicamente con E03.25.
6. Ante incidencia en la autorización de emisión, para recuperar el servicio
   QA el rollback de política debe comenzar por desactivar
   `MTC_CERTIFY_PROVIDER_ISSUANCE_REQUIRED` en Certify QA, conforme al plan de
   cambio y con autorización de Infraestructura; no desactivar controles de PRD.

## Riesgos conocidos

- La observación manual puede diferir de la configuración real; es obligatoria
  la comparación por Infraestructura. La herramienta **no autentica** una prueba
  de despliegue ni un artefacto.
- Un estado sin contradicciones no garantiza que Cognito disponga de un scope
  correcto, de que Redis/DB sean accesibles ni que la autorización online funcione.
- No asumir `false` al no disponer de un flag real: usar `UNRECORDED` y bloquear.
- Los expedientes originales son inmutables: retests requieren ticket nuevo,
  referencia previa y soporte sanitizado de E03.24.
- Ninguna combinación de flags ni un expediente con 34 PASS declarados concede
  facultad para habilitar producción. `PRD NOT_AUTHORIZED` es incondicional.
