# MTC Portal — Entrega 03.4 — Validacion interna de sesion e instalacion

**Fecha:** 25/11/2026. **Estado:** código para validacion local; sin habilitacion QA/PRD.

## Objetivo

Cerrar de forma incremental dos condiciones distintas del futuro flujo:

1. **MiMoto:** RENIEC debe haberse iniciado bajo una clave de Wallet previamente
   atestada y la misma clave debe solicitar la acreditacion de identidad; el
   almacenamiento de Redis asocia `reniecSessionId -> JWK SHA-256 thumbprint`.
2. **Provider:** la misma clave debe corresponder al `installation_id` almacenado,
   con sesion `identity_session_id` PENDING, purpose `HOLDER_ENROLLMENT`, nonce correcto,
   expiracion futura e instalacion ACTIVE. Sin titular previamente asociado.

El hash JWK se calcula a partir del PEM P-256 que Provider guardo al enrolar
la instalacion, usando el algoritmo RFC 7638 de Nimbus. Coincide con el
thumbprint de `MtcWalletSessionGate` de MiMoto.

## Lo que NO hace este lote

- NO publica endpoint M2M, no autentica todavia al servidor MiMoto ante Provider,
  ni crea un proceso que conecte estos dos metodos.
- NO usa ni consume `ReniecAuthCodeSuccessMarker` ni firma evidencia automaticamente.
- NO modifica el flujo que pide DNI por credencial ni Verify web.
- NO activa biometria de primera apertura ni altera el AS-IS de INJI Wallet.
- NO agrega tablas, variables, certificados ni claves.

## Criterios de seguridad

- El backend que integre ambos componentes debe autenticar MiMoto (mTLS/OAuth2
  M2M, conforme a configuracion institucional) y obtener los datos de sesión de
  Provider y MiMoto, no directamente de parámetros no verificados del movil.
- El `thumbprint` de esta etapa **no es** por si solo una prueba de posesion:
  MiMoto debe validar primero Attestation + PoP. Provider corrobora con la clave
  de instalacion guardada.
- La consulta de Provider es read-only. Al completar la acreditacion, Provider
  debe **volver a validar en transaccion** estado ACTIVE, session PENDING y nonce.
- En el proximo lote, enlazar check MiMoto + check Provider + consumo unico del
  resultado RENIEC + firma y cierre transaccional, con pruebas de replay, expiracion
  y concurrencia. Mantener flags apagados hasta E2E.

## Pruebas sugeridas

```bash
mvn -B -ntp -f mcs-wallet-provider/pom.xml \
  -Dtest=HolderInstallationBindingVerifierTest test
mvn -B -ntp -f mcs-wallet-provider/pom.xml clean verify
mvn -B -ntp -f mimoto-mtc/pom.xml \
  -Dtest=MtcWalletSessionGateTest,MtcHolderEvidenceSignerTest,ReniecAuthCodeSuccessMarkerTest test
```

No ejecutar sobre PostgreSQL institucional; los tests unitarios son mocks.
