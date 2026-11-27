# MTC-BD-ESP-ENR-001 — Entrega 01.1: comprobación PostgreSQL completamente aislada

**Objetivo:** verificar DDL de V1–V4 en PostgreSQL 16 antes de implementar DNI–instalación.

## Evidencia previa

El usuario ejecutó `InstitutionalAuthorizationServiceTest`: **15/15 PASS**. También `mvn -B -ntp -f mcs-wallet-provider/pom.xml clean verify`: **BUILD SUCCESS**, **42 contabilizadas / 4 omitidas**. La prueba `PersistenceSmokeTest` utiliza H2.

## Política de aislamiento

- `docker run --network none`, sin publicación de puertos, montaje de directorios, enlaces de Docker a redes ni reutilización de bases existentes.
- Container name aleatorio, contraseña aleatoria, base `wallet_provider_lab` creada dentro del propio contenedor.
- Las cuatro migraciones se copian hacia ese contenedor efímero.
- Se utilizan únicamente identidades sintéticas y blobs ficticios; la transacción de pruebas se revierte y luego se destruye el contenedor.
- No se consulta ninguna variable de acceso a RDS ni se activan `WALLET_PG_IT` / `WALLET_PG_DEEP_IT`.
- Si `docker run` o algún SQL falla, el script termina con error y elimina su contenedor.

## Cómo ejecutar

```bash
cd ~/fuentes/mtc/billetera/iugo/v2/repositorio
bash mcs-wallet-provider/tools/validate_portal_db_lab.sh
```

Se necesita Docker utilizable sin ejecutar el script como root y disponer de la imagen `postgres:16-alpine` (Docker puede descargarla).

## Qué comprueba

- Existencia de las 15 relaciones base (cinco preexistentes y diez de V3/V4).
- Integridad positiva de instalación, titular, sesión, entidad y autorización.
- Bloqueo de un vínculo acreditado a una sesión de otra instalación.
- Rechazo de una sesión `COMPLETED` sin evidencia consumida.
- Unicidad del titular mediante HMAC de documento.
- Rechazo de vigencia inválida y revocación sin fecha.
- Restricción de roles administrativos a MTC y unicidad de operador por `issuer/sub`.

## Límites de esta entrega

Es una validación SQL sobre PostgreSQL real, **no valida Flyway ni integra el resultado de RENIEC con Provider**. No crea ni cambia endpoints y no altera el código productivo. V1/V2 no se modifican. El informe del script debe adjuntarse al siguiente avance.

**Variables nuevas de aplicación:** ninguna. El README se actualizó para reflejar las variables existentes, el resultado `clean verify` y este procedimiento.
