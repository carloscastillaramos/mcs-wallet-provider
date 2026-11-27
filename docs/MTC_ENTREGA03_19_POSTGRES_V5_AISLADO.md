# MTC — Entrega 03.19: validación real aislada de PostgreSQL V5

**Propósito:** homologar migraciones V1–V5 y el predicado de autorización
Certify → Provider sin riesgo a bases corporativas ni exposición de datos.

## Alcance y garantías

1. Contenedor PostgreSQL 16 Alpine **existente localmente**, sin red (`--network none`),
   sin puertos publicados y sin montar volúmenes; credenciales aleatorias efímeras.
2. Se crean **solo** `wallet_provider_lab` y esquema `wallet_provider` dentro del contenedor.
3. Se aplican las migraciones fuente V1–V5 sin modificarlas, con `PGOPTIONS` para
   fijar el esquema desde el inicio de cada sesión.
4. 27 aserciones verifican estructura, claves, restricciones, caducidad,
   instalación revocada, titular bloqueado, sesión fallida y duplicidad.
5. La prueba SQL usa datos absolutamente ficticios y `ROLLBACK`.
6. El contenedor se destruye con `trap` también si falla una comprobación.

**Límite:** las aserciones SQL reproducen el predicado de consulta, no ejecutan
`CredentialKeyBindingRegistry` mediante JDBC; esto no demuestra la configuración
AWS/Cognito ni el flujo de prueba firmada de INJI Wallet a Certify. Requiere
validaciones E2E y contratos de aplicación separados.

## Ejecución

```bash
cd ~/fuentes/mtc/billetera/iugo/v2/repositorio
bash mcs-wallet-provider/tools/validate_credential_binding_db_lab.sh
```

No acepta parámetros de conexión. No usar `sudo` para ejecutar el script.
El script **no** descarga la imagen automáticamente: si falta, solicita
obtener `postgres:16-alpine` mediante un paso consciente del operador.

## Corrección de build Certify E03.18

El comando `mvn clean verify` puede activar `maven-gpg-plugin`, que necesita
clave privada solo disponible en la cadena de publicación. En el laboratorio
local usar `-Dgpg.skip=true`, **sin** `-DskipTests`. No modificar el POM
para retirar la firma del ciclo formal de publicación.

## Pendientes de despliegue

- Ejecutar migraciones con rol DBA y `search_path` autorizado en PostgreSQL QA.
- Homologar JDBC real, JWT Cognito y vínculo PoP/atestado del móvil.
- Validar mDL y SD-JWT y revocación en emisión en dispositivo físico.
- Mantener flags nuevos desactivados hasta completar pruebas integrales.
