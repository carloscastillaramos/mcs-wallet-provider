# MTC · Entrega 03.22 — Control integrado de preparación local

**Versión:** 03.22  
**Fecha:** 24/11/2026 (America/Lima)  
**Componentes cubiertos:** `inji-wallet`, `mimoto-mtc`, `mcs-wallet-provider`, `inji-certify` y laboratorio PostgreSQL 16.  
**Estado:** herramienta de pruebas local; **no** habilita controles, AWS, ni producción.

## 1. Objetivo

Consolidar en una sola ejecución reproducible la evidencia de los incrementos 03.11–03.21, sin perder el detalle del resultado por componente. La aprobación de cada suite se determina desde **sus propias salidas reales**, no desde recuentos históricos. Un caso negativo esperado puede emitir un stack trace sin invalidar la suite: la autoridad final es el código de salida junto al resumen inequívoco de pruebas.

### Matriz de validación local

| Fase | Origen | Verificación y alcance |
|---|---|---|
| Wallet | Jest | Cliente titular, sesión pendiente, decisión inicial, cabeceras de instalación |
| MiMoto | JUnit Maven | Estado de acreditación, iniciación/consulta protegida RENIEC, políticas fail-closed |
| Provider | Maven `clean verify` | Identidad titular, atestación, vínculo clave–nonce, permisos Certify M2M |
| Certify | Maven `clean verify -Dgpg.skip=true` | Emisión y pruebas negativas de autorización Provider, incluyendo ambos modos |
| Python | unittest | 17 pruebas internas del ejecutor y 11 del preflight OAuth2, validaciones de host y de contrato |
| Contratos | Preflight `--offline` | Coincidencia del contrato local Certify–Provider |
| PostgreSQL **opt-in** | Docker 16 | Migraciones V1–V5 y 27 escenarios de integridad/autorización de vínculo |

## 2. Ejecución

Desde la raíz `~/fuentes/mtc/billetera/iugo/v2/repositorio`:

```bash
# Ver los pasos, sin ejecutar nada
python3 mcs-wallet-provider/tools/mtc_integrated_readiness.py --plan --with-postgres

# Pruebas de los cuatro componentes + preflight, sin Docker
python3 mcs-wallet-provider/tools/mtc_integrated_readiness.py --run \
  --report ./mtc_e0322_readiness.json

# Incluir también PostgreSQL 16 efímero: requiere imagen postgres:16-alpine instalada
python3 mcs-wallet-provider/tools/mtc_integrated_readiness.py --run --with-postgres \
  --report ./mtc_e0322_readiness_con_pg.json

# Probar únicamente el controlador de evidencia, sin Maven/Android/Docker
python3 -m unittest discover -s mcs-wallet-provider/tools/tests \
  -p test_mtc_integrated_readiness.py -v
```

**Condiciones previas:** Java 21, Maven y sus dependencias ya almacenadas localmente (`-o` evita descargas Maven), `inji-wallet/node_modules/.bin/jest` instalado, Python 3, Bash; Docker y `postgres:16-alpine` solo para `--with-postgres`. El laboratorio PostgreSQL preexistente inicia su contenedor con `--network none`, sin montaje de volúmenes ni publicación de puertos, y lo elimina al terminar. El script no descarga imágenes; no invoca `npx`, `kubectl`, AWS CLI ni llamadas a QA.

Las pruebas del propio código Java de terceros **pueden** efectuar solicitudes a `localhost`, por ejemplo la configuración de pruebas Spring a `localhost:8888`; `mvn -o` impide descarga de dependencias Maven pero no constituye un *sandbox* de red universal. Ejecutar en un equipo/ambiente corporativo autorizado y verificar los tests internos si existen restricciones de salida estrictas.

## 3. Seguridad del laboratorio y tratamiento de datos

- Antes de ejecutar, rechaza presencia de indicadores activos de obligatoriedad MTC, variables de conexión del laboratorio QA E03.21 y credenciales/perfiles AWS evidentes.
- Elimina del ambiente hijo las variables cuyo nombre indique secretos, contraseñas, tokens, claves o credenciales AWS; no las transmite ni las imprime. Este filtro es adicional, no sustituye un almacén de secretos.
- Captura la salida de Maven/Jest en memoria únicamente para interpretar el resultado; **no** la incorpora al JSON ni guarda logs completos. El informe contiene identificadores de pruebas, estado, duraciones, conteos, huellas SHA-256 de fuentes locales y contexto de aceptación. No incluye DNI, JWT, nombres de clientes ni URLs de la organización.
- Escribe el JSON con permisos `0600` en la ruta elegida. El usuario debe evitar subir este fichero a Git si los informes internos de su organización se consideran restringidos.
- En caso de fallo muestra un resumen seguro; para análisis fino, ejecutar **individualmente** la suite fallida con su comando habitual y revisar su log local. No compartir trazas con tokens reales.

## 4. Semántica de resultados

- `PASS` por suite exige retorno 0 **y** un resumen de ejecución verificable; en Maven requiere además `BUILD SUCCESS` y cero errores/fallos.
- `NOT_PASS` global indica al menos una suite fallida o bloqueada. No se convierte en PASS aunque las demás pasen.
- `local_validation=PASS` indica **solo** el conjunto seleccionado. Si no se utiliza `--with-postgres`, el informe explicita `postgres_lab_requested=false`, sin afirmar haber ejecutado el laboratorio SQL en esa corrida.
- `qa_e2e=PENDING` y `production_release=NOT_AUTHORIZED` son incondicionales, incluso si todas las pruebas locales pasan.
- Un informe de 03.22 **no** valida atestación real en Keystore/StrongBox, Cognito real, biometría ID Perú ni pruebas de dispositivo físico.

## 5. Criterios institucionales pendientes para habilitar QA E2E

1. Registrar cuenta AWS **QA**, región, namespace EKS, FQDN de QA de Provider, MiMoto, Certify y Cognito; comprobar TLS y DNS con Infraestructura (sin entregar secretos).
2. Habilitar el Resource Server y cliente Cognito **exclusivo** Certify, scope `mtc-wallet-provider/wallet.issuance.certify`. Mantener separados los permisos de MiMoto y de administración.
3. Aplicar migraciones V1–V5 en base PostgreSQL **QA autorizada** mediante procedimiento controlado y respaldo. La prueba Docker no sustituye ese cambio.
4. Configurar flags secuencialmente **solo en QA** y verificar que los endpoints internos no quedan expuestos públicamente; comprobar gestión de llaves y secreto Cognito por Secrets Manager.
5. En Android real: primer ingreso con ID Perú, DNI acreditado unido a instalación, segundo ingreso sin nueva biometría cuando la asociación siga vigente y reinstalación que obligue a reacreditar.
6. Emitir credencial **mDL** y **SD-JWT** con nuevo `c_nonce`; demostrar que la atestación de clave registra en Provider exactamente ese nonce y la misma huella RFC7638 obtenida del proof **validado** por Certify.
7. Negativos obligatorios **antes** de generar credencial: titular sin acreditar; instalación revocada; vínculo vencido; clave diferente; nonce diferente; cliente MiMoto intentando usar scope Certify; JWKS no accesible; token Cognito expirado; Provider indisponible; PostgreSQL indisponible. **Todos** deben impedir la emisión.
8. Confirmar continuidad del requisito DNI **por cada credencial**, y que la verificación web de INJI Verify no se altera.
9. Recuperación/rollback: desactivar primero `MTC_CERTIFY_PROVIDER_ISSUANCE_REQUIRED` en Certify QA; después revisar las políticas de Provider, manteniendo auditoría y sin limpiar datos de QA salvo procedimiento aprobado.

Estas pruebas de QA son **pendientes** y deliberadamente no están automatizadas por este paquete. Una `local_validation=PASS` es una precondición técnica, nunca un criterio único de liberación.
