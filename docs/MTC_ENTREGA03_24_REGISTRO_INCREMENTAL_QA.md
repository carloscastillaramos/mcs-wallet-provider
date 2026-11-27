# MTC — Entrega 03.24: registro incremental de evidencias QA

**Versión:** 03.24  
**Fecha:** 24/11/2026 (America/Lima)  
**Prerequisitos:** E03.22 local PASS con PostgreSQL V1–V5; E03.23 y expediente inicial de 34 casos PENDING.  
**Alcance:** herramienta documental sin red, sin operaciones AWS, sin cambio de configuración ni de código productivo.

## Finalidad y límites

La entrega 03.23 genera y evalúa el expediente E2E QA, pero actualizar los resultados requiere edición manual de JSON. Esta entrega permite incorporar **de manera incremental** la configuración QA y un resultado declarado de prueba, creando **un archivo distinto en cada operación**. El manifiesto anterior queda preservado y puede archivarse como antecedente. La herramienta calcula SHA-256 de un soporte de texto ya sanitizado; no certifica por sí misma que el escenario QA se haya ejecutado o que el soporte sea auténtico. Jamás autoriza PRD.

## Paso 1. Verificar instalación y herramienta

Desde la raíz del monorepositorio, tras aplicar E03.24:

```bash
python3 -m unittest discover -s mcs-wallet-provider/tools/tests \
  -p test_mtc_qa_e2e_register.py -v
python3 mcs-wallet-provider/tools/mtc_qa_e2e_register.py --help
```

Se esperan **36 pruebas**, sin acceso a red ni credenciales. El script Python solo utiliza biblioteca estándar y reutiliza las comprobaciones `mtc_qa_e2e_evidence.py` ya instaladas con E03.23. Revalida que el informe local E03.22 sea reciente (14 días), que las ocho suites estén aprobadas, que PostgreSQL se haya probado y que no haya variación en los hashes de las fuentes.

## Paso 2. Configurar revisiones reales de QA

El equipo de despliegue debe suministrar ticket y las cuatro revisiones **efectivamente desplegadas** en QA. No reemplazar estas variables con valores de ejemplo ni inventar revisiones.

```bash
python3 mcs-wallet-provider/tools/mtc_qa_e2e_register.py configure \
  --local-report ./mtc_e0322_readiness_con_pg.json \
  --input ./mtc_qa_e0323/mtc_qa_e0323_evidencias.json \
  --out ./mtc_qa_e0323/expediente_qa_configurado.json \
  --change-ref "$QA_CHANGE_REF" \
  --wallet-version "$QA_WALLET_REVISION" \
  --mimoto-version "$QA_MIMOTO_REVISION" \
  --provider-version "$QA_PROVIDER_REVISION" \
  --certify-version "$QA_CERTIFY_REVISION"
```

La operación guarda una nueva versión, sin marcar escenarios como ejecutados. No se pueden cambiar versiones o ticket en el mismo expediente una vez configurado; otro despliegue QA debe iniciar expediente nuevo.

## Paso 3. Registrar pruebas E2E realmente ejecutadas

Tras ejecutar un escenario en QA autorizado, conservar los soportes originales en el repositorio documental institucional, generar un **extracto minimizado** de texto (UTF-8, extensión `.md`, `.txt` o `.json`), revisar que no contenga datos personales, biometría, URLs internas ni secretos, y protegerlo con `chmod 600`.

```bash
chmod 600 "$QA_SANITIZED_EVIDENCE_FILE"
python3 mcs-wallet-provider/tools/mtc_qa_e2e_register.py record \
  --local-report ./mtc_e0322_readiness_con_pg.json \
  --input ./mtc_qa_e0323/expediente_qa_configurado.json \
  --out ./mtc_qa_e0323/expediente_qa_caso01.json \
  --case-id "$QA_CASE_ID" \
  --status "$QA_RECORDED_RESULT" \
  --ticket "$QA_EVIDENCE_TICKET" \
  --executed-at-utc "$QA_EXECUTED_AT_ISO8601" \
  --evidence-file "$QA_SANITIZED_EVIDENCE_FILE"
```

`QA_CASE_ID` debe ser uno de los 34 IDs del catálogo (p. ej., `QA-ENV-01`). `QA_RECORDED_RESULT` requiere una decisión explícita `PASS`, `FAIL` o `BLOCKED`; **el script no determina el resultado**. La fecha debe incluir zona horaria y encontrarse dentro de los 30 días anteriores. El ticket debe usar la forma `MTCQA-...` o un identificador institucional permitido, sin URLs. El texto del soporte no se incorpora al expediente: únicamente hash SHA-256, ticket, fecha y resultado.

Para registrar el segundo caso, utilizar `--input ./mtc_qa_e0323/expediente_qa_caso01.json` y otro nombre nuevo en `--out`. Archivar todos los expedientes anteriores. El programa imprime las huellas SHA-256 tanto del expediente de entrada como del de salida para mantener la cadena de custodia documental.

### Retest

Si el caso está `FAIL` o `BLOCKED`, una nueva ejecución requiere `--retest --supersedes-ticket "<ticket_anterior>"`, un ticket nuevo, soporte distinto y fecha posterior. Es imposible sustituir silenciosamente un `PASS`; una rectificación de un PASS exige un expediente nuevo y una gestión de cambio autorizada. `human_review` nunca es cambiado por la herramienta.

## Paso 4. Evaluar expediente

```bash
python3 mcs-wallet-provider/tools/mtc_qa_e2e_evidence.py --assess \
  --local-report ./mtc_e0322_readiness_con_pg.json \
  --evidence ./mtc_qa_e0323/expediente_qa_caso01.json \
  --report ./mtc_qa_e0323/evaluacion_caso01.json
```

El código de salida `1` mientras haya casos `PENDING`, `FAIL` o `BLOCKED` **es normal** y significa que aún no hay homologación completa. El código `0` solo indica que las 34 pruebas están documentadas con metadatos completos; sigue siendo necesaria revisión independiente y pruebas QA genuinas. En todo caso `qa_e2e_verified_by_tool=false` y `production_release=NOT_AUTHORIZED`.

## Controles de seguridad y criterios de aceptación

- **Fuente inmutable:** no se sobrescribe el archivo original y cada versión nueva se escribe con permisos `0600`; un destino existente bloquea la operación.
- **No exposición:** no se guarda el contenido de soportes ni sus rutas. Se rechazan archivos binarios, enlaces simbólicos, tamaños fuera de 20–65536 bytes, permisos accesibles por grupo/otros y extensiones que no sean texto/Markdown/JSON.
- **Sanitización conservadora:** se rechazan patrones frecuentes de DNI, correo, tokens, secretos, direcciones IP y URLs; el filtro no sustituye una revisión institucional y puede producir falsos positivos.
- **Baseline verificable:** se bloquea un reporte E03.22 adulterado, caducado o que no concuerde con las fuentes.
- **Estados explícitos:** no hay promoción de un caso a `PASS` por la sola presencia de un archivo ni por el SHA-256.
- **Separación institucional:** completar el expediente documental no autoriza el despliegue productivo. No hay ninguna ejecución sobre AWS, Cognito, ID Perú o PostgreSQL real.
