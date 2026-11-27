# MTC · Entrega 03.23 — Expediente de homologación E2E en QA

**Versión:** 03.23  
**Fecha:** 24/11/2026 (America/Lima)  
**Prerequisito:** Entrega 03.22 local validada con PostgreSQL V1–V5.  
**Estado:** herramienta documental sin red, ninguna política se activa y producción no queda autorizada.

## 1. Objetivo y límite de confianza

El informe consolidado E03.22 permite pasar a la etapa de homologación QA. **No equivale a la prueba E2E**. Esta entrega crea un catálogo versionado de 34 escenarios de QA y un expediente de trazabilidad con huellas SHA-256 y referencias a evidencias resguardadas en el repositorio documental de la institución. El programa no controla AWS, Cognito, ID Perú, móviles Android, Kubernetes, bases de datos ni realiza pruebas en red: su evaluación es de **completitud documental y consistencia local**, nunca una verificación autónoma de hechos en QA. Es obligatorio contrastar manualmente las evidencias y obtener aprobación institucional independiente.

El script **nunca** cambia `production_release=NOT_AUTHORIZED`, ni siquiera cuando todos los casos aparezcan como `PASS`. La propiedad `qa_e2e_verified_by_tool` es siempre `false`.

## 2. Reglas del inventario

El catálogo `tools/mtc_qa_e2e_cases.json` contiene 34 pruebas obligatorias. Cada una presenta identificador estable, área, título, procedimiento de alto nivel y resultado esperado. Las áreas son infraestructura, datos, despliegue, auditoría, ID Perú, atestación, emisión mDL/SD-JWT, revocación, resiliencia, compatibilidad y operación.

El programa exige que el reporte local E03.22:

- sea `mtc-local-readiness/1`, versión 03.22 y tenga `local_validation=PASS`;
- incluya las ocho suites obligatorias aprobadas, incluyendo `postgres_v5`;
- declare `qa_e2e=PENDING` y `production_release=NOT_AUTHORIZED`;
- contenga huellas SHA-256 de fuentes que **todavía coincidan** con el checkout;
- haya sido emitido hace no más de catorce días (o repetir E03.22).

El manifiesto QA resultante enlaza el SHA-256 del informe local completo y **no** se puede reutilizar con otro baseline sin iniciar un expediente nuevo.

## 3. Flujo de trabajo

Desde la raíz del repositorio MTC:

```bash
# Validación de la nueva herramienta
python3 -m unittest discover -s mcs-wallet-provider/tools/tests \
  -p test_mtc_qa_e2e_evidence.py -v

# Generar matriz y expediente QA (sin conectividad, sin permisos AWS)
python3 mcs-wallet-provider/tools/mtc_qa_e2e_evidence.py --init \
  --local-report ./mtc_e0322_readiness_con_pg.json \
  --out-dir ./mtc_qa_e0323

# Ver matriz de casos que se ejecutarán posteriormente en QA autorizado
sed -n '1,160p' ./mtc_qa_e0323/mtc_qa_e0323_matriz.md
```

La plantilla genera `mtc_qa_e0323_evidencias.json` con todos los casos en `PENDING`. **No** marcar `PASS` sin haber realizado el escenario en QA y revisado sus evidencias. Completar `change_ref` (por ejemplo `MTCQA-20261124`), las cuatro revisiones de despliegue (`wallet`, `mimoto`, `provider`, `certify`), y para cada caso ejecutado:

- `status`: `PASS`, `FAIL`, `BLOCKED`, `PENDING`;
- `evidence_ref`: identificador interno de ticket institucional, **no** URL, DNI, nombre ni secreto;
- `evidence_sha256`: SHA-256 (hex minúscula) del reporte **sanitizado y verificado** que reside en almacenamiento institucional autorizado;
- `executed_at_utc`: fecha ISO 8601 con zona horaria.

El campo `human_review=REVIEWED` registra que un revisor hizo la revisión **fuera de la herramienta**; no autoriza producción. Un SHA-256 anotado no demuestra que exista el archivo ni que el caso se haya ejecutado: las personas responsables deben revisar el artefacto original y su hash en el repositorio documental.

```bash
# Solo después de alimentar resultados genuinos de QA; inicial = 34 PENDING
python3 mcs-wallet-provider/tools/mtc_qa_e2e_evidence.py --assess \
  --local-report ./mtc_e0322_readiness_con_pg.json \
  --evidence ./mtc_qa_e0323/mtc_qa_e0323_evidencias.json \
  --report ./mtc_qa_e0323/mtc_qa_e0323_evaluacion.json
```

**Códigos de salida:** `0` únicamente si la plantilla se creó correctamente o si todos los casos están documentados con metadatos completos (aún pendiente revisión externa); `1` si hay escenarios `PENDING`, `FAIL`, `BLOCKED` o metadatos QA incompletos; `2` ante incongruencia estructural, evidencia faltante, riesgo de secreto o baseline inválido. Es **esperable** que `--assess` devuelva `1` mientras no se hayan ejecutado los casos E2E.

## 4. Etapas operativas propuestas, solo para QA autorizado

1. **Preparación:** Infraestructura confirma cuenta y red QA, rutas privadas, TLS, segregación de clientes/scopes Cognito y migraciones V1–V5 con respaldo.
2. **Acreditación:** usar dispositivo Android y identidades de ensayo autorizadas. Validar primer ingreso con ID Perú, repetición, reinstalación, cancelación y rechazo por identidad inconsistente.
3. **Atestación:** demostrar firma de posesión, cadena hardware confiable y relación registrada entre instalación y clave de credencial.
4. **Emisión:** contrastar `c_nonce` desde Certify con hash persistido en Provider y huella RFC7638 de la clave verificada. Emitir mDL y SD-JWT manteniendo el DNI por credencial.
5. **Negativos:** revocación, bloqueo, vencimiento, clave/nonce erróneos, cliente M2M equivocado, JWT inválido, Provider o PostgreSQL indisponibles: **ninguno debe emitir credenciales**.
6. **Compatibilidad y recuperación:** INJI Verify web, coexistencia mDL/SD-JWT y rollback de flags **únicamente en QA**; conservar registros y auditar cambios.

Cualquier acción que cambie configuraciones QA, revoque identidades de prueba o produzca indisponibilidad requiere ventana, autorización y procedimiento de reversión institucional. **La herramienta no ejecuta esas acciones**. Jamás usar ciudadanos reales, ambientes PRD ni secretos fuera del gestor aprobado.

## 5. Privacidad y seguridad del expediente

Los informes y plantillas se crean con permisos `0600` y sin sobrescritura. El evaluador no conserva logs completos, JWT, DNI, claves, correos ni evidencia biométrica. Rechaza patrones obvios de secretos, datos extra y referencias URL en los campos documentales. Este filtrado es preventivo, **no garantiza anonimización** de artefactos externos; todo soporte y toda validación de huellas debe hacerse en el sistema institucional protegido.

## 6. Interpretación de estados

| Resultado del evaluador | Significado |
|---|---|
| `QA_TESTS_PENDING` | Faltan escenarios E2E reales |
| `QA_TEST_FAILURES` | Al menos un caso falló; no homologar |
| `QA_EXECUTION_BLOCKED` | Hay escenarios bloqueados; no homologar |
| `QA_METADATA_INCOMPLETE` | Faltan revisiones o ticket de cambio |
| `QA_EVIDENCE_RECORDED_REQUIRES_INDEPENDENT_REVIEW` | Expediente completo en forma **declarativa**; exige contraste de cada prueba y aprobación institucional, no es certificación E2E |

En todos los casos: `qa_e2e_verified_by_tool=false`, `production_release=NOT_AUTHORIZED`.
