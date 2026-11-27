# MTC — Entrega 03.25: consolidación de avance QA y acciones pendientes

**Versión:** 03.25  
**Fecha:** 25/11/2026 (America/Lima)  
**Ámbito:** reporte documental local; no cambia lógica productiva, flags, infra ni bases de datos.  
**Dependencias:** E03.22 (`local_validation=PASS`, laboratorio PostgreSQL incluido), catálogo/expediente E03.23 y herramienta de registro E03.24.

## Objetivo

Ofrecer al responsable de homologación una vista reproducible del estado de los **34 casos**
distribuidos en **11 grupos**, sin editar JSON a mano ni inferir aprobación a partir de un
archivo de evidencia. La herramienta trabaja exclusivamente con información contenida
en los reportes del repositorio. No consulta AWS, Cognito, ID Perú, Wallet ni Provider.

## Entrada requerida

- Informe E03.22, habitualmente `mtc_e0322_readiness_con_pg.json`, que debe ser
  reciente conforme a la validación original E03.23 (máximo 14 días) y corresponder
  exactamente a las fuentes del checkout.
- Manifest QA vigente. El inicial es `mtc_qa_e0323/mtc_qa_e0323_evidencias.json`;
  tras la E03.24 se utiliza la **última versión no sobrescrita**, p. ej.
  `mtc_qa_e0323/expediente_qa_caso01.json`.
- Catálogo `tools/mtc_qa_e2e_cases.json` de E03.23. No se modifica ni se
  reemplaza por definiciones de prueba fabricadas.

## Ejecución

Desde la raíz del monorepositorio, después de aplicar el ZIP E03.25:

```bash
python3 -m unittest discover -s mcs-wallet-provider/tools/tests \
  -p test_mtc_qa_e2e_progress.py -v

python3 mcs-wallet-provider/tools/mtc_qa_e2e_progress.py \
  --local-report ./mtc_e0322_readiness_con_pg.json \
  --evidence ./mtc_qa_e0323/mtc_qa_e0323_evidencias.json \
  --out-dir ./mtc_qa_e0325_resumen_inicial
```

Para expedientes con resultados QA reales, indicar con `--evidence` la última
versión generada por `mtc_qa_e2e_register.py`. No reutilizar el directorio de
salida para el siguiente corte. Dos salidas, ambas con permisos `0600`:

1. `mtc_qa_e0325_avance.json`: estructura con totales, porcentajes,
   grupos, casos abiertos, acción sugerida y SHA-256 del expediente de entrada.
2. `mtc_qa_e0325_avance.md`: matriz legible por grupo y lista de casos
   pendientes, fallidos o bloqueados; no incluye los soportes originales.

Si existen datos incompletos o inconsistentes el programa sale con código `2`
y **no produce un informe aprobado**. Un informe válido puede incluir fallos,
bloqueos y pendientes; en tal caso la operación de reporte retorna código `0`
porque pudo resumir fielmente el expediente, **no porque QA haya aprobado**.

## Semántica exacta de métricas

- **Ejecutados declarados**: `PASS + FAIL + BLOCKED`. No certifica que una ejecución
  ocurrió realmente; solo contabiliza metadatos registrados.
- **PASS declarados**: casos con estado `PASS` y metadatos suficientes según E03.23.
- **Grupos**: exactamente los 11 grupos del catálogo de 34 casos, sin agregar
  prioridades arbitrarias ni alterar la obligatoriedad de ninguno.
- **Siguiente acción**: `RESOLVER_FALLOS` precede a `DESBLOQUEAR_ESCENARIOS`;
  después se comprueba configuración QA, ejecución de pendientes y revisión independiente.
- **FAIL/BLOCKED**: el reporte exige referencia, huella SHA-256 y fecha ISO 8601
  vigente (máximo 30 días). Un fallo o bloqueo sin soporte debe documentarse antes
  de ser considerado un resultado registrable.

## Controles y límites

1. Valida integridad y vigencia del readiness E03.22 y de las huellas de sus fuentes.
2. Reutiliza la comprobación estructural de E03.23, que rechaza casos ausentes,
   repetidos, estados inválidos, campos no previstos y diferencias de enlace al readiness.
3. Rechaza enlaces simbólicos de entrada y prohíbe sobrescribir reportes ya existentes.
4. No incorpora archivos de soporte, contenido de logs, DNI, tokens, URLs internas,
   claves privadas ni biometría. Solo registra referencias de casos y huellas de archivos.
5. La presencia de SHA-256 demuestra igualdad de bytes únicamente: **no prueba
   autenticidad, ejecución, vigencia del despliegue, ni validez del resultado**.
6. El informe señala de forma incondicional:
   `qa_e2e_verified_by_tool=false`, `evidence_integrity_independently_verified=false`
   y `production_release=NOT_AUTHORIZED`.

## Criterios de aceptación y estado de QA

**Pruebas de herramienta:** 29 escenarios unitarios sintéticos (pendientes,
fallidos, bloqueados, 34 PASS declarados, fuentes manipuladas, fechas caducadas,
expedientes incompletos, sobrescritura y outputs 0600), sin conexión a la red.

**Ejecución real QA:** los 34 escenarios permanecen PENDING según el expediente
inicial E03.23. Es necesaria la ejecución sobre ambiente QA **autorizado**,
por responsables institucionales y con evidencias revisadas. El reporte E03.25 no
habilita las políticas ni concede aprobación para PRD.

**Limitación temporal deliberada:** como E03.23 exige readiness E03.22 de hasta
14 días, un expediente conservado durante más tiempo no podrá evaluarse sin
reconciliar su baseline siguiendo un procedimiento institucional. No editar a mano
el hash del readiness ni omitir la validación para forzar la aprobación.
