#!/usr/bin/env python3
"""MTC E03.25: reporte de avance documental QA, exclusivamente lectura local.

Valida la procedencia E03.22, el catalogo E03.23 y el expediente generado
por E03.23/E03.24. Un registro PASS es declarativo, nunca prueba E2E real.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import stat
import sys

import mtc_qa_e2e_evidence as qa

SCHEMA = "mtc-qa-progress/1"
VERSION = "03.25"
ORDER = ("PASS", "FAIL", "BLOCKED", "PENDING")


def read_regular_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise qa.EvidenceError("Se requieren archivos JSON regulares; enlaces simbólicos rechazados")
    return qa._read_json(path)


def calculate(local_bytes: bytes, evidence_bytes: bytes,
              local: dict, evidence: dict, catalog: list[dict],
              repo: Path, now: datetime | None = None) -> dict:
    """Calcula grupos y acciones, tras todas las validaciones del proyecto."""
    now = now or datetime.now(timezone.utc)
    qa.validate_local(local, repo, now=now)
    assessment = qa.assess(evidence, local_bytes, catalog, now=now)

    by_id = {item["id"]: item for item in evidence["cases"]}
    groups: dict[str, dict] = {}
    open_cases: list[dict] = []
    missing_docs: list[str] = []
    stamps: list[datetime] = []
    for c in catalog:
        item = by_id[c["id"]]
        status = item["status"]
        if status != "PENDING":
            # 03.23 exige metadatos completos solo para PASS; para un resumen
            # operativo también se exige evidencia para FAIL y BLOCKED.
            if (not qa.REF.fullmatch(item["evidence_ref"])
                    or not qa.HEX.fullmatch(item["evidence_sha256"])
                    or not item["executed_at_utc"]):
                missing_docs.append(c["id"])
            else:
                try:
                    instant = qa._time(item["executed_at_utc"])
                    if instant > now + timedelta(minutes=5) or instant < now - timedelta(days=30):
                        missing_docs.append(c["id"])
                    else:
                        stamps.append(instant)
                except qa.EvidenceError:
                    missing_docs.append(c["id"])
        g = groups.setdefault(c["group"], {"group": c["group"], "total": 0,
                                                 "counts": {s: 0 for s in ORDER}})
        g["total"] += 1
        g["counts"][status] += 1
        if status != "PASS":
            open_cases.append({"id": c["id"], "group": c["group"],
                               "status": status, "title": c["title"]})
    totals = assessment["case_counts"]
    if missing_docs:
        # No producir un reporte con fallos documentados a medias: esos
        # expedientes requieren regularización, no pueden sumar ejecuciones.
        raise qa.EvidenceError("Registros FAIL/BLOCKED sin evidencia completa o fecha vigente: "
                               + ", ".join(missing_docs))
    total = len(catalog)
    all_configured = (bool(evidence.get("change_ref"))
                      and all(evidence.get("qa_revisions", {}).values()))
    executed = total - totals["PENDING"]
    passed = totals["PASS"]
    if totals["FAIL"]:
        next_action = "RESOLVER_FALLOS"
    elif totals["BLOCKED"]:
        next_action = "DESBLOQUEAR_ESCENARIOS"
    elif not all_configured:
        next_action = "REGISTRAR_VERSIONES_QA"
    elif totals["PENDING"]:
        next_action = "EJECUTAR_ESCENARIOS_PENDIENTES"
    else:
        next_action = "SOLICITAR_REVISION_INDEPENDIENTE"

    return {
        "schema": SCHEMA, "version": VERSION,
        "generated_at_utc": now.isoformat(),
        "environment": "QA",
        "local_report_sha256": hashlib.sha256(local_bytes).hexdigest(),
        "qa_manifest_sha256": hashlib.sha256(evidence_bytes).hexdigest(),
        "qa_catalog_sha256": hashlib.sha256(qa.CATALOG.read_bytes()).hexdigest(),
        "change_ref_present": all_configured,
        "qa_revisions_recorded": all_configured,
        "cases_total": total,
        "case_counts": {s: totals[s] for s in ORDER},
        "executed_cases": executed,
        "executed_percent": round(100.0 * executed / total, 1),
        "passed_cases": passed,
        "passed_percent": round(100.0 * passed / total, 1),
        "groups": list(groups.values()),
        "open_cases": open_cases,
        "most_recent_evidence_at_utc": max(stamps).isoformat() if stamps else None,
        "documentary_status": assessment["documentary_status"],
        "next_action": next_action,
        "human_review_recorded": assessment["human_review_recorded"],
        "qa_e2e_verified_by_tool": False,
        "evidence_integrity_independently_verified": False,
        "production_release": "NOT_AUTHORIZED",
    }


def markdown(report: dict) -> str:
    c = report["case_counts"]
    lines = ["# MTC — Avance documental de homologación QA · E03.25", "",
             f"**Corte UTC:** {report['generated_at_utc']}",
             "**Entorno:** QA documental; sin conexión a sistemas externos.",
             f"**Expediente SHA-256:** `{report['qa_manifest_sha256']}`", "",
             "## Resumen", "",
             f"- Casos obligatorios: **{report['cases_total']}**.",
             f"- Ejecutados declarados: **{report['executed_cases']}** ({report['executed_percent']}%).",
             f"- PASS declarados: **{c['PASS']}** ({report['passed_percent']}%).",
             f"- FAIL: **{c['FAIL']}**; BLOCKED: **{c['BLOCKED']}**; PENDING: **{c['PENDING']}**.",
             f"- Estado documental: `{report['documentary_status']}`.",
             f"- Acción requerida: `{report['next_action']}`.", "",
             "## Avance por grupo", "",
             "| Grupo | Total | PASS | FAIL | BLOCKED | PENDING |",
             "|---|---:|---:|---:|---:|---:|"]
    for g in report["groups"]:
        x = g["counts"]
        lines.append(f"| {g['group']} | {g['total']} | {x['PASS']} | {x['FAIL']} | {x['BLOCKED']} | {x['PENDING']} |")
    lines.extend(["", "## Casos que requieren atención", ""])
    if not report["open_cases"]:
        lines.append("No hay casos abiertos documentales; se requiere revisión independiente.")
    else:
        lines.extend(["| Caso | Grupo | Estado | Descripción |", "|---|---|---|---|"])
        for item in report["open_cases"]:
            # Título procede del catálogo de QA, no de un campo editable.
            lines.append(f"| {item['id']} | {item['group']} | {item['status']} | {item['title']} |")
    lines.extend(["", "## Límites y decisión institucional", "",
                  "Los resultados son **declaraciones registradas en un expediente**. Las huellas",
                  "SHA-256 permiten comparar bytes, pero no demuestran que la prueba E2E ocurrió,",
                  "que su resultado fue correcto ni que el soporte original es auténtico.", "",
                  "**QA E2E VERIFICADO POR HERRAMIENTA: NO.**",
                  "**PRODUCCIÓN: NOT_AUTHORIZED.**", "",
                  "No se incluyen DNI, tokens, direcciones internas, evidencias completas ni secretos.", ""])
    return "\n".join(lines)


def process(local_report: Path, evidence_file: Path, output_dir: Path,
            repo: Path, now: datetime | None = None) -> dict:
    inputs = (local_report, evidence_file)
    for p in inputs:
        if p.is_symlink() or not p.is_file() or not stat.S_ISREG(p.stat().st_mode):
            raise qa.EvidenceError("Los informes de entrada deben ser archivos regulares")
    local_bytes = local_report.read_bytes()
    evidence_bytes = evidence_file.read_bytes()
    if len(local_bytes) > 1_000_000 or len(evidence_bytes) > 1_000_000:
        raise qa.EvidenceError("Archivo de entrada supera límite permitido")
    local = read_regular_json(local_report)
    evidence = read_regular_json(evidence_file)
    catalog = qa.catalog_cases(read_regular_json(qa.CATALOG))
    report = calculate(local_bytes, evidence_bytes, local, evidence, catalog, repo.resolve(), now=now)
    json_path = output_dir / "mtc_qa_e0325_avance.json"
    md_path = output_dir / "mtc_qa_e0325_avance.md"
    if json_path.exists() or md_path.exists() or json_path.is_symlink() or md_path.is_symlink():
        raise qa.EvidenceError("El informe ya existe; indicar un directorio nuevo para conservar versiones")
    if json_path.resolve() in [p.resolve() for p in inputs] or md_path.resolve() in [p.resolve() for p in inputs]:
        raise qa.EvidenceError("El destino no puede coincidir con las fuentes")
    json_data = (json.dumps(report, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    md_data = markdown(report).encode("utf-8")
    qa._write_new(json_path, json_data)
    try:
        qa._write_new(md_path, md_data)
    except Exception:
        # Solo retirar el archivo que acabamos de crear en esta operación.
        json_path.unlink(missing_ok=True)
        raise
    print(f"[REPORTE] {json_path}")
    print(f"[MATRIZ] {md_path}")
    print(f"[AVANCE] PASS={report['case_counts']['PASS']} / {report['cases_total']}; "
          f"FAIL={report['case_counts']['FAIL']}; BLOCKED={report['case_counts']['BLOCKED']}; "
          f"PENDING={report['case_counts']['PENDING']}")
    print(f"[ACCION] {report['next_action']}")
    print("[CONTROL] QA E2E NO VERIFICADO POR HERRAMIENTA; PRD NOT_AUTHORIZED")
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="MTC E03.25: avance QA documental sin red ni despliegue")
    p.add_argument("--local-report", type=Path, required=True)
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    args = p.parse_args(argv)
    try:
        process(args.local_report, args.evidence, args.out_dir, args.repo)
        return 0
    except (qa.EvidenceError, OSError, TypeError, ValueError, KeyError) as ex:
        print("[BLOQUEADO] " + (str(ex) if isinstance(ex, qa.EvidenceError)
                               else "No se pudo validar el expediente o escribir los informes"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
