#!/usr/bin/env python3
"""MTC Entrega 03.23 — Evidencias documentales de homologación QA.

Sin red, sin AWS, sin credenciales, sin escritura en bases. Un informe completo
NO acredita E2E por sí mismo ni constituye autorización de despliegue PRD.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys

VERSION = "03.23"
LOCAL_REQUIRED = frozenset({"wallet_jest", "mimoto_junit", "provider_verify", "certify_verify",
                           "readiness_selftest", "preflight_python", "preflight_offline", "postgres_v5"})
COMPONENTS = ("wallet", "mimoto", "provider", "certify")
VALID_STATUS = {"PENDING", "PASS", "FAIL", "BLOCKED"}
SENSITIVE = re.compile(r"(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
                       r"\bBearer\s+[A-Za-z0-9._-]{10,}|"
                       r"\b(?:client_secret|password|private_key|access_token)\s*[\"\']?\s*[:=]\s*[\"\']?\s*\S+|"
                       r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
                       r"\bDNI\s*[:=]\s*\d{8}\b)", re.I)
REF = re.compile(r"[A-Z][A-Z0-9-]{3,63}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
RELEASE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{6,79}\Z")
CATALOG = Path(__file__).resolve().with_name("mtc_qa_e2e_cases.json")

class EvidenceError(Exception):
    pass


def _read_json(path: Path, *, max_size: int = 1_000_000) -> dict:
    try:
        if not path.is_file() or path.stat().st_size > max_size:
            raise EvidenceError("Archivo JSON ausente o demasiado grande")
        content = path.read_text(encoding="utf-8")
        if SENSITIVE.search(content):
            raise EvidenceError("Contenido potencialmente sensible: usar solo referencias y huellas")
        value = json.loads(content)
        if not isinstance(value, dict):
            raise EvidenceError("Estructura JSON no válida")
        return value
    except (OSError, UnicodeError, json.JSONDecodeError) as ex:
        raise EvidenceError("No se pudo leer el archivo JSON de evidencia") from ex


def _time(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError("timezone required")
        return result.astimezone(timezone.utc)
    except (AttributeError, ValueError) as ex:
        raise EvidenceError("Fecha no válida; se requiere ISO 8601 con zona horaria") from ex


def validate_local(local: dict, repo: Path, now: datetime | None = None) -> None:
    """Enlace al readiness realmente aprobado y a hashes de fuentes en checkout."""
    if local.get("schema") != "mtc-local-readiness/1" or local.get("version") != "03.22":
        raise EvidenceError("No corresponde al esquema de readiness 03.22")
    if (local.get("local_validation") != "PASS" or not local.get("postgres_lab_requested")
            or local.get("qa_e2e") != "PENDING" or local.get("production_release") != "NOT_AUTHORIZED"):
        raise EvidenceError("El readiness local no aprueba PostgreSQL o contiene estados no autorizados")
    executed = local.get("steps")
    if not isinstance(executed, list) or len(executed) != len(LOCAL_REQUIRED):
        raise EvidenceError("El readiness no contiene las ocho comprobaciones exigidas")
    found = {}
    for step in executed:
        if not isinstance(step, dict) or not isinstance(step.get("key"), str):
            raise EvidenceError("Paso local inválido")
        key = step["key"]
        if key in found or step.get("status") != "PASS":
            raise EvidenceError("Paso local duplicado o no aprobado")
        if key != "postgres_v5" and (not isinstance(step.get("tests_run"), int) or step["tests_run"] <= 0):
            raise EvidenceError("Faltan resultados verificables en un paso local")
        found[key] = step
    if set(found) != LOCAL_REQUIRED:
        raise EvidenceError("Faltan pasos obligatorios de la Entrega 03.22")
    evidence = local.get("evidence_sha256")
    if not isinstance(evidence, dict) or len(evidence) < 5:
        raise EvidenceError("Faltan huellas SHA256 de fuentes")
    for name, expected in evidence.items():
        if not isinstance(name, str) or not isinstance(expected, str) or not HEX.fullmatch(expected):
            raise EvidenceError("Huella de fuente inválida")
        target = PurePosixPath(name)
        if target.is_absolute() or ".." in target.parts or not name.startswith(("inji-wallet/", "mcs-wallet-provider/", "inji-certify/")):
            raise EvidenceError("Ruta de fuente fuera del repositorio")
        p = repo.joinpath(*target.parts)
        if not p.is_file() or p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest() != expected:
            raise EvidenceError("Las fuentes actuales no coinciden con el readiness local")
    now = now or datetime.now(timezone.utc)
    stamped = _time(local.get("created_at_utc", ""))
    if stamped > now + timedelta(minutes=5) or stamped < now - timedelta(days=14):
        raise EvidenceError("El reporte local expiró o tiene fecha futura; repetir E03.22")


def catalog_cases(catalog: dict) -> list[dict]:
    if catalog.get("schema") != "mtc-qa-catalog/1" or catalog.get("version") != VERSION:
        raise EvidenceError("Catálogo de homologación no corresponde a E03.23")
    cases = catalog.get("cases", [])
    if not isinstance(cases, list) or len(cases) < 25:
        raise EvidenceError("Catálogo incompleto")
    ids: set[str] = set()
    for c in cases:
        if not isinstance(c, dict) or not all(isinstance(c.get(k), str) and c[k].strip()
                    for k in ("id", "group", "title", "procedure", "expected")) or c.get("mandatory") is not True:
            raise EvidenceError("Caso de prueba sin definición obligatoria")
        if not re.fullmatch(r"QA-[A-Z]+-\d{2}", c["id"]) or c["id"] in ids:
            raise EvidenceError("Identificador de caso inválido o duplicado")
        ids.add(c["id"])
    return cases


def make_template(local_text: bytes, cases: list[dict], now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    return {
        "schema": "mtc-qa-evidence/1", "version": VERSION, "environment": "QA",
        "created_at_utc": now.isoformat(),
        "local_report_sha256": hashlib.sha256(local_text).hexdigest(),
        "change_ref": "", "qa_revisions": {component: "" for component in COMPONENTS},
        "cases": [{"id": c["id"], "status": "PENDING", "evidence_ref": "",
                   "evidence_sha256": "", "executed_at_utc": ""} for c in cases],
        "human_review": "PENDING",
    }


def matrix_md(cases: list[dict]) -> str:
    lines = ["# MTC — Matriz QA E2E · Entrega 03.23", "",
             "**Ámbito:** exclusivamente QA autorizado, dispositivos y identidades de prueba.",
             "**Estado inicial:** todos los escenarios pendientes. No habilita PRD.",
             "**Evidencia:** conservar los registros originales en repositorio institucional autorizado;",
             "registrar aquí solo ID del ticket y SHA-256 del extracto sanitizado.", "",
             "Cada caso PASS requiere referencia verificable, SHA-256 y fecha de ejecución;",
             "la herramienta comprueba completitud documental, NO ejecuta pruebas QA.", ""]
    last = ""
    for c in cases:
        if c["group"] != last:
            last = c["group"]
            lines.extend([f"## {last}", ""])
        lines.extend([f"### {c['id']} — {c['title']}", "",
                      f"**Procedimiento:** {c['procedure']}", "",
                      f"**Resultado exigido:** {c['expected']}", ""])
    lines.extend(["## Aprobación institucional", "",
                  "Un expediente íntegro documentalmente requiere revisión humana independiente,",
                  "evidencia E2E auténtica, revisión de segregación y autorización formal del MTC.",
                  "**No equivale a permiso de despliegue PRD.**", ""])
    return "\n".join(lines)


def assess(evidence: dict, raw_local: bytes, cases: list[dict], now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    if evidence.get("schema") != "mtc-qa-evidence/1" or evidence.get("version") != VERSION or evidence.get("environment") != "QA":
        raise EvidenceError("No es un manifiesto de homologación QA E03.23")
    if evidence.get("local_report_sha256") != hashlib.sha256(raw_local).hexdigest():
        raise EvidenceError("El expediente QA no corresponde al readiness local adjuntado")
    if evidence.get("human_review") not in ("PENDING", "REVIEWED"):
        raise EvidenceError("Estado de revisión no permitido")
    rev = evidence.get("qa_revisions")
    if not isinstance(rev, dict) or set(rev) != set(COMPONENTS):
        raise EvidenceError("Falta identificar las cuatro versiones de QA")
    all_revisions = all(isinstance(v, str) and RELEASE.fullmatch(v) for v in rev.values())
    change_ref = evidence.get("change_ref", "")
    good_change = isinstance(change_ref, str) and REF.fullmatch(change_ref)
    rows = evidence.get("cases")
    if not isinstance(rows, list) or len(rows) != len(cases):
        raise EvidenceError("El expediente QA debe contener exactamente todos los casos")
    index: dict[str,dict] = {}
    catalog_ids = {c["id"] for c in cases}
    for record in rows:
        if not isinstance(record, dict) or set(record) != {"id", "status", "evidence_ref", "evidence_sha256", "executed_at_utc"}:
            raise EvidenceError("Campos de caso inesperados: no incluir secretos ni datos personales")
        ident = record["id"]
        if not isinstance(ident, str) or ident not in catalog_ids or ident in index:
            raise EvidenceError("Caso desconocido o duplicado")
        if record["status"] not in VALID_STATUS:
            raise EvidenceError("Estado de caso QA inválido")
        if not all(isinstance(record[k],str) for k in ("evidence_ref","evidence_sha256","executed_at_utc")):
            raise EvidenceError("Metadatos documentales incorrectos")
        if record["status"] == "PASS":
            if not REF.fullmatch(record["evidence_ref"]) or not HEX.fullmatch(record["evidence_sha256"]):
                raise EvidenceError("PASS sin ticket y SHA-256 de evidencia sanitizada")
            stamp = _time(record["executed_at_utc"])
            if stamp > now + timedelta(minutes=5) or stamp < now - timedelta(days=30):
                raise EvidenceError("Fecha de ejecución QA inválida o caducada")
        elif any(record[k] for k in ("evidence_ref", "evidence_sha256", "executed_at_utc")) and \
                record["status"] == "PENDING":
            raise EvidenceError("Un caso PENDING no puede declararse ejecutado")
        index[ident] = record
    status_counts = {s: sum(r["status"] == s for r in rows) for s in ("PASS", "FAIL", "BLOCKED", "PENDING")}
    if status_counts["FAIL"]:
        outcome = "QA_TEST_FAILURES"
    elif status_counts["BLOCKED"]:
        outcome = "QA_EXECUTION_BLOCKED"
    elif status_counts["PENDING"]:
        outcome = "QA_TESTS_PENDING"
    elif not all_revisions or not good_change:
        outcome = "QA_METADATA_INCOMPLETE"
    else:
        outcome = "QA_EVIDENCE_RECORDED_REQUIRES_INDEPENDENT_REVIEW"
    return {
        "schema": "mtc-qa-assessment/1", "version": VERSION,
        "assessed_at_utc": now.isoformat(), "environment": "QA",
        "documentary_status": outcome, "case_counts": status_counts,
        "qa_e2e_verified_by_tool": False,
        "human_review_recorded": evidence["human_review"] == "REVIEWED",
        "evidence_integrity_independently_verified": False,
        "production_release": "NOT_AUTHORIZED",
        "note": "El registro documental y sus SHA-256 son declarativos. Revisar en repositorio institucional y validar E2E real antes de autorización externa.",
    }


def _write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.chmod(path, 0o600)
    except FileExistsError as ex:
        raise EvidenceError("El archivo destino ya existe. No se sobrescribió") from ex


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MTC E03.23: expediente de QA documental, sin red ni despliegue")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--init", action="store_true", help="iniciar matriz y expediente QA pendiente")
    mode.add_argument("--assess", action="store_true", help="evaluar completitud documental")
    parser.add_argument("--local-report", required=True, type=Path)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--out-dir", type=Path, help="destino de plantilla, con --init")
    parser.add_argument("--evidence", type=Path, help="evidencias editadas, con --assess")
    parser.add_argument("--report", type=Path, help="informe JSON, con --assess")
    args = parser.parse_args(argv)
    if args.init and (not args.out_dir or args.evidence or args.report):
        parser.error("--init requiere --out-dir y no admite --evidence/--report")
    if args.assess and (not args.evidence or not args.report or args.out_dir):
        parser.error("--assess requiere --evidence y --report")
    try:
        local_raw = args.local_report.read_bytes()
        if len(local_raw) > 1_000_000:
            raise EvidenceError("Informe local demasiado grande")
        local = _read_json(args.local_report)
        validate_local(local, args.repo.resolve())
        cases = catalog_cases(_read_json(CATALOG))
        if args.init:
            evidence = make_template(local_raw, cases)
            _write_new(args.out_dir / "mtc_qa_e0323_evidencias.json",
                       (json.dumps(evidence,ensure_ascii=False,indent=2)+"\n").encode())
            _write_new(args.out_dir / "mtc_qa_e0323_matriz.md", matrix_md(cases).encode())
            print(f"[OK] Matriz de QA generada: {len(cases)} casos, todos pendientes; sin llamadas a AWS")
            print("[ESTADO] QA PENDING; PRD NOT_AUTHORIZED")
            return 0
        evidence = _read_json(args.evidence)
        result = assess(evidence, local_raw, cases)
        _write_new(args.report, (json.dumps(result,ensure_ascii=False,indent=2)+"\n").encode())
        print("[CASOS] " + ", ".join(f"{k}={v}" for k,v in result["case_counts"].items()))
        print(f"[DOCUMENTAL] {result['documentary_status']}")
        print("[AUTORIZACION] E2E no verificado automáticamente; PRD NOT_AUTHORIZED")
        return 0 if result["documentary_status"] == "QA_EVIDENCE_RECORDED_REQUIRES_INDEPENDENT_REVIEW" else 1
    except (EvidenceError, OSError, UnicodeError) as ex:
        print("[BLOQUEADO] " + (str(ex) if isinstance(ex, EvidenceError) else "Error de lectura/escritura"), file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
