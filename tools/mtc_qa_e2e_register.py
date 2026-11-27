#!/usr/bin/env python3
"""MTC E03.24: registro incremental verificable de evidencias QA, solo local.

Cada operación escribe un manifiesto nuevo. Nunca decide que un escenario fue PASS,
no examina sistemas QA y jamás otorga autorización de despliegue.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

import mtc_qa_e2e_evidence as base

VERSION = "03.24"
MAX_DOCUMENT_BYTES = 65536
ALLOWED_EXTENSIONS = {".txt", ".md", ".json"}
# Detección conservadora: se requieren soportes previamente anonimizados.
PRIVATE_CONTENT = re.compile(
    r"(?:\b[0-9]{8}\b|"          # posibles DNI, incluso sin etiqueta
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|"
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
    r"-----BEGIN [^-]+-----|"
    r"\b(?:authorization|cookie|set-cookie)\s*[:=]|"
    r"\b(?:client_secret|password|refresh_token|access_token|private_key)\s*[:=]|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|"
    r"https?://\S+|"               # URLs pueden incorporar tokens o PII
    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)",
    re.IGNORECASE,
)


def read_secure_json(path: Path) -> dict:
    if path.is_symlink():
        raise base.EvidenceError("No se aceptan archivos JSON simbólicos")
    return base._read_json(path)


def read_sanitized_evidence(path: Path) -> tuple[str, int]:
    """Calcula SHA-256 de un soporte local de texto minimizado, nunca lo copia."""
    try:
        if path.suffix.lower() not in ALLOWED_EXTENSIONS or path.is_symlink():
            raise base.EvidenceError("El soporte debe ser texto/Markdown/JSON regular, no enlace")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or not (20 <= info.st_size <= MAX_DOCUMENT_BYTES):
            raise base.EvidenceError("Soporte inexistente, vacío, binario o de tamaño no autorizado")
        if info.st_mode & 0o077:
            raise base.EvidenceError("Proteger el soporte sanitizado con chmod 600 antes de registrarlo")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as fp:
            opened = os.fstat(fp.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_ino != info.st_ino
                    or opened.st_dev != info.st_dev or opened.st_mode & 0o077):
                raise base.EvidenceError("El soporte cambió o no tiene permisos privados")
            raw = fp.read(MAX_DOCUMENT_BYTES + 1)
        if len(raw) != info.st_size:
            raise base.EvidenceError("El soporte cambió mientras se calculaba su huella")
        content = raw.decode("utf-8")
        if any(ord(ch) < 32 and ch not in "\n\r\t" for ch in content):
            raise base.EvidenceError("El soporte debe ser texto sin caracteres binarios")
        if PRIVATE_CONTENT.search(content) or base.SENSITIVE.search(content):
            raise base.EvidenceError("Posibles datos personales/secretos o URLs: sanitizar el soporte")
        return hashlib.sha256(raw).hexdigest(), len(raw)
    except (UnicodeError, OSError) as ex:
        raise base.EvidenceError("No se puede leer el soporte de evidencia") from ex


def configure(evidence: dict, change_ref: str, versions: dict[str, str]) -> dict:
    if evidence.get("human_review") != "PENDING":
        raise base.EvidenceError("La revisión humana es externa; no modificar expedientes revisados")
    if evidence.get("change_ref") or any(evidence.get("qa_revisions", {}).values()):
        raise base.EvidenceError("Versiones o ticket ya configurados: crear otro expediente si cambió el despliegue")
    if not base.REF.fullmatch(change_ref):
        raise base.EvidenceError("Referencia de cambio QA inválida")
    if set(versions) != set(base.COMPONENTS) or not all(base.RELEASE.fullmatch(v or "") for v in versions.values()):
        raise base.EvidenceError("Registrar las cuatro revisiones QA no vacías")
    result = json.loads(json.dumps(evidence))
    result["change_ref"] = change_ref
    result["qa_revisions"] = dict(versions)
    return result


def record(evidence: dict, case_id: str, status: str, ref: str,
           executed_at_utc: str, evidence_sha256: str,
           now: datetime | None = None, *, retest: bool = False, supersedes_ref: str | None = None) -> dict:
    """La evaluación es un acto del operador; el archivo NO infiere PASS/FAIL."""
    now = now or datetime.now(timezone.utc)
    if evidence.get("human_review") != "PENDING":
        raise base.EvidenceError("No modificar un expediente sometido a revisión humana")
    if not evidence.get("change_ref") or not all(evidence.get("qa_revisions", {}).get(x) for x in base.COMPONENTS):
        raise base.EvidenceError("Configurar antes el cambio y las cuatro versiones QA")
    if status not in {"PASS", "FAIL", "BLOCKED"}:
        raise base.EvidenceError("El estado debe ser declarado explícitamente como PASS, FAIL o BLOCKED")
    if not base.REF.fullmatch(ref) or not base.HEX.fullmatch(evidence_sha256):
        raise base.EvidenceError("Ticket y SHA-256 de soporte inválidos")
    stamp = base._time(executed_at_utc)
    if stamp < now - timedelta(days=30) or stamp > now + timedelta(minutes=5):
        raise base.EvidenceError("Fecha QA anterior a 30 días o posterior al momento actual")
    result = json.loads(json.dumps(evidence))
    target = next((r for r in result["cases"] if r["id"] == case_id), None)
    if target is None:
        raise base.EvidenceError("Caso no incluido en el catálogo QA")
    if target["status"] != "PENDING":
        if not retest or supersedes_ref != target["evidence_ref"]:
            raise base.EvidenceError("Caso ya ejecutado; para retest indicar --retest y el ticket sustituido")
        if target["status"] == "PASS":
            raise base.EvidenceError("Un PASS previo requiere un expediente nuevo para corrección")
        if ref == target["evidence_ref"] or evidence_sha256 == target["evidence_sha256"]:
            raise base.EvidenceError("El retest exige ticket y soporte diferentes")
        if stamp <= base._time(target["executed_at_utc"]):
            raise base.EvidenceError("El retest debe tener una fecha posterior a la prueba original")
    elif retest:
        raise base.EvidenceError("No indicar retest sobre un caso PENDING")
    target.update(status=status, evidence_ref=ref,
                  evidence_sha256=evidence_sha256, executed_at_utc=stamp.isoformat())
    return result


def process(command: str, local_report: Path, source: Path, target: Path, repo: Path,
            *, change_ref: str | None = None, versions: dict | None = None,
            case_id: str | None = None, status: str | None = None,
            ticket: str | None = None, executed_at: str | None = None,
            support_file: Path | None = None, retest: bool = False,
            supersedes_ref: str | None = None) -> dict:
    if source.resolve() == target.resolve():
        raise base.EvidenceError("Origen y destino deben ser distintos; prohibido sobrescribir")
    raw_local = local_report.read_bytes()
    if len(raw_local) > 1_000_000:
        raise base.EvidenceError("El reporte local supera el límite admitido")
    local = read_secure_json(local_report)
    base.validate_local(local, repo.resolve())
    cases = base.catalog_cases(base._read_json(base.CATALOG))
    previous = read_secure_json(source)
    base.assess(previous, raw_local, cases)
    if command == "configure":
        next_manifest = configure(previous, change_ref, versions)
    elif command == "record":
        if not support_file:
            raise base.EvidenceError("Para registrar se requiere soporte sanitizado")
        digest, byte_count = read_sanitized_evidence(support_file)
        next_manifest = record(previous, case_id, status, ticket, executed_at, digest,
                               retest=retest, supersedes_ref=supersedes_ref)
    else:
        raise base.EvidenceError("Operación desconocida")
    assessment = base.assess(next_manifest, raw_local, cases)
    serialized = (json.dumps(next_manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    base._write_new(target, serialized)
    print("[EXPEDIENTE] " + str(target))
    print("[INTEGRIDAD] entrada_sha256=" + hashlib.sha256(source.read_bytes()).hexdigest())
    print("[INTEGRIDAD] salida_sha256=" + hashlib.sha256(serialized).hexdigest())
    if command == "record":
        print(f"[SOPORTE] SHA256={digest}; bytes={byte_count}; caso={case_id}; resultado declarado={status}")
    print("[DOCUMENTAL] " + assessment["documentary_status"])
    print("[SEGURIDAD] Sin conexión QA, sin certificación E2E, PRD NOT_AUTHORIZED")
    return assessment


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MTC E03.24 — registro manual versionado de QA; sin red")
    subs = parser.add_subparsers(dest="command", required=True)
    for name in ("configure", "record"):
        sub = subs.add_parser(name)
        sub.add_argument("--local-report", required=True, type=Path)
        sub.add_argument("--input", required=True, type=Path)
        sub.add_argument("--out", required=True, type=Path)
        sub.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
        if name == "configure":
            sub.add_argument("--change-ref", required=True)
            for component in base.COMPONENTS:
                sub.add_argument(f"--{component}-version", required=True)
        else:
            sub.add_argument("--case-id", required=True)
            sub.add_argument("--status", required=True, choices=("PASS", "FAIL", "BLOCKED"))
            sub.add_argument("--ticket", required=True)
            sub.add_argument("--executed-at-utc", required=True)
            sub.add_argument("--evidence-file", required=True, type=Path)
            sub.add_argument("--retest", action="store_true")
            sub.add_argument("--supersedes-ticket")
    args = parser.parse_args(argv)
    try:
        if args.command == "configure":
            process("configure", args.local_report, args.input, args.out, args.repo,
                    change_ref=args.change_ref,
                    versions={c:getattr(args,f"{c}_version") for c in base.COMPONENTS})
        else:
            process("record", args.local_report, args.input, args.out, args.repo,
                    case_id=args.case_id, status=args.status, ticket=args.ticket,
                    executed_at=args.executed_at_utc,
                    support_file=args.evidence_file, retest=args.retest,
                    supersedes_ref=args.supersedes_ticket)
        return 0
    except (base.EvidenceError, OSError, ValueError, KeyError, TypeError) as ex:
        print("[BLOQUEADO] " + (str(ex) if isinstance(ex, base.EvidenceError)
                               else "Entrada o archivo no válido"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
