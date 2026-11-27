#!/usr/bin/env python3
"""MTC E03.22: consolidated LOCAL release-readiness evidence, not QA/PRD E2E.

This program does not perform live QA tests, deploy, change feature flags or
handle any actual credentials. Commands run on a local checkout. A Docker lab
is opt-in, with its separate guard against non-ephemeral databases.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Mapping

PROTECTED_FLAGS = (
    "WALLET_IDENTITY_ENABLED", "WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED",
    "WALLET_IDENTITY_CREDENTIAL_BINDING_ENABLED", "WALLET_IDENTITY_CERTIFY_M2M_ENABLED",
    "MTC_CERTIFY_PROVIDER_ISSUANCE_REQUIRED", "WALLET_HOLDER_IDENTITY_REQUIRED",
    "MIMOTO_HOLDER_ISSUANCE_ENFORCEMENT_ENABLED",
)
REQUIRED_FILES = (
    "inji-wallet/jest.mtc.holder-identity.config.cjs",
    "mimoto-mtc/pom.xml",
    "mcs-wallet-provider/pom.xml",
    "inji-certify/pom.xml",
    "mcs-wallet-provider/tools/mtc_certify_m2m_preflight.py",
    "mcs-wallet-provider/tools/validate_credential_binding_db_lab.sh",
    "mcs-wallet-provider/src/main/resources/db/migration/V5__credential_key_issuance_binding.sql",
    "mcs-wallet-provider/src/main/java/pe/gob/mtc/walletprovider/identity/CredentialKeyBindingRegistry.java",
    "inji-certify/certify-service/src/main/java/io/mosip/certify/security/MtcCertifyProviderIssuanceGuard.java",
)
EVIDENCE_FILES = (
    "mcs-wallet-provider/src/main/resources/db/migration/V5__credential_key_issuance_binding.sql",
    "mcs-wallet-provider/src/main/java/pe/gob/mtc/walletprovider/identity/CredentialKeyBindingRegistry.java",
    "inji-certify/certify-service/src/main/java/io/mosip/certify/security/MtcCertifyProviderIssuanceGuard.java",
    "mcs-wallet-provider/tools/mtc_certify_m2m_preflight.py",
    "inji-wallet/jest.mtc.holder-identity.config.cjs",
)


@dataclass(frozen=True)
class Step:
    key: str
    description: str
    command: tuple[str, ...]
    parser: str
    timeout: int
    required_binary: str


@dataclass(frozen=True)
class Result:
    key: str
    status: str
    reason: str
    duration_ms: int = 0
    tests_run: int | None = None
    tests_skipped: int | None = None


def steps(include_postgres: bool) -> list[Step]:
    result = [
        Step("wallet_jest", "Wallet: identidad y cabeceras RENIEC",
             ("inji-wallet/node_modules/.bin/jest", "-c", "jest.mtc.holder-identity.config.cjs", "--runInBand"),
             "jest", 480, "node"),
        Step("mimoto_junit", "MiMoto: acreditación y autorización RENIEC",
             ("mvn", "-B", "-ntp", "-o", "-f", "mimoto-mtc/pom.xml",
              "-Dtest=MtcHolderEnrollmentControllerTest,ReniecAuthCodeControllerIdentityPolicyTest,MtcHolderIssuancePolicyTest", "test"),
             "maven", 900, "mvn"),
        Step("provider_verify", "Provider: pruebas de seguridad y registro V5",
             ("mvn", "-B", "-ntp", "-o", "-f", "mcs-wallet-provider/pom.xml", "clean", "verify"),
             "maven", 900, "mvn"),
        Step("certify_verify", "Certify: regresión completa y autorización de emisión",
             ("mvn", "-B", "-ntp", "-o", "-f", "inji-certify/pom.xml", "clean", "verify", "-Dgpg.skip=true"),
             "maven", 1200, "mvn"),
        Step("readiness_selftest", "Herramienta local: 17 controles de evidencia y aislamiento",
             ("python3", "-m", "unittest", "discover", "-s", "mcs-wallet-provider/tools/tests",
              "-p", "test_mtc_integrated_readiness.py", "-v"), "unittest", 60, "python3"),
        Step("preflight_python", "Preflight: tests sintéticos (sin red)",
             ("python3", "-m", "unittest", "discover", "-s", "mcs-wallet-provider/tools/tests",
              "-p", "test_mtc_certify_m2m_preflight.py", "-v"), "unittest", 60, "python3"),
        Step("preflight_offline", "Preflight: contratos locales entre componentes",
             ("python3", "mcs-wallet-provider/tools/mtc_certify_m2m_preflight.py", "--offline"),
             "offline", 60, "python3"),
    ]
    if include_postgres:
        result.append(Step("postgres_v5", "PostgreSQL 16: migraciones y casos negativos V1–V5",
                           ("bash", "mcs-wallet-provider/tools/validate_credential_binding_db_lab.sh"),
                           "postgres", 240, "bash"))
    return result


def validate_environment(env: Mapping[str, str]) -> list[str]:
    problems = []
    for name in PROTECTED_FLAGS:
        if env.get(name, "").strip().lower() in ("1", "true", "yes", "on"):
            problems.append(f"Flag de control obligatorio activo en entorno local: {name}")
    if any(k.startswith("MTC_E321_QA_") and v for k, v in env.items()):
        problems.append("Se detectaron variables del preflight QA. Retirarlas antes del laboratorio local")
    if env.get("AWS_PROFILE") or env.get("AWS_ACCESS_KEY_ID"):
        problems.append("Credenciales/perfil AWS presentes. Ejecutar en una shell local sin configuración AWS")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        problems.append("No ejecutar como root")
    return problems


def restricted_environment(env: Mapping[str, str]) -> dict[str, str]:
    """Avoid forwarding QA tokens, AWS credentials or institutional secrets to test processes."""
    block = re.compile(r"(SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE_KEY|AWS_|MTC_E321_|KUBECONFIG)", re.I)
    clean = {key: val for key, val in env.items() if not block.search(key)}
    clean["SPRING_CLOUD_CONFIG_ENABLED"] = "false"
    clean["AWS_EC2_METADATA_DISABLED"] = "true"
    clean["CI"] = "true"
    return clean


def source_evidence(repo: Path) -> dict[str, str]:
    return {name: hashlib.sha256((repo / name).read_bytes()).hexdigest()
            for name in EVIDENCE_FILES if (repo / name).is_file()}


def prerequisites(repo: Path, include_postgres: bool, binaries: Mapping[str, bool] | None = None) -> list[str]:
    missing = [f"Archivo obligatorio ausente: {name}" for name in REQUIRED_FILES if not (repo / name).is_file()]
    bins = binaries or {binary: shutil.which(binary) is not None for binary in ("mvn", "python3", "node", "bash")}
    for step in steps(include_postgres):
        if not bins.get(step.required_binary, False):
            missing.append(f"Herramienta ausente: {step.required_binary}")
    if not (repo / "inji-wallet/node_modules/.bin/jest").is_file():
        missing.append("Jest local ausente: instalar dependencias previamente, sin npx ni descarga automática")
    if include_postgres:
        if shutil.which("docker") is None:
            missing.append("Docker ausente")
        else:
            try:
                check = subprocess.run(("docker", "image", "inspect", "postgres:16-alpine"),
                                       capture_output=True, timeout=10, check=False)
                if check.returncode != 0:
                    missing.append("Imagen postgres:16-alpine ausente; se prohíbe descargar durante el control")
            except (OSError, subprocess.TimeoutExpired):
                missing.append("Docker/imagen local no disponible")
    return sorted(set(missing))


def result_from_output(step: Step, text: str, returncode: int, duration_ms: int) -> Result:
    """Do not forward arbitrary child output into evidence (may contain secrets)."""
    found: tuple[int, int, int, int] | None = None
    if step.parser == "maven":
        matches = re.findall(r"Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+),\s*Skipped:\s*(\d+)", text)
        if matches:
            found = tuple(map(int, matches[-1]))
        passed = returncode == 0 and "BUILD SUCCESS" in text and found is not None and found[0] > 0 and found[1] == found[2] == 0
    elif step.parser == "jest":
        m = re.search(r"Tests:\s*(\d+) passed,\s*(\d+) total", text)
        found = (int(m.group(2)), 0, 0, 0) if m else None
        passed = returncode == 0 and found is not None and found[0] > 0 and found[0] == int(m.group(1))
    elif step.parser == "unittest":
        m = re.search(r"Ran (\d+) tests? in", text)
        found = (int(m.group(1)), 0, 0, 0) if m else None
        passed = returncode == 0 and found is not None and found[0] > 0 and re.search(r"(?m)^OK\s*$", text) is not None
    elif step.parser == "offline":
        m = re.search(r"RESUMEN:\s*(\d+)/(\d+) comprobaciones aprobadas", text)
        found = (int(m.group(2)), 0, 0, 0) if m else None
        passed = returncode == 0 and m is not None and int(m.group(1)) == int(m.group(2)) and int(m.group(2)) > 0
    elif step.parser == "postgres":
        passed = returncode == 0 and "[OK] Migración V1–V5 y pruebas SQL V5 completadas" in text
    else:
        passed = False
    reason = "Validación completada" if passed else "Falló o no se encontró resumen verificable; revisar Maven/Jest localmente"
    return Result(step.key, "PASS" if passed else "FAIL", reason, duration_ms,
                  found[0] if found else None, found[3] if found else None)


def execute(step: Step, repo: Path, env: Mapping[str, str]) -> Result:
    command = list(step.command)
    if command[0].startswith("inji-wallet/"):
        command[0] = str(repo / command[0])
        cwd = repo / "inji-wallet"
    else:
        cwd = repo
    start = time.monotonic()
    try:
        process = subprocess.run(command, cwd=cwd, env=restricted_environment(env),
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, errors="replace", timeout=step.timeout, check=False)
        return result_from_output(step, process.stdout, process.returncode,
                                  round((time.monotonic() - start) * 1000))
    except subprocess.TimeoutExpired:
        return Result(step.key, "FAIL", "Tiempo máximo superado; ejecución local detenida",
                      round((time.monotonic() - start) * 1000))
    except OSError:
        return Result(step.key, "BLOCKED", "No se pudo lanzar el ejecutable requerido")


def build_report(repo: Path, results: list[Result], include_postgres: bool) -> dict:
    good = bool(results) and all(r.status == "PASS" for r in results)
    return {
        "schema": "mtc-local-readiness/1", "version": "03.22",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "local_validation": "PASS" if good else "NOT_PASS",
        "qa_e2e": "PENDING", "production_release": "NOT_AUTHORIZED",
        "postgres_lab_requested": include_postgres,
        "evidence_sha256": source_evidence(repo),
        "steps": [asdict(r) for r in results],
        "note": "Resultados locales; no incluyen información sensible ni logs en crudo. No acreditan E2E ni autorizan despliegue.",
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="MTC E03.22 - puerta LOCAL de preparación, no desplegable")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--plan", action="store_true", help="solo muestra el plan, modo predeterminado")
    group.add_argument("--run", action="store_true", help="ejecuta pruebas locales, nunca QA")
    p.add_argument("--with-postgres", action="store_true", help="incluye laboratorio Docker V1–V5 aislado")
    p.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2], help="raíz del checkout")
    p.add_argument("--report", type=Path, help="archivo JSON de evidencias, solo con --run")
    args = p.parse_args(argv)
    if args.report is not None and not args.run:
        p.error("--report requiere --run")
    repo = args.repo.resolve()
    issues = validate_environment(os.environ)
    if issues:
        for issue in issues:
            print("[BLOQUEADO] " + issue, file=sys.stderr)
        return 2
    if args.run:
        issues = prerequisites(repo, args.with_postgres)
        if issues:
            for issue in issues:
                print("[BLOQUEADO] " + issue)
            return 2
    print("MTC E03.22: control local; no se ejecutan pruebas QA ni cambios de configuración")
    selection = steps(args.with_postgres)
    if not args.run:
        for step in selection:
            print("[PLAN] " + step.key + ": " + step.description)
        if not args.with_postgres:
            print("[PLAN] PostgreSQL V1–V5 excluido; usar --with-postgres para incorporarlo")
        return 0
    results = []
    for step in selection:
        print("[EJECUTANDO] " + step.description, flush=True)
        outcome = execute(step, repo, os.environ)
        results.append(outcome)
        print("[" + outcome.status + "] " + step.key +
              (f" ({outcome.tests_run} pruebas, {outcome.tests_skipped} omitidas)" if outcome.tests_run is not None else ""),
              flush=True)
    report = build_report(repo, results, args.with_postgres)
    if args.report:
        destination = args.report.expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.chmod(destination, 0o600)
        print("[INFORME] " + str(destination))
    print("[RESULTADO] " + report["local_validation"] + "; E2E QA PENDING; PRD NOT_AUTHORIZED")
    return 0 if report["local_validation"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
