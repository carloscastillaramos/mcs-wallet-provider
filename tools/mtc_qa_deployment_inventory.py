#!/usr/bin/env python3
"""E03.26: inventario QA declarativo + reglas de precedencia de flags.

No lee AWS, .env de servicios, Kubernetes, secretos, ni verifica despliegues.
Los metadatos introducidos son declaraciones del operador QA, no evidencia E2E.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

import mtc_qa_e2e_evidence as qa
import mtc_qa_e2e_register as registry

SCHEMA = 'mtc-qa-deployment-inventory/1'
VERSION = '03.26'
# Todos estos nombres están documentados en las entregas anteriores; no se
# recogen URLs, IDs Cognito, secretos ni rutas de infraestructura.
FLAGS = {
    'wallet': ('WALLET_HOLDER_IDENTITY_REQUIRED',),
    'mimoto': ('MIMOTO_HOLDER_EVIDENCE_ENABLED',
               'MIMOTO_PROVIDER_IDENTITY_M2M_ENABLED',
               'MIMOTO_HOLDER_ISSUANCE_ENFORCEMENT_ENABLED'),
    'provider': ('WALLET_IDENTITY_ENABLED', 'WALLET_COGNITO_ENABLED',
                 'WALLET_IDENTITY_MIMOTO_M2M_ENABLED',
                 'WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED',
                 'WALLET_IDENTITY_CREDENTIAL_BINDING_ENABLED',
                 'WALLET_IDENTITY_CERTIFY_M2M_ENABLED'),
    'certify': ('MTC_KEY_ATTESTATION_VALIDATION_ENABLED',
                'MTC_KEY_ATTESTATION_REQUIRED',
                'MTC_CERTIFY_PROVIDER_ISSUANCE_REQUIRED'),
}
ALL_FLAGS = tuple(name for fields in FLAGS.values() for name in fields)
REQUIRE = {
 'WALLET_IDENTITY_MIMOTO_M2M_ENABLED': ('WALLET_IDENTITY_ENABLED','WALLET_COGNITO_ENABLED'),
 'WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED': ('WALLET_IDENTITY_ENABLED',),
 'WALLET_IDENTITY_CREDENTIAL_BINDING_ENABLED': ('WALLET_IDENTITY_ENABLED','WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED'),
 'WALLET_IDENTITY_CERTIFY_M2M_ENABLED': ('WALLET_IDENTITY_ENABLED','WALLET_COGNITO_ENABLED',
   'WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED','WALLET_IDENTITY_CREDENTIAL_BINDING_ENABLED'),
 'MTC_KEY_ATTESTATION_REQUIRED': ('MTC_KEY_ATTESTATION_VALIDATION_ENABLED',),
 'MTC_CERTIFY_PROVIDER_ISSUANCE_REQUIRED': ('MTC_KEY_ATTESTATION_VALIDATION_ENABLED',
   'MTC_KEY_ATTESTATION_REQUIRED','WALLET_IDENTITY_CERTIFY_M2M_ENABLED',
   'WALLET_IDENTITY_CREDENTIAL_BINDING_ENABLED'),
 'MIMOTO_HOLDER_ISSUANCE_ENFORCEMENT_ENABLED': ('MIMOTO_HOLDER_EVIDENCE_ENABLED',
   'MIMOTO_PROVIDER_IDENTITY_M2M_ENABLED','WALLET_IDENTITY_ENABLED',
   'WALLET_IDENTITY_MIMOTO_M2M_ENABLED'),
 'WALLET_HOLDER_IDENTITY_REQUIRED': ('MIMOTO_HOLDER_ISSUANCE_ENFORCEMENT_ENABLED',
   'WALLET_IDENTITY_ENABLED'),
}
MAX_FLAGS_SIZE = 8192
ERROR_PREFIX = '[BLOQUEADO] '


def flags_template() -> str:
    lines = ['# MTC E03.26 - instantanea QA, declarar valores realmente observados.',
             '# UNRECORDED es intencional: no equivale a false.',
             '# No introducir secretos, client IDs, tokens, URLs ni direcciones.']
    for group, fields in FLAGS.items():
        lines.append('# '+group.upper())
        for field in fields:lines.append(f'{field}=UNRECORDED')
    return '\n'.join(lines)+'\n'


def _safe_regular(path: Path, max_size: int) -> bytes:
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise qa.EvidenceError('Debe ser archivo regular; enlaces simbólicos no permitidos')
    info=path.stat()
    if info.st_size <= 0 or info.st_size > max_size:
        raise qa.EvidenceError('Tamaño de archivo inválido')
    if info.st_mode & 0o077:
        raise qa.EvidenceError('Proteger archivo de configuración con chmod 600')
    raw=path.read_bytes()
    if len(raw) != info.st_size:
        raise qa.EvidenceError('El archivo cambió durante su lectura')
    return raw


def parse_flags(data: bytes) -> dict[str,bool]:
    try:
        text=data.decode('utf-8','strict')
    except UnicodeDecodeError as ex:
        raise qa.EvidenceError('Flags: se requiere texto UTF-8') from ex
    if len(data)>MAX_FLAGS_SIZE:
        raise qa.EvidenceError('Archivo de flags demasiado grande')
    if registry.PRIVATE_CONTENT.search(text) or qa.SENSITIVE.search(text):
        raise qa.EvidenceError('El archivo de flags contiene posibles secretos, URLs o datos personales')
    if '\x00' in text or '\r' in text:
        raise qa.EvidenceError('No se aceptan caracteres binarios ni CR')
    flags={}
    for n,line in enumerate(text.splitlines(),1):
        line=line.strip()
        if not line or line.startswith('#'):continue
        if not re.fullmatch(r'[A-Z][A-Z0-9_]*=(true|false|UNRECORDED)',line):
            raise qa.EvidenceError(f'Entrada {n} inválida: únicamente NOMBRE=true/false')
        name,value=line.split('=',1)
        if name not in ALL_FLAGS:
            raise qa.EvidenceError(f'Flag desconocida o no permitida: {name}')
        if name in flags:
            raise qa.EvidenceError(f'Flag duplicada: {name}')
        if value=='UNRECORDED':
            raise qa.EvidenceError(f'Falta verificar el valor real del flag: {name}')
        flags[name]=(value=='true')
    missing=set(ALL_FLAGS)-set(flags)
    if missing:
        raise qa.EvidenceError('Flags sin registrar: '+', '.join(sorted(missing)))
    return {name:flags[name] for name in ALL_FLAGS}


def contradictions(flags: dict[str,bool]) -> list[str]:
    if set(flags)!=set(ALL_FLAGS) or any(type(v) is not bool for v in flags.values()):
        raise qa.EvidenceError('Snapshot de flags incompleto o con tipos inválidos')
    errors=[]
    for enabled, prerequisites in REQUIRE.items():
        if not flags[enabled]:continue
        for p in prerequisites:
            if not flags[p]:errors.append(f'{enabled} exige {p}=true')
    return errors


def classification(flags: dict[str,bool]) -> str:
    problems=contradictions(flags)
    if problems:return 'DEPENDENCY_CONFLICT'
    if not any(flags.values()):return 'BASELINE_ALL_DISABLED'
    if flags['MTC_CERTIFY_PROVIDER_ISSUANCE_REQUIRED'] and flags['WALLET_HOLDER_IDENTITY_REQUIRED']:
        return 'ENFORCEMENT_CONFIGURED_QA_E2E_PENDING'
    return 'PARTIAL_STAGING_QA_E2E_PENDING'


def validate_inventory_fields(change_ref: str, versions: dict[str,str]) -> None:
    if not qa.REF.fullmatch(change_ref or ''):
        raise qa.EvidenceError('Ticket QA inválido: formato A-Z, 0-9 y guiones')
    if set(versions)!=set(qa.COMPONENTS) or not all(qa.RELEASE.fullmatch(v or '') for v in versions.values()):
        raise qa.EvidenceError('Faltan las cuatro revisiones QA válidas')


def inventory(flags: dict[str,bool], raw_flags: bytes,
              change_ref: str, versions: dict[str,str],
              raw_local: bytes, raw_evidence: bytes,
              created_at: datetime | None=None) -> dict:
    validate_inventory_fields(change_ref,versions)
    detected=contradictions(flags)
    created_at=created_at or datetime.now(timezone.utc)
    return {'schema':SCHEMA,'version':VERSION,'environment':'QA',
            'created_at_utc':created_at.isoformat(),
            'change_ref':change_ref, 'qa_revisions_declared':dict(versions),
            'flags_sha256':hashlib.sha256(raw_flags).hexdigest(),
            'local_readiness_sha256':hashlib.sha256(raw_local).hexdigest(),
            'qa_evidence_input_sha256':hashlib.sha256(raw_evidence).hexdigest(),
            'flags':{group:{key:flags[key] for key in names} for group,names in FLAGS.items()},
            'classification':classification(flags),'dependency_conflicts':detected,
            'source_of_values':'OPERATOR_DECLARED_NOT_CLOUD_VERIFIED',
            'cloud_deployment_confirmed_by_tool':False,
            'qa_e2e_verified_by_tool':False,
            'production_release':'NOT_AUTHORIZED'}


def markdown(report:dict) -> str:
    lines=['# MTC — Inventario y consistencia de flags QA · E03.26','',
       '**Alcance:** valores declarados; sin lectura de AWS ni verificación de despliegue.',
       f"**Cambio:** `{report['change_ref']}`",
       f"**Clasificación:** `{report['classification']}`",'',
       '| Componente | Revisión QA declarada |','|---|---|']
    for comp,v in report['qa_revisions_declared'].items():lines.append(f'| {comp} | `{v}` |')
    lines+=['','## Flags declarados','', '| Componente | Flag | Valor |', '|---|---|---|']
    for comp,values in report['flags'].items():
        for k,v in values.items():lines.append(f'| {comp} | `{k}` | `{str(v).lower()}` |')
    lines+=['','## Compatibilidad de precedencias','']
    if report['dependency_conflicts']:
        for issue in report['dependency_conflicts']:lines.append('- BLOQUEO: '+issue)
    else:lines.append('No se detectaron contradicciones entre los flags declarados.')
    lines+=['','## Advertencias','',
       'La ausencia de contradicciones **no demuestra** que Cognito, ID Perú,',
       'PostgreSQL o los microservicios funcionen. El cambio y las revisiones han sido',
       'introducidos manualmente; deben cotejarse con los artefactos de QA reales.',
       'La prueba de red y el E2E requieren autorización y ejecución separada.',
       '', '**QA E2E: PENDING. PRODUCCIÓN: NOT_AUTHORIZED.**','']
    return '\n'.join(lines)


def create_inventory(flag_file:Path, local_file:Path, qa_file:Path, output_dir:Path,
                     repo:Path, change_ref:str, versions:dict[str,str],
                     now:datetime|None=None) -> dict:
    raw_flags=_safe_regular(flag_file,MAX_FLAGS_SIZE)
    flags=parse_flags(raw_flags)
    raw_local=local_file.read_bytes()
    raw_qa=qa_file.read_bytes()
    if len(raw_local)>1_000_000 or len(raw_qa)>1_000_000:
        raise qa.EvidenceError('Informes de entrada demasiado grandes')
    local=qa._read_json(local_file)
    qa.validate_local(local,repo.resolve(),now=now)
    previous=qa._read_json(qa_file)
    cases=qa.catalog_cases(qa._read_json(qa.CATALOG))
    qa.assess(previous,raw_local,cases,now=now)
    result=inventory(flags,raw_flags,change_ref,versions,raw_local,raw_qa,created_at=now)
    if result['dependency_conflicts']:
        raise qa.EvidenceError('Incoherencias de flags QA: '+'; '.join(result['dependency_conflicts']))
    configured=registry.configure(previous,change_ref,versions)
    qa.assess(configured,raw_local,cases,now=now)
    files={
        output_dir/'mtc_qa_e0326_inventario.json':(json.dumps(result,indent=2,ensure_ascii=False)+'\n').encode('utf-8'),
        output_dir/'mtc_qa_e0326_inventario.md':markdown(result).encode('utf-8'),
        output_dir/'mtc_qa_e0326_evidencias_configuradas.json':(json.dumps(configured,indent=2,ensure_ascii=False)+'\n').encode('utf-8'),
    }
    for p in files:
        if p.exists() or p.is_symlink():raise qa.EvidenceError('Los destinos ya existen; conservar histórico en directorio nuevo')
        if p.resolve() in {flag_file.resolve(),local_file.resolve(),qa_file.resolve()}:
            raise qa.EvidenceError('No sobrescribir entradas')
    created=[]
    try:
        for path,data in files.items():
            qa._write_new(path,data)
            created.append(path)
    except Exception:
        for path in created:path.unlink(missing_ok=True)
        raise
    print('[INVENTARIO] '+str(output_dir/'mtc_qa_e0326_inventario.json'))
    print('[MATRIZ CONFIGURADA] '+str(output_dir/'mtc_qa_e0326_evidencias_configuradas.json'))
    print('[FLAGS] '+result['classification'])
    print('[CONTROL] Fuentes DECLARADAS; QA E2E PENDING; PRD NOT_AUTHORIZED')
    return result


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description='MTC E03.26: QA flags y revisiones, sin red ni secretos')
    sub=p.add_subparsers(dest='command',required=True)
    x=sub.add_parser('init-flags',help='Genera plantilla UNRECORDED (nunca presume false)')
    x.add_argument('--out',type=Path,required=True)
    x=sub.add_parser('check-flags',help='Evalúa precedencias de snapshot sanitizado')
    x.add_argument('--flags-file',type=Path,required=True)
    x=sub.add_parser('configure-qa',help='Genera reporte + expediente QA configurado y versionado')
    x.add_argument('--flags-file',type=Path,required=True)
    x.add_argument('--local-report',type=Path,required=True)
    x.add_argument('--evidence',type=Path,required=True)
    x.add_argument('--out-dir',type=Path,required=True)
    x.add_argument('--change-ref',required=True)
    x.add_argument('--repo',type=Path,default=Path(__file__).resolve().parents[2])
    for c in qa.COMPONENTS:x.add_argument(f'--{c}-version',required=True)
    a=p.parse_args(argv)
    try:
        if a.command=='init-flags':
            qa._write_new(a.out,flags_template().encode('utf-8'))
            print('[PLANTILLA] '+str(a.out))
            print('[ATENCION] UNRECORDED no representa un valor real de AWS')
        elif a.command=='check-flags':
            flags=parse_flags(_safe_regular(a.flags_file,MAX_FLAGS_SIZE))
            issues=contradictions(flags)
            if issues:raise qa.EvidenceError('; '.join(issues))
            print('[FLAGS] '+classification(flags))
            print('[CONTROL] Valores declarados, sin consulta AWS; QA E2E PENDING')
        else:
            versions={c:getattr(a,f'{c}_version') for c in qa.COMPONENTS}
            create_inventory(a.flags_file,a.local_report,a.evidence,a.out_dir,a.repo,
                             a.change_ref,versions)
        return 0
    except (qa.EvidenceError,OSError,ValueError,TypeError,KeyError) as ex:
        print(ERROR_PREFIX+(str(ex) if isinstance(ex,qa.EvidenceError) else
                             'Datos o archivos inválidos; no se generó autorización'),file=sys.stderr)
        return 2

if __name__=='__main__':sys.exit(main())
