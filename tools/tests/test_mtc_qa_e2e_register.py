"""Pruebas del registro incremental E03.24 con datos completamente sintéticos."""
from datetime import datetime, timezone, timedelta
from pathlib import Path
import hashlib, json, sys, tempfile, unittest

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import mtc_qa_e2e_evidence as base
import mtc_qa_e2e_register as reg


class RegisterQaEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        sources = {}
        for i in range(5):
            name=f'inji-wallet/sample{i}.ts'
            path=self.repo/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(f'source-{i}')
            sources[name]=hashlib.sha256(path.read_bytes()).hexdigest()
        local = {'schema':'mtc-local-readiness/1','version':'03.22',
            'created_at_utc':self.now.isoformat(),'local_validation':'PASS',
            'postgres_lab_requested':True,'qa_e2e':'PENDING','production_release':'NOT_AUTHORIZED',
            'steps':[{'key':key,'status':'PASS','tests_run':None if key=='postgres_v5' else 2}
                     for key in sorted(base.LOCAL_REQUIRED)], 'evidence_sha256':sources}
        self.local_path=self.root/'local.json';self.local_path.write_text(json.dumps(local))
        self.cases=base.catalog_cases(base._read_json(base.CATALOG))
        self.evidence=base.make_template(self.local_path.read_bytes(),self.cases,now=self.now)
        self.change='MTCQA-20261125'
        self.versions={c:'0.14.0-mtc.1' for c in base.COMPONENTS}
        self.stamp=self.now.isoformat()
        self.artifact=self.root/'evidence.md'
        self.artifact.write_text('Escenario sintético de QA.\nResultado revisado para ensayo.\n')
        self.artifact.chmod(0o600)
        self.source_path=self.root/'evidence.json';self.source_path.write_text(json.dumps(self.evidence))
        self.out_path=self.root/'new.json'

    def configured(self): return reg.configure(self.evidence,self.change,self.versions)
    def write_support(self,content):
        self.artifact.write_text(content);self.artifact.chmod(0o600)
    def record_case(self,evidence=None,**kw):
        return reg.record(evidence or self.configured(),kw.pop('case_id','QA-ENV-01'),
              kw.pop('status','PASS'),kw.pop('ref','MTCQA-EXAMPLE-01'),
              kw.pop('executed_at_utc',self.stamp),kw.pop('digest','f'*64),
              now=self.now,**kw)

    def test_configure_valid(self):
        x=self.configured()
        self.assertEqual(x['change_ref'],self.change)
        self.assertEqual(set(x['qa_revisions']),set(base.COMPONENTS))
        self.assertEqual(self.evidence['change_ref'],'')

    def test_config_missing_version(self):
        with self.assertRaises(base.EvidenceError):reg.configure(self.evidence,self.change,{'wallet':'abcdef1234'})

    def test_config_invalid_version(self):
        v=dict(self.versions);v['certify']='x'
        with self.assertRaises(base.EvidenceError):reg.configure(self.evidence,self.change,v)

    def test_config_bad_ref(self):
        with self.assertRaises(base.EvidenceError):reg.configure(self.evidence,'https://example.com',self.versions)

    def test_config_twice_denied(self):
        with self.assertRaises(base.EvidenceError):reg.configure(self.configured(),self.change,self.versions)

    def test_config_reviewed_denied(self):
        x=dict(self.evidence);x['human_review']='REVIEWED'
        with self.assertRaises(base.EvidenceError):reg.configure(x,self.change,self.versions)

    def test_document_digest(self):
        sha,size=reg.read_sanitized_evidence(self.artifact)
        self.assertEqual(sha,hashlib.sha256(self.artifact.read_bytes()).hexdigest())
        self.assertEqual(size,self.artifact.stat().st_size)

    def test_document_dni_denied(self):
        self.write_support('Soporte con identificador de ciudadano 11223344\n')
        with self.assertRaises(base.EvidenceError):reg.read_sanitized_evidence(self.artifact)

    def test_document_email_denied(self):
        self.write_support('Soporte de ejemplo contacto foo@example.org\n')
        with self.assertRaises(base.EvidenceError):reg.read_sanitized_evidence(self.artifact)

    def test_document_token_denied(self):
        self.write_support('Authorization: Bearer abcdefghijklmnopq\n')
        with self.assertRaises(base.EvidenceError):reg.read_sanitized_evidence(self.artifact)

    def test_document_url_denied(self):
        self.write_support('Archivo de soporte https://qa.example.org/internal\n')
        with self.assertRaises(base.EvidenceError):reg.read_sanitized_evidence(self.artifact)

    def test_document_world_readable_denied(self):
        self.artifact.chmod(0o644)
        with self.assertRaises(base.EvidenceError):reg.read_sanitized_evidence(self.artifact)

    def test_document_symlink_denied(self):
        link=self.root/'shortcut.md';link.symlink_to(self.artifact)
        with self.assertRaises(base.EvidenceError):reg.read_sanitized_evidence(link)

    def test_document_binary_denied(self):
        self.artifact.write_bytes(b'\x00'*100)
        with self.assertRaises(base.EvidenceError):reg.read_sanitized_evidence(self.artifact)

    def test_document_oversize_denied(self):
        self.artifact.write_bytes(b'A'*(reg.MAX_DOCUMENT_BYTES+1))
        with self.assertRaises(base.EvidenceError):reg.read_sanitized_evidence(self.artifact)

    def test_document_pdf_denied(self):
        file=self.root/'bad.pdf';file.write_text('Documento sintético de QA');file.chmod(0o600)
        with self.assertRaises(base.EvidenceError):reg.read_sanitized_evidence(file)

    def test_record_pass_manual(self):
        x=self.record_case()
        self.assertEqual(x['cases'][0]['status'],'PASS')
        self.assertEqual(x['cases'][1]['status'],'PENDING')
        self.assertEqual(x['human_review'],'PENDING')
        self.assertEqual(base.assess(x,self.local_path.read_bytes(),self.cases,self.now)['case_counts']['PASS'],1)

    def test_record_fail_blocks(self):
        x=self.record_case(status='FAIL')
        self.assertEqual(base.assess(x,self.local_path.read_bytes(),self.cases,self.now)['documentary_status'],'QA_TEST_FAILURES')

    def test_record_pending_invalid(self):
        with self.assertRaises(base.EvidenceError):self.record_case(status='PENDING')

    def test_record_unknown_case(self):
        with self.assertRaises(base.EvidenceError):self.record_case(case_id='QA-FAKE-99')

    def test_record_without_config(self):
        with self.assertRaises(base.EvidenceError):self.record_case(evidence=self.evidence)

    def test_record_invalid_ticket(self):
        with self.assertRaises(base.EvidenceError):self.record_case(ref='invalid ticket')

    def test_record_future_time(self):
        with self.assertRaises(base.EvidenceError):self.record_case(executed_at_utc=(self.now+timedelta(hours=1)).isoformat())

    def test_record_old_time(self):
        with self.assertRaises(base.EvidenceError):self.record_case(executed_at_utc=(self.now-timedelta(days=31)).isoformat())

    def test_record_cannot_override(self):
        x=self.record_case(status='FAIL')
        with self.assertRaises(base.EvidenceError):self.record_case(evidence=x,ref='MTCQA-EXAMPLE-02')

    def test_retest_fail_to_pass(self):
        x=self.record_case(status='FAIL',executed_at_utc=(self.now-timedelta(days=1)).isoformat())
        result=self.record_case(evidence=x,ref='MTCQA-EXAMPLE-02',digest='e'*64,
                                retest=True,supersedes_ref='MTCQA-EXAMPLE-01')
        self.assertEqual(result['cases'][0]['status'],'PASS')

    def test_retest_wrong_prior_ticket(self):
        x=self.record_case(status='FAIL')
        with self.assertRaises(base.EvidenceError):self.record_case(evidence=x,ref='MTCQA-EXAMPLE-02',digest='e'*64,
                                                                    retest=True,supersedes_ref='MTCQA-WRONG')

    def test_retest_existing_pass_denied(self):
        x=self.record_case()
        with self.assertRaises(base.EvidenceError):self.record_case(evidence=x,ref='MTCQA-EXAMPLE-02',digest='e'*64,
                                                                    retest=True,supersedes_ref='MTCQA-EXAMPLE-01')

    def test_process_configure_then_record(self):
        reg.process('configure',self.local_path,self.source_path,self.out_path,self.repo,
                    change_ref=self.change,versions=self.versions)
        second=self.root/'record.json'
        result=reg.process('record',self.local_path,self.out_path,second,self.repo,
                           case_id='QA-ENV-01',status='PASS',ticket='MTCQA-EXAMPLE-01',
                           executed_at=self.stamp,support_file=self.artifact)
        self.assertEqual(result['case_counts']['PASS'],1)
        self.assertEqual(result['case_counts']['PENDING'],33)
        self.assertEqual(json.loads(self.out_path.read_text())['cases'][0]['status'],'PENDING')
        self.assertEqual(json.loads(second.read_text())['cases'][0]['status'],'PASS')
        self.assertEqual(second.stat().st_mode&0o777,0o600)
        self.assertEqual(result['production_release'],'NOT_AUTHORIZED')

    def test_process_cannot_overwrite(self):
        self.out_path.write_text('EXISTING')
        with self.assertRaises(base.EvidenceError):reg.process('configure',self.local_path,self.source_path,self.out_path,self.repo,
                                                            change_ref=self.change,versions=self.versions)
        self.assertEqual(self.out_path.read_text(),'EXISTING')

    def test_process_same_source_target_denied(self):
        with self.assertRaises(base.EvidenceError):reg.process('configure',self.local_path,self.source_path,self.source_path,self.repo,
                                                            change_ref=self.change,versions=self.versions)

    def test_process_baseline_tamper_denied(self):
        (self.repo/'inji-wallet/sample0.ts').write_text('tampered')
        with self.assertRaises(base.EvidenceError):reg.process('configure',self.local_path,self.source_path,self.out_path,self.repo,
                                                            change_ref=self.change,versions=self.versions)

    def test_cli_configure(self):
        args=['configure','--local-report',str(self.local_path),'--input',str(self.source_path),
              '--out',str(self.out_path),'--repo',str(self.repo),'--change-ref',self.change]
        for key in base.COMPONENTS:args.extend([f'--{key}-version',self.versions[key]])
        self.assertEqual(reg.main(args),0)
        self.assertTrue(self.out_path.exists())

    def test_cli_record(self):
        self.source_path.write_text(json.dumps(self.configured()))
        args=['record','--local-report',str(self.local_path),'--input',str(self.source_path),
              '--out',str(self.out_path),'--repo',str(self.repo),'--case-id','QA-ENV-01',
              '--status','PASS','--ticket','MTCQA-EXAMPLE-01',
              '--executed-at-utc',self.stamp,'--evidence-file',str(self.artifact)]
        self.assertEqual(reg.main(args),0)
        self.assertEqual(json.loads(self.out_path.read_text())['cases'][0]['status'],'PASS')

    def test_process_bad_ref_no_file(self):
        self.source_path.write_text(json.dumps(self.configured()))
        with self.assertRaises(base.EvidenceError):reg.process('record',self.local_path,self.source_path,self.out_path,self.repo,
                       case_id='QA-ENV-01',status='PASS',ticket='BAD REF',executed_at=self.stamp,support_file=self.artifact)
        self.assertFalse(self.out_path.exists())

    def test_source_unchanged(self):
        source_bytes=self.source_path.read_bytes()
        reg.process('configure',self.local_path,self.source_path,self.out_path,self.repo,
                    change_ref=self.change,versions=self.versions)
        self.assertEqual(self.source_path.read_bytes(),source_bytes)

if __name__=='__main__':unittest.main()
