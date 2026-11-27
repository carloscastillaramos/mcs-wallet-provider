"""Contratos locales E03.26: entradas sintéticas, sin red, AWS ni cambios de QA."""
from __future__ import annotations
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,sys,tempfile,unittest
TOOLS=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TOOLS))
import mtc_qa_e2e_evidence as qa
import mtc_qa_deployment_inventory as inv

class QaInventoryTests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.addCleanup(self.td.cleanup)
        self.root=Path(self.td.name)
        self.flags={k:False for k in inv.ALL_FLAGS}
        self.now=datetime.now(timezone.utc).replace(microsecond=0)
        self.change='MTCQA-20261125'
        self.versions={c:'0.14.0-mtc.1' for c in qa.COMPONENTS}
        self.flags_path=self.root/'flags.env'
        self.write_flags()
        self.repo=self.root/'repo';self.repo.mkdir()
        hashes={}
        for i in range(5):
            relative=f'inji-wallet/t{i}.ts'
            path=self.repo/relative;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('sample'+str(i),encoding='utf-8')
            hashes[relative]=hashlib.sha256(path.read_bytes()).hexdigest()
        local={'schema':'mtc-local-readiness/1','version':'03.22',
               'created_at_utc':self.now.isoformat(),'local_validation':'PASS',
               'postgres_lab_requested':True,'qa_e2e':'PENDING','production_release':'NOT_AUTHORIZED',
               'steps':[{'key':key,'status':'PASS','tests_run':None if key=='postgres_v5' else 2}
                        for key in sorted(qa.LOCAL_REQUIRED)],'evidence_sha256':hashes}
        self.local=self.root/'readiness.json';self.local.write_text(json.dumps(local))
        evidence=qa.make_template(self.local.read_bytes(),qa.catalog_cases(qa._read_json(qa.CATALOG)),now=self.now)
        self.evidence=self.root/'evidence.json';self.evidence.write_text(json.dumps(evidence))
        self.out=self.root/'out'
    def write_flags(self,vals=None):
        values=vals or self.flags
        self.flags_path.write_text('\n'.join(f'{k}={str(v).lower()}' for k,v in values.items())+'\n')
        self.flags_path.chmod(0o600)
    def process(self):
        return inv.create_inventory(self.flags_path,self.local,self.evidence,self.out,
                                    self.repo,self.change,self.versions,now=self.now)
    def test_template_all_unrecorded(self):
        x=inv.flags_template();self.assertEqual(x.count('=UNRECORDED'),len(inv.ALL_FLAGS))
    def test_template_does_not_claim_false(self):
        self.assertNotIn('=false',inv.flags_template())
    def test_all_flags_unique(self):self.assertEqual(len(inv.ALL_FLAGS),len(set(inv.ALL_FLAGS)))
    def test_parse_valid_false(self):self.assertEqual(inv.parse_flags(self.flags_path.read_bytes()),self.flags)
    def test_parse_unknown(self):
        with self.assertRaises(qa.EvidenceError):inv.parse_flags(self.flags_path.read_bytes()+b'EVIL_FLAG=true\n')
    def test_parse_missing(self):
        lines=self.flags_path.read_text().splitlines()
        with self.assertRaises(qa.EvidenceError):inv.parse_flags(('\n'.join(lines[:-1])+'\n').encode())
    def test_parse_duplicate(self):
        with self.assertRaises(qa.EvidenceError):inv.parse_flags(self.flags_path.read_bytes()+b'WALLET_IDENTITY_ENABLED=true\n')
    def test_parse_unrecorded(self):
        with self.assertRaises(qa.EvidenceError):inv.parse_flags(inv.flags_template().encode())
    def test_parse_refuse_secret(self):
        with self.assertRaises(qa.EvidenceError):inv.parse_flags(self.flags_path.read_bytes()+b'CLIENT_SECRET=abc\n')
    def test_parse_refuse_url(self):
        with self.assertRaises(qa.EvidenceError):inv.parse_flags(self.flags_path.read_bytes()+b'EXAMPLE=https://foo\n')
    def test_parse_refuse_url_even_in_comment(self):
        with self.assertRaises(qa.EvidenceError):
            inv.parse_flags(self.flags_path.read_bytes()+b'# https://qa.example.invalid/unsafe\n')
    def test_parse_refuse_token_even_in_comment(self):
        with self.assertRaises(qa.EvidenceError):
            inv.parse_flags(self.flags_path.read_bytes()+b'# Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234\n')
    def test_parse_refuse_export(self):
        with self.assertRaises(qa.EvidenceError):inv.parse_flags(b'export WALLET_IDENTITY_ENABLED=true\n')
    def test_parse_refuse_shell_substitution(self):
        with self.assertRaises(qa.EvidenceError):inv.parse_flags(b'WALLET_IDENTITY_ENABLED=$(whoami)\n')
    def test_parse_refuse_mixed_case(self):
        with self.assertRaises(qa.EvidenceError):inv.parse_flags(self.flags_path.read_bytes().replace(b'=false',b'=False',1))
    def test_parse_refuse_crlf(self):
        with self.assertRaises(qa.EvidenceError):inv.parse_flags(self.flags_path.read_bytes().replace(b'\n',b'\r\n'))
    def test_parse_refuse_binary(self):
        with self.assertRaises(qa.EvidenceError):inv.parse_flags(self.flags_path.read_bytes()+b'\x00')
    def test_parse_refuse_oversize(self):
        with self.assertRaises(qa.EvidenceError):inv.parse_flags(b' '*(inv.MAX_FLAGS_SIZE+1))
    def test_baseline(self):self.assertEqual(inv.classification(self.flags),'BASELINE_ALL_DISABLED')
    def test_provider_key_requires_identity(self):
        f=dict(self.flags);f['WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED']=True
        self.assertIn('WALLET_IDENTITY_ENABLED',str(inv.contradictions(f)))
    def test_provider_binding_requires_key(self):
        f=dict(self.flags);f.update(WALLET_IDENTITY_ENABLED=True,WALLET_IDENTITY_CREDENTIAL_BINDING_ENABLED=True)
        self.assertIn('WALLET_IDENTITY_KEY_ATTESTATION_REQUIRED',str(inv.contradictions(f)))
    def test_provider_m2m_requires_cognito(self):
        f=dict(self.flags);f.update(WALLET_IDENTITY_ENABLED=True,WALLET_IDENTITY_MIMOTO_M2M_ENABLED=True)
        self.assertIn('WALLET_COGNITO_ENABLED',str(inv.contradictions(f)))
    def test_certify_requires_key_validation(self):
        f=dict(self.flags);f['MTC_KEY_ATTESTATION_REQUIRED']=True
        self.assertIn('MTC_KEY_ATTESTATION_VALIDATION_ENABLED',str(inv.contradictions(f)))
    def test_certify_enforcement_requires_provider(self):
        f=dict(self.flags);f.update(MTC_CERTIFY_PROVIDER_ISSUANCE_REQUIRED=True,
                                    MTC_KEY_ATTESTATION_VALIDATION_ENABLED=True,
                                    MTC_KEY_ATTESTATION_REQUIRED=True)
        self.assertIn('WALLET_IDENTITY_CERTIFY_M2M_ENABLED',str(inv.contradictions(f)))
    def test_mimoto_guard_requires_evidence(self):
        f=dict(self.flags);f['MIMOTO_HOLDER_ISSUANCE_ENFORCEMENT_ENABLED']=True
        self.assertIn('MIMOTO_HOLDER_EVIDENCE_ENABLED',str(inv.contradictions(f)))
    def test_wallet_requires_mimoto(self):
        f=dict(self.flags);f['WALLET_HOLDER_IDENTITY_REQUIRED']=True
        self.assertIn('MIMOTO_HOLDER_ISSUANCE_ENFORCEMENT_ENABLED',str(inv.contradictions(f)))
    def test_all_true_consistent(self):
        f={k:True for k in inv.ALL_FLAGS}
        self.assertFalse(inv.contradictions(f))
        self.assertEqual(inv.classification(f),'ENFORCEMENT_CONFIGURED_QA_E2E_PENDING')
    def test_partial_consistent(self):
        f=dict(self.flags);f.update(WALLET_IDENTITY_ENABLED=True,WALLET_COGNITO_ENABLED=True)
        self.assertEqual(inv.classification(f),'PARTIAL_STAGING_QA_E2E_PENDING')
    def test_wrong_type_blocked(self):
        f=dict(self.flags);f['WALLET_IDENTITY_ENABLED']='false'
        with self.assertRaises(qa.EvidenceError):inv.contradictions(f)
    def test_wrong_versions_blocked(self):
        with self.assertRaises(qa.EvidenceError):inv.validate_inventory_fields(self.change,{'wallet':'foo'})
    def test_invalid_change_blocked(self):
        with self.assertRaises(qa.EvidenceError):inv.validate_inventory_fields('https://malicious',self.versions)
    def test_inventory_contract(self):
        x=inv.inventory(self.flags,self.flags_path.read_bytes(),self.change,self.versions,b'local',b'evidence',self.now)
        self.assertFalse(x['cloud_deployment_confirmed_by_tool'])
        self.assertEqual(x['production_release'],'NOT_AUTHORIZED')
        self.assertEqual(x['source_of_values'],'OPERATOR_DECLARED_NOT_CLOUD_VERIFIED')
    def test_inventory_no_secrets(self):
        x=inv.inventory(self.flags,self.flags_path.read_bytes(),self.change,self.versions,b'local',b'evidence',self.now)
        self.assertNotIn('secret',json.dumps(x).lower())
        self.assertNotIn('https://',json.dumps(x))
    def test_inventory_markdown_has_disclaimer(self):
        x=inv.inventory(self.flags,self.flags_path.read_bytes(),self.change,self.versions,b'local',b'evidence',self.now)
        self.assertIn('NOT_AUTHORIZED',inv.markdown(x))
    def test_create_configures_evidence_no_mutation(self):
        orig=self.evidence.read_bytes();x=self.process()
        self.assertEqual(x['classification'],'BASELINE_ALL_DISABLED')
        self.assertEqual(orig,self.evidence.read_bytes())
        changed=json.loads((self.out/'mtc_qa_e0326_evidencias_configuradas.json').read_text())
        self.assertEqual(changed['qa_revisions'],self.versions)
        self.assertTrue(all(r['status']=='PENDING' for r in changed['cases']))
        self.assertEqual((self.out/'mtc_qa_e0326_inventario.json').stat().st_mode&0o777,0o600)
    def test_create_rejects_conflicts(self):
        self.flags['MTC_CERTIFY_PROVIDER_ISSUANCE_REQUIRED']=True
        self.write_flags()
        with self.assertRaises(qa.EvidenceError):self.process()
        self.assertFalse((self.out/'mtc_qa_e0326_evidencias_configuradas.json').exists())
    def test_create_rejects_overwrite(self):
        self.process()
        with self.assertRaises(qa.EvidenceError):self.process()
    def test_create_rejects_flags_symlink(self):
        link=self.root/'link.env';link.symlink_to(self.flags_path)
        with self.assertRaises(qa.EvidenceError):
            inv.create_inventory(link,self.local,self.evidence,self.out,self.repo,self.change,self.versions,now=self.now)
    def test_create_rejects_world_readable(self):
        self.flags_path.chmod(0o644)
        with self.assertRaises(qa.EvidenceError):self.process()
    def test_create_rejects_tampered_readiness(self):
        (self.repo/'inji-wallet/t0.ts').write_text('tampered')
        with self.assertRaises(qa.EvidenceError):self.process()
    def test_create_rejects_already_configured(self):
        data=json.loads(self.evidence.read_text())
        data['change_ref']=self.change
        data['qa_revisions']=self.versions
        self.evidence.write_text(json.dumps(data))
        with self.assertRaises(qa.EvidenceError):self.process()
    def test_cli_template(self):
        path=self.root/'template.env'
        self.assertEqual(inv.main(['init-flags','--out',str(path)]),0)
        self.assertEqual(path.stat().st_mode&0o777,0o600)
    def test_cli_check_false(self):
        self.assertEqual(inv.main(['check-flags','--flags-file',str(self.flags_path)]),0)
    def test_cli_check_conflict(self):
        self.flags['MTC_KEY_ATTESTATION_REQUIRED']=True;self.write_flags()
        self.assertEqual(inv.main(['check-flags','--flags-file',str(self.flags_path)]),2)
    def test_cli_configure(self):
        args=['configure-qa','--flags-file',str(self.flags_path),
              '--local-report',str(self.local),'--evidence',str(self.evidence),
              '--out-dir',str(self.out),'--repo',str(self.repo),
              '--change-ref',self.change]
        for c,v in self.versions.items():args.extend([f'--{c}-version',v])
        self.assertEqual(inv.main(args),0)
        self.assertTrue((self.out/'mtc_qa_e0326_evidencias_configuradas.json').is_file())
    def test_cli_template_no_overwrite(self):
        path=self.root/'template.env';path.write_text('DO NOT OVERWRITE')
        self.assertEqual(inv.main(['init-flags','--out',str(path)]),2)
        self.assertEqual(path.read_text(),'DO NOT OVERWRITE')
if __name__=='__main__':unittest.main()
