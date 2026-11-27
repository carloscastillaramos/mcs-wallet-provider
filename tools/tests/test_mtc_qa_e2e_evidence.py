"""Regresión documental de MTC E03.23. No necesita internet, Docker ni AWS."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from unittest.mock import patch

TOOL = Path(__file__).resolve().parents[1] / "mtc_qa_e2e_evidence.py"
spec = importlib.util.spec_from_file_location("mtc_qa_e2e_evidence", TOOL)
mtc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mtc)

class QaHomologationEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.name = "inji-wallet/jest.mtc.holder-identity.config.cjs"
        (self.repo / self.name).parent.mkdir()
        (self.repo / self.name).write_text("jest config")
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.local = {
            "schema":"mtc-local-readiness/1", "version":"03.22",
            "created_at_utc":self.now.isoformat(), "local_validation":"PASS",
            "postgres_lab_requested":True, "qa_e2e":"PENDING", "production_release":"NOT_AUTHORIZED",
            "steps":[{"key":id,"status":"PASS","tests_run":None if id=="postgres_v5" else 10,
                      "tests_skipped":0} for id in sorted(mtc.LOCAL_REQUIRED)],
            "evidence_sha256":{
                self.name:hashlib.sha256(b"jest config").hexdigest(),
                **{f"inji-wallet/dummy{i}.ts":hashlib.sha256(f"source-{i}".encode()).hexdigest() for i in range(4)}
            },
        }
        for i in range(4):
            (self.repo / f"inji-wallet/dummy{i}.ts").write_text(f"source-{i}")
        self.cases = mtc.catalog_cases(mtc._read_json(mtc.CATALOG))
        self.raw = json.dumps(self.local,sort_keys=True).encode()
        self.ev = mtc.make_template(self.raw,self.cases,now=self.now)

    def fill(self):
        self.ev["change_ref"] = "MTCQA-20261124"
        self.ev["qa_revisions"] = {x:"abcdef123456789" for x in mtc.COMPONENTS}
        for c in self.ev["cases"]:
            c.update(status="PASS", evidence_ref="MTCQA-20261124",
                evidence_sha256="a"*64,executed_at_utc=self.now.isoformat())

    def test_catalog_has_34_unique_cases(self):
        self.assertEqual(len(self.cases),34)
        self.assertEqual(len({c["id"] for c in self.cases}),34)

    def test_validate_local_happy_path(self):
        mtc.validate_local(self.local,self.repo,self.now)

    def test_missing_postgres_fails(self):
        self.local["postgres_lab_requested"]=False
        with self.assertRaises(mtc.EvidenceError):mtc.validate_local(self.local,self.repo,self.now)

    def test_missing_step_fails(self):
        self.local["steps"].pop()
        with self.assertRaises(mtc.EvidenceError):mtc.validate_local(self.local,self.repo,self.now)

    def test_duplicate_step_fails(self):
        self.local["steps"][-1]=self.local["steps"][0]
        with self.assertRaises(mtc.EvidenceError):mtc.validate_local(self.local,self.repo,self.now)

    def test_fake_local_pass_step_fails(self):
        self.local["steps"][0]["status"]="FAIL"
        with self.assertRaises(mtc.EvidenceError):mtc.validate_local(self.local,self.repo,self.now)

    def test_bad_local_environment_fails(self):
        self.local["production_release"]="AUTHORIZED"
        with self.assertRaises(mtc.EvidenceError):mtc.validate_local(self.local,self.repo,self.now)

    def test_invalid_local_checksum_fails(self):
        (self.repo/self.name).write_text("altered")
        with self.assertRaises(mtc.EvidenceError):mtc.validate_local(self.local,self.repo,self.now)

    def test_local_path_traversal_blocked(self):
        self.local["evidence_sha256"]["inji-wallet/../../secret"]="f"*64
        with self.assertRaises(mtc.EvidenceError):mtc.validate_local(self.local,self.repo,self.now)

    def test_local_stale_report_fails(self):
        self.local["created_at_utc"]=(self.now-timedelta(days=15)).isoformat()
        with self.assertRaises(mtc.EvidenceError):mtc.validate_local(self.local,self.repo,self.now)

    def test_local_future_report_fails(self):
        self.local["created_at_utc"]=(self.now+timedelta(hours=2)).isoformat()
        with self.assertRaises(mtc.EvidenceError):mtc.validate_local(self.local,self.repo,self.now)

    def test_local_fails_without_tests(self):
        self.local["steps"][0]["tests_run"]=0
        with self.assertRaises(mtc.EvidenceError):mtc.validate_local(self.local,self.repo,self.now)

    def test_template_is_all_pending(self):
        self.assertTrue(all(c["status"]=="PENDING" for c in self.ev["cases"]))
        self.assertEqual(self.ev["environment"],"QA")

    def test_markdown_covers_all_cases(self):
        md=mtc.matrix_md(self.cases)
        self.assertTrue(all(c["id"] in md for c in self.cases))
        self.assertIn("No habilita PRD",md)

    def test_pending_is_not_approval(self):
        out=mtc.assess(self.ev,self.raw,self.cases,self.now)
        self.assertEqual(out["documentary_status"],"QA_TESTS_PENDING")
        self.assertEqual(out["case_counts"]["PENDING"],34)
        self.assertEqual(out["production_release"],"NOT_AUTHORIZED")

    def test_failed_case_blocks(self):
        self.fill()
        self.ev["cases"][0]["status"]="FAIL"
        self.assertEqual(mtc.assess(self.ev,self.raw,self.cases,self.now)["documentary_status"],"QA_TEST_FAILURES")

    def test_blocked_case_blocks(self):
        self.fill()
        self.ev["cases"][0]["status"]="BLOCKED"
        self.assertEqual(mtc.assess(self.ev,self.raw,self.cases,self.now)["documentary_status"],"QA_EXECUTION_BLOCKED")

    def test_pass_without_evidence_rejected(self):
        self.fill()
        self.ev["cases"][0]["evidence_ref"]=""
        with self.assertRaises(mtc.EvidenceError):mtc.assess(self.ev,self.raw,self.cases,self.now)

    def test_pass_without_date_rejected(self):
        self.fill()
        self.ev["cases"][0]["executed_at_utc"]=""
        with self.assertRaises(mtc.EvidenceError):mtc.assess(self.ev,self.raw,self.cases,self.now)

    def test_forged_local_fingerprint_rejected(self):
        self.fill()
        self.ev["local_report_sha256"]="f"*64
        with self.assertRaises(mtc.EvidenceError):mtc.assess(self.ev,self.raw,self.cases,self.now)

    def test_production_environment_rejected(self):
        self.ev["environment"]="PRD"
        with self.assertRaises(mtc.EvidenceError):mtc.assess(self.ev,self.raw,self.cases,self.now)

    def test_case_duplicate_rejected(self):
        self.ev["cases"][-1]=dict(self.ev["cases"][0])
        with self.assertRaises(mtc.EvidenceError):mtc.assess(self.ev,self.raw,self.cases,self.now)

    def test_case_omitted_rejected(self):
        self.ev["cases"].pop()
        with self.assertRaises(mtc.EvidenceError):mtc.assess(self.ev,self.raw,self.cases,self.now)

    def test_extra_field_secrets_rejected(self):
        self.ev["cases"][0]["dni"]="12345678"
        with self.assertRaises(mtc.EvidenceError):mtc.assess(self.ev,self.raw,self.cases,self.now)

    def test_pass_without_versions_remains_incomplete(self):
        self.fill()
        self.ev["qa_revisions"]["wallet"]=""
        self.assertEqual(mtc.assess(self.ev,self.raw,self.cases,self.now)["documentary_status"],"QA_METADATA_INCOMPLETE")

    def test_all_pass_needs_independent_review(self):
        self.fill()
        o=mtc.assess(self.ev,self.raw,self.cases,self.now)
        self.assertEqual(o["documentary_status"],"QA_EVIDENCE_RECORDED_REQUIRES_INDEPENDENT_REVIEW")
        self.assertFalse(o["qa_e2e_verified_by_tool"])
        self.assertFalse(o["evidence_integrity_independently_verified"])
        self.assertEqual(o["production_release"],"NOT_AUTHORIZED")

    def test_human_review_not_auto_approval(self):
        self.fill()
        self.ev["human_review"]="REVIEWED"
        o=mtc.assess(self.ev,self.raw,self.cases,self.now)
        self.assertTrue(o["human_review_recorded"])
        self.assertEqual(o["production_release"],"NOT_AUTHORIZED")

    def test_secret_in_json_rejected(self):
        p=self.root/"secret.json"
        p.write_text('{"client_secret": "very_long_secret_string"}')
        with self.assertRaises(mtc.EvidenceError):mtc._read_json(p)

    def test_large_json_rejected(self):
        p=self.root/"large.json"
        p.write_text("x"*1000)
        with self.assertRaises(mtc.EvidenceError):mtc._read_json(p,max_size=100)

    def test_secure_file_no_overwrite(self):
        p=self.root/"report.json"
        mtc._write_new(p,b"{}")
        self.assertEqual(p.stat().st_mode & 0o777,0o600)
        with self.assertRaises(mtc.EvidenceError):mtc._write_new(p,b"secret")
        self.assertEqual(p.read_bytes(),b"{}")

    def test_cli_init_and_assess_pending(self):
        p=self.root/"local.json"
        p.write_bytes(self.raw)
        out=self.root/"qa"
        self.assertEqual(mtc.main(["--init","--local-report",str(p),"--repo",str(self.repo),"--out-dir",str(out)]),0)
        self.assertTrue((out/"mtc_qa_e0323_matriz.md").is_file())
        manifest=out/"mtc_qa_e0323_evidencias.json"
        target=out/"assessment.json"
        self.assertEqual(mtc.main(["--assess","--local-report",str(p),"--repo",str(self.repo),
                                   "--evidence",str(manifest),"--report",str(target)]),1)
        self.assertEqual(json.loads(target.read_text())["production_release"],"NOT_AUTHORIZED")

if __name__ == '__main__': unittest.main()
