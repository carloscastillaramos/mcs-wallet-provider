"""MTC E03.25: avance documental a partir de expedientes sintéticos."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import mtc_qa_e2e_evidence as qa
import mtc_qa_e2e_progress as progress


class QaProgressTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        source_digests = {}
        for i in range(5):
            p = self.repo / f"inji-wallet/synthetic-{i}.ts"
            p.parent.mkdir(exist_ok=True, parents=True)
            p.write_text(f"safe-fixture-{i}")
            source_digests[f"inji-wallet/synthetic-{i}.ts"] = hashlib.sha256(p.read_bytes()).hexdigest()
        self.local = {
            "schema": "mtc-local-readiness/1", "version": "03.22",
            "created_at_utc": self.now.isoformat(), "local_validation": "PASS",
            "postgres_lab_requested": True, "qa_e2e": "PENDING",
            "production_release": "NOT_AUTHORIZED",
            "steps": [{"key": key, "status": "PASS", "tests_run": 0 if key == "postgres_v5" else 2}
                      for key in sorted(qa.LOCAL_REQUIRED)],
            "evidence_sha256": source_digests,
        }
        self.local_path = self.root / "local.json"
        self.local_path.write_text(json.dumps(self.local))
        self.catalog = qa.catalog_cases(qa._read_json(qa.CATALOG))
        self.evidence = qa.make_template(self.local_path.read_bytes(), self.catalog, now=self.now)
        self.evidence_path = self.root / "evidence.json"
        self.write_evidence()
        self.dest = self.root / "reports"

    def write_evidence(self):
        self.evidence_path.write_text(json.dumps(self.evidence))

    def configure(self):
        self.evidence["change_ref"] = "MTCQA-EXAMPLE-0325"
        self.evidence["qa_revisions"] = {k: "0.14.0-mtc.1" for k in qa.COMPONENTS}

    def update(self, ident="QA-ENV-01", status="PASS", *, ref="MTCQA-CASE-01",
               sha="a"*64, time=None):
        item = next(c for c in self.evidence["cases"] if c["id"] == ident)
        item.update(status=status, evidence_ref=ref, evidence_sha256=sha,
                    executed_at_utc=(time or self.now).isoformat())

    def calculate(self):
        raw_local = self.local_path.read_bytes()
        raw_evidence = self.evidence_path.read_bytes()
        return progress.calculate(raw_local,raw_evidence,self.local,self.evidence,self.catalog,
                                  self.repo,now=self.now)

    def test_initial_34_pending(self):
        r = self.calculate()
        self.assertEqual(r["cases_total"],34)
        self.assertEqual(r["case_counts"],dict(PASS=0,FAIL=0,BLOCKED=0,PENDING=34))
        self.assertEqual(r["executed_percent"],0)
        self.assertEqual(r["passed_percent"],0)
        self.assertEqual(r["next_action"],"REGISTRAR_VERSIONES_QA")

    def test_groups_cover_all_catalog_cases(self):
        r = self.calculate()
        self.assertEqual(len(r["groups"]),11)
        self.assertEqual(sum(group["total"] for group in r["groups"]),34)
        for group in r["groups"]:
            self.assertEqual(sum(group["counts"].values()),group["total"])

    def test_pending_order_matches_catalog(self):
        self.assertEqual([x["id"] for x in self.calculate()["open_cases"]],
                         [x["id"] for x in self.catalog])

    def test_after_configure_action_changes(self):
        self.configure()
        self.write_evidence()
        self.assertEqual(self.calculate()["next_action"],"EJECUTAR_ESCENARIOS_PENDIENTES")

    def test_one_pass_progress(self):
        self.configure()
        self.update()
        self.write_evidence()
        r = self.calculate()
        self.assertEqual(r["case_counts"],dict(PASS=1,FAIL=0,BLOCKED=0,PENDING=33))
        self.assertEqual(r["executed_cases"],1)
        self.assertEqual(r["executed_percent"],2.9)
        self.assertEqual(r["passed_percent"],2.9)
        self.assertEqual(len(r["open_cases"]),33)
        self.assertEqual(r["most_recent_evidence_at_utc"],self.now.isoformat())

    def test_fail_priority_over_pending(self):
        self.configure()
        self.update(status="FAIL")
        self.write_evidence()
        self.assertEqual(self.calculate()["next_action"],"RESOLVER_FALLOS")

    def test_blocked_priority_over_pending(self):
        self.configure()
        self.update(status="BLOCKED")
        self.write_evidence()
        self.assertEqual(self.calculate()["next_action"],"DESBLOQUEAR_ESCENARIOS")

    def test_fail_priority_over_blocked(self):
        self.configure()
        self.update(status="BLOCKED")
        self.update(ident="QA-ENV-02",status="FAIL",ref="MTCQA-CASE-02",sha="b"*64)
        self.write_evidence()
        self.assertEqual(self.calculate()["next_action"],"RESOLVER_FALLOS")

    def test_fail_without_evidence_rejected(self):
        self.configure()
        self.update(status="FAIL",sha="")
        self.write_evidence()
        with self.assertRaises(qa.EvidenceError): self.calculate()

    def test_blocked_without_ticket_rejected(self):
        self.configure()
        self.update(status="BLOCKED",ref="")
        self.write_evidence()
        with self.assertRaises(qa.EvidenceError): self.calculate()

    def test_blocked_stale_date_rejected(self):
        self.configure()
        self.update(status="BLOCKED",time=self.now-timedelta(days=31))
        self.write_evidence()
        with self.assertRaises(qa.EvidenceError): self.calculate()

    def test_fail_future_date_rejected(self):
        self.configure()
        self.update(status="FAIL",time=self.now+timedelta(days=1))
        self.write_evidence()
        with self.assertRaises(qa.EvidenceError): self.calculate()

    def test_documentary_not_institutional_approval(self):
        self.configure()
        for i,item in enumerate(self.catalog):
            self.update(item["id"],"PASS",ref="MTCQA-CASE-"+str(i+1),sha=format(i+1,"064x"))
        self.evidence["human_review"]="REVIEWED"
        self.write_evidence()
        r=self.calculate()
        self.assertEqual(r["case_counts"]["PASS"],34)
        self.assertEqual(r["next_action"],"SOLICITAR_REVISION_INDEPENDIENTE")
        self.assertTrue(r["human_review_recorded"])
        self.assertFalse(r["qa_e2e_verified_by_tool"])
        self.assertEqual(r["production_release"],"NOT_AUTHORIZED")

    def test_all_pass_without_configuration_not_complete(self):
        for i,item in enumerate(self.catalog):
            self.update(item["id"],"PASS",ref="MTCQA-CASE-"+str(i+1),sha=format(i+1,"064x"))
        self.write_evidence()
        self.assertEqual(self.calculate()["next_action"],"REGISTRAR_VERSIONES_QA")

    def test_tampered_local_report_rejected(self):
        self.local["production_release"]="AUTHORIZED"
        with self.assertRaises(qa.EvidenceError):self.calculate()

    def test_changed_source_rejected(self):
        (self.repo / "inji-wallet/synthetic-0.ts").write_text("changed")
        with self.assertRaises(qa.EvidenceError):self.calculate()

    def test_stale_local_report_rejected(self):
        self.local["created_at_utc"]=(self.now-timedelta(days=15)).isoformat()
        with self.assertRaises(qa.EvidenceError):self.calculate()

    def test_catalog_missing_case_rejected(self):
        self.evidence["cases"].pop()
        with self.assertRaises(qa.EvidenceError):self.calculate()

    def test_manifest_wrong_local_digest_rejected(self):
        self.evidence["local_report_sha256"]="f"*64
        with self.assertRaises(qa.EvidenceError):self.calculate()

    def test_md_shows_group_and_not_authorized(self):
        self.configure()
        self.update()
        self.write_evidence()
        report=self.calculate()
        text=progress.markdown(report)
        self.assertIn("QA-ENV-02",text)
        self.assertIn("| ID_PERU |",text)
        self.assertNotIn("| QA-ENV-01 |",text)
        self.assertIn("NOT_AUTHORIZED",text)
        self.assertNotIn("http",text)

    def test_read_symlink_denied(self):
        alias=self.root/"alias.json"
        alias.symlink_to(self.local_path)
        with self.assertRaises(qa.EvidenceError):progress.read_regular_json(alias)

    def test_read_unknown_path_denied(self):
        with self.assertRaises(qa.EvidenceError):progress.read_regular_json(self.root/"missing.json")

    def test_report_process_no_source_mutation(self):
        before=self.evidence_path.read_bytes()
        r=progress.process(self.local_path,self.evidence_path,self.dest,self.repo,now=self.now)
        self.assertEqual(r["cases_total"],34)
        self.assertEqual(self.evidence_path.read_bytes(),before)
        for f in (self.dest/"mtc_qa_e0325_avance.json",self.dest/"mtc_qa_e0325_avance.md"):
            self.assertTrue(f.is_file())
            self.assertEqual(f.stat().st_mode & 0o777,0o600)
        data=json.loads((self.dest/"mtc_qa_e0325_avance.json").read_text())
        self.assertEqual(data["qa_manifest_sha256"],hashlib.sha256(before).hexdigest())
        self.assertFalse(data["qa_e2e_verified_by_tool"])

    def test_existing_output_cannot_overwrite(self):
        self.dest.mkdir()
        p=self.dest/"mtc_qa_e0325_avance.md"
        p.write_text("existing")
        with self.assertRaises(qa.EvidenceError):
            progress.process(self.local_path,self.evidence_path,self.dest,self.repo,now=self.now)
        self.assertEqual(p.read_text(),"existing")
        self.assertFalse((self.dest/"mtc_qa_e0325_avance.json").exists())

    def test_cli_success(self):
        self.assertEqual(progress.main(["--local-report",str(self.local_path),
                                        "--evidence",str(self.evidence_path),
                                        "--out-dir",str(self.dest),
                                        "--repo",str(self.repo)]),0)

    def test_cli_bad_manifest(self):
        self.evidence["environment"]="PRD"
        self.write_evidence()
        self.assertEqual(progress.main(["--local-report",str(self.local_path),
                                        "--evidence",str(self.evidence_path),
                                        "--out-dir",str(self.dest),
                                        "--repo",str(self.repo)]),2)
        self.assertFalse(self.dest.exists())

    def test_no_qa_or_prod_cli_switch(self):
        p=Path(progress.__file__).read_text()
        self.assertNotIn("--qa-host",p)
        self.assertNotIn("--enable-prod",p)

    def test_unknown_case_title_cannot_be_injected(self):
        self.evidence["cases"][0]["title"]="malicious"
        with self.assertRaises(qa.EvidenceError):self.calculate()

    def test_counts_compatible_with_existing_assessment(self):
        self.configure()
        self.update(status="FAIL")
        self.write_evidence()
        raw=self.local_path.read_bytes()
        prior=qa.assess(self.evidence,raw,self.catalog,now=self.now)
        self.assertEqual(prior["case_counts"],self.calculate()["case_counts"])
        self.assertEqual(prior["documentary_status"],self.calculate()["documentary_status"])

if __name__ == "__main__":
    unittest.main()
