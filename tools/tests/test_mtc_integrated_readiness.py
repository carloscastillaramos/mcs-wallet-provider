"""Deterministic unit tests for local-only E03.22 readiness orchestrator."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import sys

SCRIPT = Path(__file__).resolve().parents[1] / 'mtc_integrated_readiness.py'
spec = importlib.util.spec_from_file_location('mtc_e322_readiness', SCRIPT)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class TestReadiness(unittest.TestCase):
    def step(self, parser):
        return module.Step('example', 'example', ('x',), parser, 60, 'x')

    def test_plan_has_all_components(self):
        names = {item.key for item in module.steps(False)}
        self.assertEqual({'wallet_jest', 'mimoto_junit', 'provider_verify',
                          'certify_verify', 'readiness_selftest', 'preflight_python', 'preflight_offline'}, names)

    def test_postgres_is_explicit_opt_in(self):
        self.assertNotIn('postgres_v5', [item.key for item in module.steps(False)])
        self.assertIn('postgres_v5', [item.key for item in module.steps(True)])

    def test_maven_success_needs_test_count_and_build_success(self):
        out = 'Tests run: 25, Failures: 0, Errors: 0, Skipped: 0\nBUILD SUCCESS'
        result = module.result_from_output(self.step('maven'), out, 0, 1)
        self.assertEqual('PASS', result.status)
        self.assertEqual(25, result.tests_run)

    def test_maven_success_without_test_results_rejected(self):
        self.assertEqual('FAIL', module.result_from_output(self.step('maven'), 'BUILD SUCCESS', 0, 1).status)

    def test_maven_nonzero_exit_rejected_even_with_success_marker(self):
        txt = 'Tests run: 25, Failures: 0, Errors: 0, Skipped: 0\nBUILD SUCCESS'
        self.assertEqual('FAIL', module.result_from_output(self.step('maven'), txt, 2, 1).status)

    def test_maven_failures_rejected(self):
        txt = 'Tests run: 25, Failures: 1, Errors: 0, Skipped: 0\nBUILD SUCCESS'
        self.assertEqual('FAIL', module.result_from_output(self.step('maven'), txt, 0, 1).status)

    def test_jest_requires_summary(self):
        txt = 'Test Suites: 4 passed, 4 total\nTests:       43 passed, 43 total'
        self.assertEqual('PASS', module.result_from_output(self.step('jest'), txt, 0, 1).status)
        self.assertEqual('FAIL', module.result_from_output(self.step('jest'), 'Test Suites: 4 passed', 0, 1).status)

    def test_unittest_requires_ok(self):
        good = 'Ran 11 tests in 0.001s\n\nOK'
        self.assertEqual('PASS', module.result_from_output(self.step('unittest'), good, 0, 1).status)
        self.assertEqual('FAIL', module.result_from_output(self.step('unittest'), good.replace('OK', 'FAILED'), 0, 1).status)

    def test_offline_requires_all_pass(self):
        good = 'RESUMEN: 4/4 comprobaciones aprobadas'
        bad = 'RESUMEN: 3/4 comprobaciones aprobadas'
        self.assertEqual('PASS', module.result_from_output(self.step('offline'), good, 0, 1).status)
        self.assertEqual('FAIL', module.result_from_output(self.step('offline'), bad, 1, 1).status)

    def test_pg_requires_ok_marker(self):
        good = '[OK] Migración V1–V5 y pruebas SQL V5 completadas'
        self.assertEqual('PASS', module.result_from_output(self.step('postgres'), good, 0, 1).status)
        self.assertEqual('FAIL', module.result_from_output(self.step('postgres'), '', 0, 1).status)

    def test_environment_blocks_qa_and_prod_flags(self):
        problems = module.validate_environment({
            'MTC_E321_QA_CERTIFY_CLIENT_SECRET': 'test',
            'WALLET_IDENTITY_ENABLED': 'true',
            'AWS_ACCESS_KEY_ID': 'test',
        })
        self.assertGreaterEqual(len(problems), 3)
        self.assertNotIn('test', str(problems))

    def test_environment_sanitizes_secrets(self):
        env = module.restricted_environment({
            'PATH': '/usr/bin', 'MTC_E321_QA_CERTIFY_CLIENT_SECRET': 'secret-value',
            'AWS_ACCESS_KEY_ID': 'access', 'MY_TOKEN': 'bearer', 'USERNAME': 'operator',
            'PASSWORD': 'credential',
        })
        self.assertIn('PATH', env)
        self.assertNotIn('MTC_E321_QA_CERTIFY_CLIENT_SECRET', env)
        self.assertNotIn('AWS_ACCESS_KEY_ID', env)
        self.assertNotIn('MY_TOKEN', env)
        self.assertNotIn('PASSWORD', env)
        self.assertNotIn('secret-value', str(env))

    def test_report_is_secretless_and_not_qa(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            report = module.build_report(root, [module.Result('x', 'PASS', 'OK', 20, 1, 0)], True)
            raw = json.dumps(report)
            self.assertEqual('PASS', report['local_validation'])
            self.assertEqual('PENDING', report['qa_e2e'])
            self.assertEqual('NOT_AUTHORIZED', report['production_release'])
            self.assertNotIn('Authorization', raw)
            self.assertNotIn('token', raw.lower())

    def test_failed_suite_must_fail_local_readiness(self):
        with TemporaryDirectory() as tmp:
            report = module.build_report(Path(tmp), [module.Result('x', 'FAIL', 'Failure')], False)
            self.assertEqual('NOT_PASS', report['local_validation'])
            self.assertEqual('NOT_AUTHORIZED', report['production_release'])

    def test_static_manifest_missing_files_is_blocking(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(module.shutil, 'which', return_value='/usr/bin/command'):
                problems = module.prerequisites(root, False)
            self.assertTrue(any('Archivo obligatorio ausente' in issue for issue in problems))
            self.assertTrue(any('Jest local ausente' in issue for issue in problems))

    def test_no_qa_switch_in_cli(self):
        args = set()
        for step in module.steps(True):
            args.update(step.command)
        self.assertNotIn('--qa', args)
        self.assertNotIn('aws', args)
        self.assertNotIn('kubectl', args)
        self.assertNotIn('npx', args)

    def test_executed_failure_does_not_capture_fake_secret(self):
        step = self.step('maven')
        with TemporaryDirectory() as tmp:
            import subprocess
            fake = subprocess.CompletedProcess(['x'], 1, 'SECRET VERY SECRET VALUE\nBUILD FAILURE')
            with patch.object(module.subprocess, 'run', return_value=fake):
                result = module.execute(step, Path(tmp), {'PATH': '/usr/bin'})
            self.assertEqual('FAIL', result.status)
            self.assertNotIn('VERY SECRET', str(result))


if __name__ == '__main__':
    unittest.main()
