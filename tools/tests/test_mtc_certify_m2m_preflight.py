"""Offline-only tests for QA preflight; fake transport never opens a socket."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "mtc_certify_m2m_preflight.py"
spec = importlib.util.spec_from_file_location("mtc_e321_preflight", SCRIPT)
import sys
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

CONFIG = {
    "base": "https://provider-qa.example.org",
    "token_url": "https://cognito-qa.example.org/oauth2/token",
    "client_id": "certify-qa", "client_secret": "secret-fake",
    "mimoto_id": "mimoto-qa", "mimoto_secret": "mimoto-fake",
    "thumbprint": "A" * 43, "nonce": "nonce-for-registered-qa",
}


class FakeTransport:
    def __init__(self, no_scope=True, statuses=None, response_scope=None):
        self.no_scope = no_scope
        self.statuses = statuses or {}
        self.response_scope = response_scope
        self.calls = []

    def post(self, url, headers, body):
        self.calls.append((url, headers, body))
        if url.endswith("/oauth2/token"):
            if self.response_scope is not None:
                value = self.response_scope
            elif b"wallet.identity.mimoto" in body:
                value = module.MIMOTO_SCOPE
            else:
                value = module.CERTIFY_SCOPE
            data = {"access_token": "mock-valid-token", "token_type": "Bearer"}
            if not self.no_scope:
                data["scope"] = value
            import json
            return module.Response(200, json.dumps(data).encode())
        import json
        payload = json.loads(body)
        if "Authorization" not in headers:
            return module.Response(self.statuses.get("anon", 401))
        if "invalid" == payload["credentialKeyThumbprint"]:
            return module.Response(self.statuses.get("malformed", 400))
        if payload["credentialKeyThumbprint"] == CONFIG["thumbprint"]:
            return module.Response(self.statuses.get("positive", 204))
        if headers["Authorization"] == "Bearer mock-valid-token" and len(self.calls) >= 5:
            return module.Response(self.statuses.get("mimoto", 403))
        return module.Response(self.statuses.get("missing", 403))


class PreflightTest(unittest.TestCase):
    def test_requires_qa_confirmation(self):
        with self.assertRaises(ValueError):
            module.qa_environment({})

    def test_qa_requires_pinned_host(self):
        env = self.qaenv()
        env["MTC_E321_APPROVED_PROVIDER_HOST"] = "other.example.org"
        with self.assertRaises(ValueError):
            module.qa_environment(env)

    def test_qa_rejects_http_and_userinfo(self):
        env = self.qaenv()
        for url in ["http://provider-qa.example.org", "https://x:y@provider-qa.example.org",
                    "https://provider-qa.example.org/?secret=y", "https://localhost"]:
            env["MTC_E321_QA_PROVIDER_URL"] = url
            with self.subTest(url=url), self.assertRaises(ValueError):
                module.qa_environment(env)

    def test_offline_detects_incomplete_repo(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as temp:
            self.assertTrue(all(r.state == "FAIL" for r in module.run_offline(Path(temp))))

    def test_qa_default_all_four_checks(self):
        fake = FakeTransport()
        results = module.run_qa(fake, CONFIG)
        self.assertEqual(["PASS"] * 4, [r.state for r in results])
        self.assertEqual(4, len(fake.calls))
        self.assertTrue(all("mock-valid-token" not in str(r) for r in results))
        self.assertTrue(all("secret-fake" not in str(r) for r in results))

    def test_qa_fails_when_binding_is_accidentally_allowed(self):
        fake = FakeTransport(statuses={"missing": 204})
        results = module.run_qa(fake, CONFIG)
        self.assertIn("FAIL", [r.state for r in results])

    def test_qa_fails_on_missing_body_validation(self):
        fake = FakeTransport(statuses={"malformed": 403})
        results = module.run_qa(fake, CONFIG)
        self.assertIn("FAIL", [r.state for r in results])

    def test_qa_positive_and_cross_client_optional(self):
        fake = FakeTransport(no_scope=False)
        result = module.run_qa(fake, CONFIG, positive=True, cross_client=True)
        self.assertEqual(6, len(result))
        self.assertTrue(all(r.state == "PASS" for r in result), result)

    def test_rejects_scope_changed_in_cognito_response(self):
        fake = FakeTransport(no_scope=False, response_scope="wrong/scope")
        with self.assertRaises(ValueError):
            module.token_from_cognito(fake, CONFIG)

    def test_accepts_cognito_response_without_scope(self):
        fake = FakeTransport(no_scope=True)
        self.assertEqual("mock-valid-token", module.token_from_cognito(fake, CONFIG))

    def test_qa_production_host_not_approved(self):
        env = self.qaenv()
        env["MTC_E321_QA_PROVIDER_URL"] = "https://provider-prd.example.org"
        with self.assertRaises(ValueError):
            module.qa_environment(env)

    @staticmethod
    def qaenv():
        return {
            "MTC_E321_QA_CONFIRM": module.APPROVAL_PHRASE,
            "MTC_E321_QA_PROVIDER_URL": CONFIG["base"],
            "MTC_E321_APPROVED_PROVIDER_HOST": "provider-qa.example.org",
            "MTC_E321_QA_COGNITO_TOKEN_URL": CONFIG["token_url"],
            "MTC_E321_APPROVED_COGNITO_HOST": "cognito-qa.example.org",
            "MTC_E321_QA_CERTIFY_CLIENT_ID": CONFIG["client_id"],
            "MTC_E321_QA_CERTIFY_CLIENT_SECRET": CONFIG["client_secret"],
        }


if __name__ == "__main__":
    unittest.main()
