#!/usr/bin/env python3
"""MTC E03.21: only-read QA Certify -> Provider smoke; no secrets/tokens in output.

Default is offline static-contract checking. Network mode requires explicit QA
approval and host pinning, never writes to Provider or Cognito aside from obtaining
the OAuth client_credentials token. Do not run against PRD.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import sys
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote_plus, urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

CERTIFY_SCOPE = "mtc-wallet-provider/wallet.issuance.certify"
MIMOTO_SCOPE = "mtc-wallet-provider/wallet.identity.mimoto"
ENDPOINT = "/api/v1/internal/identity/certify/authorize-issuance"
APPROVAL_PHRASE = "CONFIRMO_QA_NO_PRODUCCION"


@dataclass(frozen=True)
class Result:
    name: str
    state: str
    detail: str = ""


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes = b""


class Transport(Protocol):
    def post(self, url: str, headers: dict[str, str], body: bytes) -> Response: ...


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpsTransport:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), NoRedirect())

    def post(self, url: str, headers: dict[str, str], body: bytes) -> Response:
        request = Request(url, data=body, headers=headers, method="POST")
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                # The client does not print or persist response bodies.
                return Response(response.status, response.read(32769))
        except HTTPError as error:
            error.close()
            return Response(error.code)
        except (URLError, OSError, TimeoutError) as exc:
            # Do not include URL, proxy or credential-bearing diagnostic bodies.
            raise RuntimeError("No se pudo completar la conexión HTTPS de QA") from None


def checked_https(url: str, *, origin: bool = False, token: bool = False) -> str:
    parts = urlsplit(url)
    if (parts.scheme != "https" or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.query or parts.fragment
            or not parts.netloc or "\\" in url or " " in url):
        raise ValueError("Se requiere URL HTTPS de servicio, sin credenciales ni query")
    if origin and parts.path not in ("", "/"):
        raise ValueError("Provider debe ser solo su origen HTTPS")
    if token and not parts.path.endswith("/oauth2/token"):
        raise ValueError("El endpoint de Cognito debe terminar en /oauth2/token")
    if parts.hostname in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("La prueba QA exige un servicio remoto HTTPS")
    return parts.hostname.lower()


def qa_environment(env: dict[str, str]) -> dict[str, str]:
    if env.get("MTC_E321_QA_CONFIRM") != APPROVAL_PHRASE:
        raise ValueError("Falta confirmación explícita de laboratorio QA")
    base = env.get("MTC_E321_QA_PROVIDER_URL", "")
    host = checked_https(base, origin=True)
    approved = env.get("MTC_E321_APPROVED_PROVIDER_HOST", "").strip().lower()
    if host != approved:
        raise ValueError("Hostname de Provider no corresponde al QA aprobado")
    token = env.get("MTC_E321_QA_COGNITO_TOKEN_URL", "")
    token_host = checked_https(token, token=True)
    if token_host != env.get("MTC_E321_APPROVED_COGNITO_HOST", "").strip().lower():
        raise ValueError("Hostname Cognito no corresponde al QA aprobado")
    for hostname in (host, token_host):
        if re.search(r"(^|[.\-])(prod|prd|production|live)([.\-]|$)", hostname):
            raise ValueError("Dominio aparentemente productivo: prohibido en el laboratorio")
    values = {
        "base": base.rstrip("/"), "token_url": token,
        "client_id": env.get("MTC_E321_QA_CERTIFY_CLIENT_ID", ""),
        "client_secret": env.get("MTC_E321_QA_CERTIFY_CLIENT_SECRET", ""),
        "mimoto_id": env.get("MTC_E321_QA_MIMOTO_CLIENT_ID", ""),
        "mimoto_secret": env.get("MTC_E321_QA_MIMOTO_CLIENT_SECRET", ""),
        "thumbprint": env.get("MTC_E321_QA_KNOWN_THUMBPRINT", ""),
        "nonce": env.get("MTC_E321_QA_KNOWN_NONCE", ""),
    }
    if not values["client_id"] or not values["client_secret"]:
        raise ValueError("Credenciales de cliente Certify QA ausentes")
    if len(values["client_id"]) > 256 or len(values["client_secret"]) > 2048:
        raise ValueError("Credenciales fuera de límites aceptados")
    return values


def token_from_cognito(transport: Transport, config: dict[str, str], *, mimoto=False) -> str:
    client_id = config["mimoto_id"] if mimoto else config["client_id"]
    secret = config["mimoto_secret"] if mimoto else config["client_secret"]
    scope = MIMOTO_SCOPE if mimoto else CERTIFY_SCOPE
    if not client_id or not secret:
        raise ValueError("Cliente M2M requerido no está configurado")
    # Mirrors Certify's RFC6749-encoded OAuth Basic request.
    basic = base64.b64encode(f"{quote_plus(client_id)}:{quote_plus(secret)}".encode("utf-8")).decode("ascii")
    body = f"grant_type=client_credentials&scope={quote_plus(scope)}".encode("ascii")
    reply = transport.post(config["token_url"], {
        "Authorization": "Basic " + basic,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }, body)
    if reply.status != 200 or len(reply.body) > 32768:
        raise ValueError("Cognito no entregó un token M2M QA válido")
    try:
        data = json.loads(reply.body)
        if not isinstance(data, dict):
            raise ValueError()
        token = data.get("access_token")
        token_type = data.get("token_type")
        # RFC6749: response scope is optional if same as the request. Provider
        # independently verifies the SIGNED access token claims at request time.
        granted = data.get("scope")
        if (not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~-]{1,8192}", token)
                or not isinstance(token_type, str) or token_type.lower() != "bearer"
                or (granted is not None and granted.strip() != scope)):
            raise ValueError()
        return token
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Respuesta OAuth2 M2M incorrecta") from None


def post_provider(transport: Transport, config: dict[str, str], payload: dict[str, str], token: str | None) -> Response:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    return transport.post(config["base"] + ENDPOINT, headers,
                          json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def run_qa(transport: Transport, config: dict[str, str], *, positive: bool = False,
           cross_client: bool = False) -> list[Result]:
    results = []
    thumbprint = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    nonce = "mtc-e321-qa-readonly-" + secrets.token_hex(24)
    nonexistent = {"credentialKeyThumbprint": thumbprint, "issuerNonce": nonce}

    def check(name, acceptable, fn):
        try:
            reply = fn()
            ok = reply.status in acceptable
            results.append(Result(name, "PASS" if ok else "FAIL", f"HTTP {reply.status}; esperado {sorted(acceptable)}"))
        except (RuntimeError, ValueError) as error:
            results.append(Result(name, "FAIL", type(error).__name__))

    # 1. Without a bearer token: must be denied regardless of payload.
    check("Sin bearer", {401, 403}, lambda: post_provider(transport, config, nonexistent, None))

    # 2. Real QA Cognito token; token is kept ONLY in process memory.
    try:
        jwt = token_from_cognito(transport, config)
        results.append(Result("OAuth2 Certify", "PASS", "Token recibido; valor no mostrado"))
    except (ValueError, RuntimeError) as error:
        results.append(Result("OAuth2 Certify", "FAIL", type(error).__name__))
        return results

    # 3. Token accepted by Provider security, body rejected by Bean Validation.
    malformed = {"credentialKeyThumbprint": "invalid", "issuerNonce": "x"}
    check("Body malformado", {400}, lambda: post_provider(transport, config, malformed, jwt))

    # 4. Valid, random, unregistered cryptographic binding must not authorize.
    check("Binding inexistente", {403}, lambda: post_provider(transport, config, nonexistent, jwt))

    if cross_client:
        if not (config["mimoto_id"] and config["mimoto_secret"]):
            results.append(Result("Aislamiento MiMoto", "FAIL", "Credenciales QA MiMoto ausentes"))
        else:
            try:
                mimoto = token_from_cognito(transport, config, mimoto=True)
                check("Aislamiento MiMoto", {403}, lambda: post_provider(transport, config, nonexistent, mimoto))
            except (ValueError, RuntimeError) as error:
                results.append(Result("Aislamiento MiMoto", "FAIL", type(error).__name__))

    if positive:
        if (not re.fullmatch(r"[A-Za-z0-9_-]{43}", config["thumbprint"]) or
                not config["nonce"] or len(config["nonce"]) > 1024):
            results.append(Result("Binding QA vigente", "FAIL", "Falta referencia QA preexistente válida"))
        else:
            known = {"credentialKeyThumbprint": config["thumbprint"], "issuerNonce": config["nonce"]}
            check("Binding QA vigente", {204}, lambda: post_provider(transport, config, known, jwt))
    return results


def run_offline(repo_root: Path) -> list[Result]:
    cases = [
        ("Guard Certify", "inji-certify/certify-service/src/main/java/io/mosip/certify/security/MtcCertifyProviderIssuanceGuard.java",
         ("granted == null", 'EXPECTED_SCOPE.equals(granted.textValue().trim())', 'response.status() != 204', "authorizeVerifiedProof")),
        ("Seguridad Provider", "mcs-wallet-provider/src/main/java/pe/gob/mtc/walletprovider/config/SecurityConfig.java",
         ("certifyIssuanceM2m()", "SCOPE_wallet.issuance.certify", '"access".equals(', "allowed.contains(token.getClaimAsString(\"client_id\"))")),
        ("API Certify Provider", "mcs-wallet-provider/src/main/java/pe/gob/mtc/walletprovider/identity/CertifyIssuanceM2mController.java",
         ("/authorize-issuance", "activeAccreditedBinding(", "ResponseEntity.noContent()")),
        ("Registro DB", "mcs-wallet-provider/src/main/java/pe/gob/mtc/walletprovider/identity/CredentialKeyBindingRegistry.java",
         ("wallet_provider.wp_credential_key_binding", "b.expires_at>CURRENT_TIMESTAMP", "ih.status='ACTIVE'")),
    ]
    results = []
    for label, relative, needles in cases:
        try:
            code = (repo_root / relative).read_text(encoding="utf-8")
            ok = all(needle in code for needle in needles)
            results.append(Result(label, "PASS" if ok else "FAIL", "Contrato local coincidente" if ok else "Contrato ausente o modificado"))
        except OSError:
            results.append(Result(label, "FAIL", "Archivo del repositorio no encontrado"))
    return results


def main() -> int:
    cli = argparse.ArgumentParser(description="MTC E03.21 · Contrato local y preflight QA solo lectura")
    options = cli.add_mutually_exclusive_group()
    options.add_argument("--offline", action="store_true", help="sin red, modo por defecto")
    options.add_argument("--qa", action="store_true", help="acceso explícito a QA previamente aprobado")
    cli.add_argument("--positive", action="store_true", help="QA: probar binding vigente conocido (204)")
    cli.add_argument("--cross-client", action="store_true", help="QA: comprobar aislamiento con cliente MiMoto")
    cli.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    args = cli.parse_args()
    if not args.qa and (args.positive or args.cross_client):
        cli.error("--positive y --cross-client requieren --qa")
    if args.qa:
        try:
            config = qa_environment(dict(os.environ))
            results = run_qa(HttpsTransport(), config, positive=args.positive,
                             cross_client=args.cross_client)
        except (ValueError, RuntimeError) as error:
            print(f"[BLOQUEADO] {error.__class__.__name__}: configuración QA incompleta o no autorizada")
            return 2
    else:
        results = run_offline(args.repo)
    for r in results:
        print(f"[{r.state}] {r.name}: {r.detail}")
    passed = sum(r.state == "PASS" for r in results)
    print(f"RESUMEN: {passed}/{len(results)} comprobaciones aprobadas")
    return 0 if passed == len(results) and results else 1


if __name__ == "__main__":
    sys.exit(main())
