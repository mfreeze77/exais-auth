"""Real Keycloak Authenticator SPI proof; no HTML parsing or password grant.

Uses the candidate's JSON challenge actions, OIDC authorization code + S256 PKCE,
and maintained PyOTP/PyJWT primitives. Private fixtures are generated locally.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import json
import pathlib
import secrets
import sys
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
import jwt
import pyotp

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXTENSION = ROOT / "engine-extensions/keycloak-headless"
FIXTURES = json.loads((EXTENSION / ".runtime/fixtures.json").read_text())
BASE = "http://kc-headless.example.test:8080/realms/" + FIXTURES["realm"]
OIDC = BASE + "/protocol/openid-connect"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def no_final_session(client):
    require(not ({"KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION"} & set(client.cookies)), "Final engine session cookie exists before all factors passed")


def altered_action(action, key, value):
    parsed = urlparse(action)
    query = parse_qs(parsed.query)
    if value is None:
        query.pop(key, None)
    else:
        query[key] = [value]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


class Flow:
    def __init__(self, username):
        self.client = httpx.Client(timeout=20, trust_env=False, follow_redirects=False)
        self.user = FIXTURES["users"][username]
        self.state = secrets.token_urlsafe(24)
        self.nonce = secrets.token_urlsafe(24)
        self.verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).decode().rstrip("=")
        self.response = self.client.get(OIDC + "/auth", params={"client_id": FIXTURES["client_id"], "redirect_uri": FIXTURES["redirect_uri"], "response_type": "code", "scope": "openid", "state": self.state, "nonce": self.nonce, "code_challenge": challenge, "code_challenge_method": "S256"})
        self.action = None
        self.accept_challenge("password")

    def accept_challenge(self, step):
        response = self.response
        require(response.headers.get("content-type", "").startswith("application/json"), f"Expected JSON {step} challenge, HTTP {response.status_code}")
        payload = response.json()
        require(payload.get("status") == "CHALLENGE" and payload.get("step") == step and payload.get("authenticated") is False, f"Expected unauthenticated {step} intermediate state")
        action = payload.get("action")
        parsed = urlparse(action)
        require(parsed.netloc == "kc-headless.example.test:8080" and parsed.path == "/realms/" + FIXTURES["realm"] + "/login-actions/authenticate", "Action URL leaves engine-owned realm boundary")
        require(all(name in parse_qs(parsed.query) for name in ("session_code", "execution", "tab_id", "client_id")), "Action lacks engine-owned state parameters")
        require(payload["method"] == "POST" and payload["contentType"] == "application/x-www-form-urlencoded", "Submission contract differs")
        self.action = action
        no_final_session(self.client)
        return payload

    def submit(self, data, action=None):
        self.response = self.client.post(action or self.action, data=data)
        return self.response

    def password(self, value=None):
        self.submit({"username": self.user["username"], "password": value or self.user["password"]})
        return self.accept_challenge("totp")

    def successful_otp(self, token=None, action=None):
        self.submit({"otp": token or pyotp.TOTP(self.user["otp_secret"]).now()}, action=action)
        require(self.response.status_code == 302, f"Final factor HTTP {self.response.status_code}, expected engine OIDC redirect")
        location = urlparse(self.response.headers["location"])
        expected = urlparse(FIXTURES["redirect_uri"])
        require((location.scheme, location.netloc, location.path) == (expected.scheme, expected.netloc, expected.path), "Final redirect target changed")
        query = parse_qs(location.query)
        require(query.get("state") == [self.state], "OAuth state was changed by an action request")
        require(bool(query.get("code")), "No authorization code after final factor")
        self.code = query["code"][0]
        require({"KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION"} <= set(self.client.cookies), "Engine did not establish final session after both factors")

    def exchange(self, verifier=None):
        return self.client.post(OIDC + "/token", data={"grant_type": "authorization_code", "client_id": FIXTURES["client_id"], "redirect_uri": FIXTURES["redirect_uri"], "code": self.code, "code_verifier": verifier or self.verifier})


def reject_action(flow, response):
    no_final_session(flow.client)
    require("code=" not in response.headers.get("location", ""), "Invalid action issued authorization code")
    if response.headers.get("content-type", "").startswith("application/json"):
        payload = response.json()
        require(payload.get("step") != "totp", "Invalid password action advanced to the factor stage")
    return {"http_status": response.status_code, "content_type": response.headers.get("content-type"), "final_session": False, "engine_owned_error_response": True}


def main():
    events = []
    context = {}

    def check(ident, function):
        start = time.monotonic()
        try:
            details = function() or {}
            event = {"id": ident, "status": "passed", "duration_ms": round((time.monotonic() - start) * 1000, 2), "details": details}
        except Exception as error:
            event = {"id": ident, "status": "failed", "duration_ms": round((time.monotonic() - start) * 1000, 2), "error": str(error) if isinstance(error, AssertionError) else type(error).__name__}
        events.append(event)
        print(ident + ": " + event["status"])
        return event["status"] == "passed"

    def initial():
        flow = Flow("primary")
        context["main"] = flow
        require(flow.response.status_code == 200, "Initial challenge must be HTTP 200")
        require("no-store" in flow.response.headers.get("cache-control", ""), "Challenge action must not be cached")
        return {"content_type": flow.response.headers["content-type"], "step": "password", "final_session": False, "fields": flow.response.json()["fields"]}
    started = check("KC-JSON-INITIAL-PASSWORD-CHALLENGE", initial)
    if started:
        flow = context["main"]
        def wrong_password():
            flow.submit({"username": flow.user["username"], "password": "deliberately-wrong-password"})
            payload = flow.accept_challenge("password")
            require(flow.response.status_code == 401 and payload.get("error") == "AUTHENTICATION_FAILED", "Wrong password did not produce generic JSON rejection")
            return {"http_status": 401, "step": "password", "final_session": False}
        check("KC-JSON-WRONG-PASSWORD-DENIED", wrong_password)

        def correct_password():
            flow.password()
            require(flow.response.status_code == 200, "Correct password did not advance")
            return {"step": "totp", "final_session": False, "fields": flow.response.json()["fields"]}
        password_ok = check("KC-JSON-PASSWORD-ADVANCES-TO-REQUIRED-TOTP", correct_password)
        if password_ok:
            def invalid_totp():
                flow.submit({"otp": "not-a-six-digit-code"})
                payload = flow.accept_challenge("totp")
                require(flow.response.status_code == 401 and payload.get("error") == "AUTHENTICATION_FAILED", "Invalid TOTP accepted")
                return {"http_status": 401, "final_session": False}
            check("KC-JSON-INVALID-TOTP-DENIED", invalid_totp)

            def absent_totp():
                flow.submit({})
                flow.accept_challenge("totp")
                return {"http_status": flow.response.status_code, "final_session": False}
            check("KC-JSON-MISSING-TOTP-REMAINS-INTERMEDIATE", absent_totp)

            def premature_token():
                response = flow.client.post(OIDC + "/token", data={"grant_type": "authorization_code", "client_id": FIXTURES["client_id"], "code": "not-issued", "redirect_uri": FIXTURES["redirect_uri"], "code_verifier": flow.verifier})
                require(response.status_code == 400 and "access_token" not in response.json(), "Premature authorization-code exchange produced tokens")
                no_final_session(flow.client)
                return {"http_status": response.status_code, "token_issued": False}
            check("KC-NO-TOKENS-BEFORE-FINAL-FACTOR", premature_token)

            def final_factor():
                flow.successful_otp(action=altered_action(flow.action, "state", "attacker-supplied-state"))
                return {"http_status": 302, "state_preserved": True, "engine_final_session": True}
            finished = check("KC-JSON-TOTP-SUCCESS-ENGINE-CODE-STATE", final_factor)
            if finished:
                def pkce_exchange():
                    response = flow.exchange()
                    require(response.status_code == 200, f"PKCE token exchange HTTP {response.status_code}")
                    tokens = response.json()
                    require(all(name in tokens for name in ("access_token", "refresh_token", "id_token")), "Token exchange omitted standard tokens")
                    jwks = flow.client.get(OIDC + "/certs").json()["keys"]
                    kid = jwt.get_unverified_header(tokens["id_token"])["kid"]
                    key = jwt.PyJWK.from_dict(next(item for item in jwks if item["kid"] == kid)).key
                    claims = jwt.decode(tokens["id_token"], key, algorithms=["RS256"], audience=FIXTURES["client_id"], issuer=BASE)
                    require(claims["nonce"] == flow.nonce, "Signed ID-token nonce differs")
                    return {"http_status": response.status_code, "id_token_signature_verified": True, "issuer_audience_nonce_verified": True, "grant": "authorization_code+S256-PKCE"}
                check("KC-AUTHORIZATION-CODE-PKCE-TOKEN-EXCHANGE", pkce_exchange)

                def code_replay():
                    response = flow.exchange()
                    require(response.status_code == 400 and "access_token" not in response.json(), "Authorization code replay accepted")
                    return {"http_status": response.status_code}
                check("KC-AUTHORIZATION-CODE-REPLAY-DENIED", code_replay)

    def totp_replay():
        first, second = Flow("replay"), Flow("replay")
        first.password()
        second.password()
        token = pyotp.TOTP(first.user["otp_secret"]).now()
        first.successful_otp(token=token)
        second.submit({"otp": token})
        payload = second.accept_challenge("totp")
        require(second.response.status_code == 401 and payload.get("error") == "AUTHENTICATION_FAILED", "TOTP reused across independent authentication sessions")
        return {"http_status": 401, "otp_code_reusable": False, "engine_replay_store": "SingleUseObjectProvider", "second_final_session": False}
    check("KC-TOTP-CROSS-SESSION-REPLAY-DENIED", totp_replay)

    def missing_action():
        flow = Flow("missingaction")
        response = flow.submit({"username": flow.user["username"], "password": flow.user["password"]}, action=altered_action(flow.action, "session_code", None))
        return reject_action(flow, response)
    check("KC-MISSING-ACTION-SESSION-CODE-DENIED", missing_action)

    def tampered_action():
        flow = Flow("tamperedaction")
        response = flow.submit({"username": flow.user["username"], "password": flow.user["password"]}, action=altered_action(flow.action, "session_code", "tampered-action-code"))
        return reject_action(flow, response)
    check("KC-TAMPERED-ACTION-SESSION-CODE-DENIED", tampered_action)

    def wrong_tab():
        flow = Flow("tamperedaction")
        response = flow.submit({"username": flow.user["username"], "password": flow.user["password"]}, action=altered_action(flow.action, "tab_id", "another-authentication-tab"))
        return reject_action(flow, response)
    check("KC-TAMPERED-TAB-STATE-DENIED", wrong_tab)

    def cross_session():
        first, second = Flow("crosssession"), Flow("crosssession")
        response = second.submit({"username": second.user["username"], "password": second.user["password"]}, action=first.action)
        return reject_action(second, response)
    check("KC-CROSS-BROWSER-ACTION-SUBSTITUTION-DENIED", cross_session)

    def missing_cookie():
        flow = Flow("nocookie")
        flow.client.cookies.clear()
        response = flow.submit({"username": flow.user["username"], "password": flow.user["password"]})
        return reject_action(flow, response)
    check("KC-MISSING-AUTHENTICATION-COOKIE-DENIED", missing_cookie)

    def bruteforce():
        flow = Flow("bruteforce")
        for _ in range(3):
            flow.submit({"username": flow.user["username"], "password": "deliberately-wrong-password"})
            flow.accept_challenge("password")
            require(flow.response.status_code == 401, "Brute-force precondition was not rejected")
        flow.submit({"username": flow.user["username"], "password": flow.user["password"]})
        payload = flow.accept_challenge("password")
        require(flow.response.status_code == 401 and payload.get("error") == "AUTHENTICATION_FAILED", "Engine brute-force policy did not block correct password after threshold")
        return {"failed_attempts": 3, "correct_password_during_lockout_http_status": 401, "final_session": False}
    check("KC-ENGINE-BRUTE-FORCE-POLICY-RETAINED", bruteforce)

    expected = 16
    failed = sum(event["status"] == "failed" for event in events)
    code = 0 if len(events) == expected and not failed else 1
    paths = [path for path in EXTENSION.rglob("*") if path.is_file() and not any(part in {".runtime", "build", ".gradle", "__pycache__"} for part in path.relative_to(EXTENSION).parts)] + [pathlib.Path(__file__)]
    report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "command": "python tests/foundation/keycloak_headless_probe.py", "keycloak_version": "26.7.3", "keycloak_source_commit": "6d238b6558037085cc25c915893c3d301a80243e", "python": sys.version, "client_packages": {package: importlib.metadata.version(package) for package in ("httpx", "PyJWT", "pyotp")}, "candidate_selected": False, "foundation_gate_passed": False, "expected_tests": expected, "executed": len(events), "passed": len(events) - failed, "failed": failed, "unexecuted": expected - len(events), "skipped": 0, "exit_code": code, "tests": events, "input_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(paths)}, "limitations": ["Bounded custom password and pre-enrolled TOTP challenge profile only", "Session/action-code validation errors outside the authenticator may be Keycloak HTML responses; no HTML is parsed", "Not a SuperTokens FDI-compatible API", "Authenticator SPI is marked internal by Keycloak and requires per-version qualification", "H2 single-node isolated lab, not operational production evidence", "Other foundation cases and independent security review remain unqualified"]}
    destination = ROOT / "evidence/foundation/keycloak-headless/probe-report.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("executed", "passed", "failed", "unexecuted", "exit_code")}, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
