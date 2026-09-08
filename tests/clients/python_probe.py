"""Live, synthetic-identity Python/FastAPI SDK probe; requires the real OSS Core.

No test doubles, provider calls, raw token output, or skipped-test success. Uses
header and cookie clients against the running API and online session verification.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import pathlib
import sys
import time
import uuid
from datetime import datetime, timezone

import httpx

ROOT = pathlib.Path(__file__).resolve().parents[2]


class OrderedCookieClient(httpx.Client):
    """Model wire-order Set-Cookie processing, including set-then-expire.

    Python's CookieJar batches multiple Set-Cookie headers before storing them;
    when a response sets and then expires the same cookie, it can retain the
    new value. Browser cookie processing follows header order. This wrapper
    restores the pre-response jar and applies each response header in order.
    It fixes the probe transport only; no SDK/server response is changed.
    """
    def send(self, request, **kwargs):
        before = httpx.Cookies(self.cookies)
        response = super().send(request, **kwargs)
        if response.headers.get_list("set-cookie"):
            self.cookies.clear()
            self.cookies.update(before)
            for value in response.headers.get_list("set-cookie"):
                cookie_response = httpx.Response(response.status_code, headers={"set-cookie": value}, request=response.request)
                self.cookies.extract_cookies(cookie_response)
        return response


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


def app_status(response):
    try:
        return response.json().get("status")
    except (ValueError, AttributeError):
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://python-app:8300")
    parser.add_argument("--origin", default="http://localhost:8300")
    parser.add_argument("--evidence-dir", type=pathlib.Path, default=ROOT / "evidence/clients/python")
    args = parser.parse_args()
    events = []
    suffix = uuid.uuid4().hex
    email = f"python-header-{suffix}@example.invalid"
    cookie_email = f"python-cookie-{suffix}@example.invalid"
    password = "P9!" + uuid.uuid4().hex
    form = lambda address, secret: {"formFields": [{"id": "email", "value": address}, {"id": "password", "value": secret}]}
    signup_headers = {"rid": "emailpassword", "fdi-version": "4.2", "st-auth-mode": "header", "Origin": args.origin}
    session_headers = {"rid": "session", "fdi-version": "4.2", "st-auth-mode": "header", "Origin": args.origin}
    shared = {}

    def check(ident, function):
        start = time.monotonic()
        try:
            details = function() or {}
            event = {"id": ident, "status": "passed", "duration_ms": round((time.monotonic() - start) * 1000, 2), "details": details}
        except Exception as error:
            # HTTP responses/tokens are never included in exception details here.
            detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
            event = {"id": ident, "status": "failed", "duration_ms": round((time.monotonic() - start) * 1000, 2), "error": detail}
        events.append(event)
        print(f"{ident}: {event['status']}")
        return event["status"] == "passed"

    with httpx.Client(base_url=args.url, timeout=20, trust_env=False) as client:
        def readiness():
            response = client.get("/ready")
            require(response.status_code == 200, f"readiness HTTP {response.status_code}")
            require(response.json()["cdi_required"] == "5.4", "Python CDI support claim differs")
            return {"http_status": response.status_code, "sdk": response.json()["sdk"], "cdi_required": "5.4"}

        ready = check("PY-READY-CORE-CDI54", readiness)
        if ready:
            def unauthenticated():
                response = client.get("/protected")
                require(response.status_code == 401, f"unauthenticated HTTP {response.status_code}")
                return {"http_status": response.status_code}
            check("PY-NO-SESSION-DENIED", unauthenticated)

            def malformed():
                response = client.get("/protected", headers={**session_headers, "Authorization": "Bearer malformed"})
                require(response.status_code == 401, f"malformed token HTTP {response.status_code}")
                return {"http_status": response.status_code}
            check("PY-MALFORMED-TOKEN-DENIED", malformed)

            def signup():
                response = client.post("/auth/signup", json=form(email, password), headers=signup_headers)
                require(response.status_code == 200 and app_status(response) == "OK", f"signup HTTP {response.status_code} status {app_status(response)}")
                require(bool(response.headers.get("st-access-token")) and bool(response.headers.get("st-refresh-token")), "signup must return header tokens")
                shared["signup_access"] = response.headers["st-access-token"]
                shared["user_id"] = response.json()["user"]["id"]
                return {"http_status": response.status_code, "status": "OK", "token_headers": ["st-access-token", "st-refresh-token"]}
            signed_up = check("PY-HEADER-SIGNUP", signup)

            if signed_up:
                def online_protected():
                    response = client.get("/protected", headers={**session_headers, "Authorization": "Bearer " + shared["signup_access"]})
                    require(response.status_code == 200, f"protected HTTP {response.status_code}")
                    data = response.json()
                    require(data["userId"] == shared["user_id"] and data["tenantId"] == "public", "authenticated identity or tenant differs")
                    require(data["verification"] == "signature-and-online-session-check", "online verification profile differs")
                    return {"http_status": response.status_code, "tenant": "public", "verification": data["verification"]}
                check("PY-HEADER-ONLINE-PROTECTED", online_protected)

                def wrong_password():
                    response = client.post("/auth/signin", json=form(email, "WrongPassword9!"), headers=signup_headers)
                    require(response.status_code == 200 and app_status(response) == "WRONG_CREDENTIALS_ERROR", f"wrong password HTTP {response.status_code} status {app_status(response)}")
                    require(not response.headers.get("st-access-token"), "wrong password returned access token")
                    return {"http_status": response.status_code, "status": app_status(response)}
                check("PY-WRONG-PASSWORD-DENIED", wrong_password)

                def duplicate_signup():
                    response = client.post("/auth/signup", json=form(email, password), headers=signup_headers)
                    require(response.status_code == 200 and app_status(response) == "FIELD_ERROR", f"duplicate signup HTTP {response.status_code} status {app_status(response)}")
                    require(not response.headers.get("st-access-token"), "duplicate signup issued token")
                    return {"http_status": response.status_code, "status": app_status(response)}
                check("PY-DUPLICATE-SIGNUP-DENIED", duplicate_signup)

                def signin():
                    response = client.post("/auth/signin", json=form(email, password), headers=signup_headers)
                    require(response.status_code == 200 and app_status(response) == "OK", f"signin HTTP {response.status_code} status {app_status(response)}")
                    require(response.json()["user"]["id"] == shared["user_id"], "signin created a different identity")
                    shared["access"] = response.headers["st-access-token"]
                    shared["refresh"] = response.headers["st-refresh-token"]
                    return {"http_status": response.status_code, "status": "OK"}
                signed_in = check("PY-HEADER-SIGNIN", signin)

                if signed_in:
                    def refresh():
                        response = client.post("/auth/session/refresh", headers={**session_headers, "Authorization": "Bearer " + shared["refresh"]})
                        require(response.status_code == 200, f"refresh HTTP {response.status_code} status {app_status(response)}")
                        shared["access"] = response.headers["st-access-token"]
                        shared["refresh"] = response.headers["st-refresh-token"]
                        return {"http_status": response.status_code, "token_headers": ["st-access-token", "st-refresh-token"]}
                    check("PY-HEADER-REFRESH", refresh)

                    def logout():
                        response = client.post("/auth/signout", headers={**session_headers, "Authorization": "Bearer " + shared["access"]})
                        require(response.status_code == 200 and app_status(response) == "OK", f"logout HTTP {response.status_code}")
                        return {"http_status": response.status_code}
                    logged_out = check("PY-HEADER-LOGOUT", logout)
                    if logged_out:
                        def revoked_access():
                            response = client.get("/protected", headers={**session_headers, "Authorization": "Bearer " + shared["access"]})
                            require(response.status_code == 401, f"revoked access HTTP {response.status_code}")
                            return {"http_status": response.status_code, "online_revocation_observed": True}
                        check("PY-LOGOUT-ONLINE-ACCESS-DENIED", revoked_access)

                        def revoked_refresh():
                            response = client.post("/auth/session/refresh", headers={**session_headers, "Authorization": "Bearer " + shared["refresh"]})
                            require(response.status_code == 401, f"revoked refresh HTTP {response.status_code}")
                            return {"http_status": response.status_code}
                        check("PY-LOGOUT-REFRESH-DENIED", revoked_refresh)
                client.post("/auth/signout", headers={**session_headers, "Authorization": "Bearer " + shared["signup_access"]})

            def reset_disabled():
                response = client.post("/auth/user/password/reset/token", json={"formFields": [{"id": "email", "value": email}]}, headers=signup_headers)
                require(response.status_code == 404, f"disabled password reset HTTP {response.status_code}")
                return {"http_status": response.status_code, "qualification": "delivery-blocked-no-local-transport"}
            check("PY-RESET-DELIVERY-DISABLED", reset_disabled)

            with OrderedCookieClient(base_url=args.url, timeout=20, trust_env=False) as cookie_client:
                cookie_headers = {"rid": "emailpassword", "fdi-version": "4.2", "st-auth-mode": "cookie", "Origin": args.origin}
                cookie_session_headers = {"rid": "session", "fdi-version": "4.2", "st-auth-mode": "cookie", "Origin": args.origin}

                def cookie_signup():
                    response = cookie_client.post("/auth/signup", json=form(cookie_email, password), headers=cookie_headers)
                    require(response.status_code == 200 and app_status(response) == "OK", f"cookie signup HTTP {response.status_code} status {app_status(response)}")
                    names = sorted(cookie.name for cookie in cookie_client.cookies.jar)
                    require("sAccessToken" in names and "sRefreshToken" in names, "cookie signup omitted required cookies")
                    cookies = response.headers.get_list("set-cookie")
                    access = next(value for value in cookies if value.startswith("sAccessToken="))
                    refresh_cookie = next(value for value in cookies if value.startswith("sRefreshToken="))
                    require("httponly" in access.lower() and "samesite=lax" in access.lower(), "access cookie security attributes differ")
                    require("path=/auth/session/refresh" in refresh_cookie.lower() and "httponly" in refresh_cookie.lower(), "refresh cookie scope/HttpOnly differs")
                    return {"http_status": response.status_code, "cookie_names": names, "http_only": True, "same_site": "lax", "secure": False, "secure_scope": "local HTTP proof only"}
                cookie_ready = check("PY-COOKIE-SIGNUP-ATTRIBUTES", cookie_signup)
                if cookie_ready:
                    def cookie_protected():
                        response = cookie_client.get("/protected")
                        require(response.status_code == 200 and response.json()["tenantId"] == "public", f"cookie protected HTTP {response.status_code}")
                        return {"http_status": response.status_code}
                    check("PY-COOKIE-ONLINE-PROTECTED", cookie_protected)

                    def csrf_denied():
                        response = cookie_client.post("/protected/action")
                        require(response.status_code == 401, f"missing CSRF custom header HTTP {response.status_code}")
                        return {"http_status": response.status_code}
                    check("PY-COOKIE-CSRF-MISSING-HEADER-DENIED", csrf_denied)

                    def csrf_present():
                        response = cookie_client.post("/protected/action", headers=cookie_session_headers)
                        require(response.status_code == 200, f"valid CSRF header HTTP {response.status_code}")
                        return {"http_status": response.status_code}
                    check("PY-COOKIE-CSRF-HEADER-ACCEPTED", csrf_present)

                    def cookie_refresh():
                        response = cookie_client.post("/auth/session/refresh", headers=cookie_session_headers)
                        require(response.status_code == 200, f"cookie refresh HTTP {response.status_code}")
                        return {"http_status": response.status_code}
                    check("PY-COOKIE-REFRESH", cookie_refresh)

                    def cookie_logout():
                        response = cookie_client.post("/auth/signout", headers=cookie_session_headers)
                        require(response.status_code == 200 and app_status(response) == "OK", f"cookie logout HTTP {response.status_code}")
                        require(not cookie_client.cookies.get("sAccessToken") and not cookie_client.cookies.get("sRefreshToken"), "logout did not clear cookies")
                        denied = cookie_client.get("/protected")
                        require(denied.status_code == 401, f"post-logout cookie access HTTP {denied.status_code}")
                        return {"http_status": response.status_code, "post_logout_http_status": denied.status_code, "cookies_cleared": True}
                    check("PY-COOKIE-LOGOUT-CLEAR-AND-DENY", cookie_logout)

    expected_tests = 19
    failed = [event for event in events if event["status"] == "failed"]
    all_executed = len(events) == expected_tests
    code = 0 if not failed and all_executed else 1
    inputs = [ROOT / "examples/python/app.py", ROOT / "examples/python/Dockerfile", ROOT / "examples/python/requirements.lock", pathlib.Path(__file__)]
    report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "command": "python tests/clients/python_probe.py --url " + args.url, "environment": {"python": sys.version, "packages": {name: importlib.metadata.version(name) for name in ("supertokens-python", "fastapi", "uvicorn", "httpx", "starlette")}}, "target": args.url, "scope": "SDKP-02 representative FastAPI password/session header/cookie profile; live real Core", "cookie_client": "OrderedCookieClient applies response Set-Cookie headers in wire order; no browser qualification claimed", "expected_tests": expected_tests, "executed": len(events), "passed": len(events) - len(failed), "failed": len(failed), "unexecuted": expected_tests - len(events), "skipped": 0, "exit_code": code, "tests": events, "input_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}, "not_qualified": ["all other Python SDK recipes", "live social providers", "password reset delivery", "TLS cookie Secure behavior", "complete SDK/framework matrix", "independent security review"]}
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    (args.evidence_dir / "probe-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("executed", "passed", "failed", "unexecuted", "exit_code")}, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
