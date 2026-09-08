"""Reproduce the HTTP client's cookie batching defect with real SDK responses."""
import hashlib
import importlib.util
import json
import pathlib
import re
import uuid
from datetime import datetime, timezone

import httpx

ROOT = pathlib.Path("/work")
spec = importlib.util.spec_from_file_location("python_probe", ROOT / "tests/clients/python_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
results = []
for client_type in (httpx.Client, probe.OrderedCookieClient):
    with client_type(base_url="http://python-app:8300", trust_env=False, timeout=20) as client:
        signup = client.post("/auth/signup", headers={"rid": "emailpassword", "fdi-version": "4.2", "st-auth-mode": "cookie"}, json={"formFields": [{"id": "email", "value": uuid.uuid4().hex + "@example.invalid"}, {"id": "password", "value": "P9!" + uuid.uuid4().hex}]})
        assert signup.status_code == 200 and signup.json()["status"] == "OK"
        refresh = client.post("/auth/session/refresh", headers={"rid": "session", "st-auth-mode": "cookie"})
        assert refresh.status_code == 200
        logout = client.post("/auth/signout", headers={"rid": "session", "st-auth-mode": "cookie"})
        assert logout.status_code == 200
        cookies = [re.sub(r"^[^=]+=[^;]*", lambda match: match[0].split("=")[0] + "=<redacted>", value) for value in logout.headers.get_list("set-cookie")]
        residual = sorted(cookie.name for cookie in client.cookies.jar)
        protected = client.get("/protected")
        results.append({"client": client_type.__name__, "signout_http_status": logout.status_code, "response_set_cookie_headers_in_wire_order": cookies, "cookie_names_after_signout": residual, "protected_http_status_after_signout": protected.status_code})
assert results[0]["cookie_names_after_signout"] == ["sAccessToken"], "Expected original-client defect did not reproduce; investigate before changing assertions"
assert results[1]["cookie_names_after_signout"] == [], "Corrected wire-order transport failed to clear cookies"
assert all(result["protected_http_status_after_signout"] == 401 for result in results), "Server-side revocation failed"
report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "command": "python examples/python/cookie_diagnostic.py", "results": results, "exit_code": 0, "conclusion": "The real SDK revokes the session and expires cookies. HTTP client's batched same-name cookie parsing caused the original residual-cookie assertion; wire-order processing preserves the acceptance test. Actual browser qualification remains unexecuted.", "input_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in (pathlib.Path(__file__), ROOT / "tests/clients/python_probe.py", ROOT / "examples/python/app.py")}}
(ROOT / "evidence/clients/python/cookie-client-diagnostic.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
