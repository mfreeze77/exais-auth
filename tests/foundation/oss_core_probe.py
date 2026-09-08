"""Real private-CDI characterization of audited OSS Core, never full-parity certification.

Request fields and legacy refresh expectations come from Apache-licensed handlers at
the pinned source revision below. No enterprise classes, activation calls, test flags,
database writes, or replacement refresh-token store are used. Credentials live only
in this process and the authoritative engine. Run only against disposable local Core
replicas sharing the launcher's PostgreSQL database.
"""
from __future__ import annotations

import concurrent.futures
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

REVISION = "b2219c4aa019a501e4dfea76cf06ef802ca93fc0"
CDI = "5.3"
ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "evidence/foundation/oss-core"
SOURCE = ROOT / ".cache/reuse-audit/source/supertokens__supertokens-core" / REVISION
SOURCE_FILES = [
    "webserver/WebserverAPI.java", "webserver/api/emailpassword/SignUpAPI.java",
    "webserver/api/emailpassword/SignInAPI.java", "webserver/api/session/SessionAPI.java",
    "webserver/api/session/VerifySessionAPI.java", "webserver/api/session/RefreshSessionAPI.java",
    "webserver/api/session/SessionRemoveAPI.java", "session/Session.java",
    "webserver/api/multitenancy/CreateOrUpdateAppV2API.java",
    "webserver/api/multitenancy/CreateOrUpdateTenantOrGetTenantV2API.java",
    "webserver/api/multitenancy/BaseCreateOrUpdate.java",
    "webserver/api/multitenancy/AssociateUserToTenantAPI.java",
    "webserver/api/multitenancy/DisassociateUserFromTenant.java",
    "webserver/api/accountlinking/CreatePrimaryUserAPI.java",
    "webserver/api/accountlinking/LinkAccountsAPI.java",
    "webserver/api/accountlinking/UnlinkAccountAPI.java",
    "webserver/api/thirdparty/SignInUpAPI.java",
]


class HarnessError(Exception):
    """Controlled diagnostics contain no raw response or credential material."""


def token(session, field):
    value = session.get(field)
    if not isinstance(value, dict) or not isinstance(value.get("token"), str):
        raise HarnessError(f"Required {field} response shape missing")
    return value["token"]


def core_status(response):
    return response[1].get("status") if isinstance(response[1], dict) else None


def ok(response):
    return response[0] == 200 and core_status(response) == "OK"


class Probe:
    def __init__(self):
        self.replicas = [os.environ.get("EXPERTAUTH_CORE_A", "http://core-a:3567"),
                         os.environ.get("EXPERTAUTH_CORE_B", "http://core-b:3567")]
        for base in self.replicas:
            parsed = urllib.parse.urlparse(base)
            if parsed.scheme != "http" or parsed.hostname not in {"core-a", "core-b", "localhost", "127.0.0.1"} or parsed.username:
                raise HarnessError("Probe targets must be disposable local Core endpoints")
        self.key = os.environ.get("EXPERTAUTH_CORE_API_KEY")
        if not self.key:
            raise HarnessError("EXPERTAUTH_CORE_API_KEY is required")
        self.password = secrets.token_urlsafe(28)
        self.cdi = CDI
        self.suffix = secrets.token_hex(6)
        self.rows, self.requests = [], []
        self.request_lock = threading.Lock()
        self.started = dt.datetime.now(dt.timezone.utc).isoformat()

    def path(self, path, app="public", tenant="public"):
        return ("" if app == "public" else f"/appid-{app}") + ("" if tenant == "public" else f"/{tenant}") + path

    def request(self, method, path, data=None, *, replica=0, recipe="session", app="public", tenant="public", key=True):
        full_path = self.path(path, app, tenant)
        headers = {"cdi-version": self.cdi, "rid": recipe}
        if key is not False:
            headers["api-key"] = self.key if key is True else key
        raw = None
        if data is not None:
            raw = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.replicas[replica] + full_path, raw, headers, method=method)
        start = time.monotonic()
        try:
            response = urllib.request.urlopen(request, timeout=20)
        except urllib.error.HTTPError as exc:
            response = exc
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            raise HarnessError(f"Core replica {replica} request transport failed ({type(exc).__name__})") from None
        with response:
            status = response.status
            body = response.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = body
        elapsed = round((time.monotonic() - start) * 1000, 3)
        with self.request_lock:
            self.requests.append({"method": method, "path": full_path.split("?", 1)[0], "replica": replica,
                                  "cdi_version": self.cdi,
                                  "http_status": status, "core_status": parsed.get("status") if isinstance(parsed, dict) else None,
                                  "duration_ms": elapsed, "request_body_recorded": False, "response_body_recorded": False})
        return status, parsed

    def result(self, identifier, passed, requirements, note, **observed):
        row = {"test_id": identifier, "outcome": "passed" if passed else "failed",
               "requirements": requirements, "note": note, "observed": observed}
        self.rows.append(row)
        print(f"{identifier}: {row['outcome']}", flush=True)
        return passed

    def unavailable(self, identifier, requirements, reason, response=None):
        self.rows.append({"test_id": identifier, "outcome": "unavailable", "requirements": requirements,
                          "reason": reason, "http_status": response[0] if response else None,
                          "core_status": core_status(response) if response else None,
                          "entitlement_boundary_observed": bool(response and response[0] == 402)})
        print(f"{identifier}: unavailable ({reason})", flush=True)

    def required_ok(self, response, action):
        if not ok(response):
            raise HarnessError(f"{action} failed: HTTP {response[0]}, status {core_status(response)}")
        return response[1]

    def signup(self, label, *, app="public", tenant="public", email=None, replica=0):
        email = email or f"{label}-{self.suffix}@example.test"
        response = self.request("POST", "/recipe/signup", {"email": email, "password": self.password},
                                app=app, tenant=tenant, replica=replica, recipe="emailpassword")
        return response, email

    def signin(self, email, *, password=None, app="public", tenant="public", replica=1):
        return self.request("POST", "/recipe/signin", {"email": email, "password": password or self.password},
                            app=app, tenant=tenant, replica=replica, recipe="emailpassword")

    def create_session(self, user, *, app="public", tenant="public", replica=0):
        response = self.request("POST", "/recipe/session", {
            "userId": user, "enableAntiCsrf": True, "userDataInJWT": {"probe": self.suffix},
            "userDataInDatabase": {"synthetic": True}, "useDynamicSigningKey": True,
        }, app=app, tenant=tenant, replica=replica)
        return self.required_ok(response, "Session creation")

    def verify(self, session, *, app="public", replica=1, online=True, csrf=None):
        return self.request("POST", "/recipe/session/verify", {
            "accessToken": token(session, "accessToken"),
            "antiCsrfToken": session.get("antiCsrfToken") if csrf is None else csrf,
            "enableAntiCsrf": True, "doAntiCsrfCheck": True, "checkDatabase": online,
        }, app=app, replica=replica)

    def refresh(self, session, *, app="public", replica=1):
        return self.request("POST", "/recipe/session/refresh", {
            "refreshToken": token(session, "refreshToken"), "antiCsrfToken": session.get("antiCsrfToken"),
            "enableAntiCsrf": True, "useDynamicSigningKey": True,
        }, app=app, replica=replica)

    def revoke(self, session, *, app="public", replica=0):
        return self.request("POST", "/recipe/session/remove", {"sessionHandles": [session["session"]["handle"]]},
                            app=app, replica=replica)

    def ready(self):
        # Launcher owns startup/health waits. Avoid looping over an unchanged failure here.
        for replica in (0, 1):
            response = self.request("GET", "/hello", replica=replica)
            if response[0] != 200:
                raise HarnessError(f"Core replica {replica} not ready")

    def basic(self):
        payload = {"email": f"denied-{self.suffix}@example.test", "password": self.password}
        missing = self.request("POST", "/recipe/signup", payload, recipe="emailpassword", key=False)
        wrong = self.request("POST", "/recipe/signup", payload, recipe="emailpassword", key="invalid-probe-api-key-00000000")
        self.result("OSS-PRIVATE-001", missing[0] == wrong[0] == 401, ["CFG-004"],
                    "Private credential endpoint rejects absent and wrong API keys.", statuses=[missing[0], wrong[0]])
        response, email = self.signup("basic")
        user = self.required_ok(response, "Password signup")["recipeUserId"]
        login = self.signin(email)
        bad = self.signin(email, password=secrets.token_urlsafe(28))
        duplicate, _ = self.signup("basic", email=email, replica=1)
        self.result("OSS-PASSWORD-001", ok(login) and login[1].get("recipeUserId") == user,
                    ["PWD-001"], "Signup on A and actual password verification on B preserve identity.")
        self.result("OSS-PASSWORD-NEGATIVE-001", core_status(bad) == "WRONG_CREDENTIALS_ERROR" and
                    core_status(duplicate) == "EMAIL_ALREADY_EXISTS_ERROR", ["PWD-001", "IDN-012"],
                    "Wrong password rejected; same-tenant duplicate cannot create another identity.",
                    wrong_password_status=core_status(bad), duplicate_status=core_status(duplicate))
        race_email = f"signup-race-{self.suffix}@example.test"
        barrier = threading.Barrier(2)
        def signup_race(replica):
            barrier.wait(timeout=10)
            return self.signup("race", email=race_email, replica=replica)[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            raced = list(pool.map(signup_race, (0, 1)))
        outcomes = sorted(core_status(r) or f"HTTP-{r[0]}" for r in raced)
        self.result("OSS-PASSWORD-RACE-001", outcomes == ["EMAIL_ALREADY_EXISTS_ERROR", "OK"],
                    ["IDN-012", "PWD-001"], "Two-replica duplicate signup converges on one identity.", statuses=outcomes)
        return user

    def sessions(self, user):
        session = self.create_session(user)
        good, csrf_bad = self.verify(session), self.verify(session, csrf="wrong-anti-csrf")
        self.result("OSS-SESSION-001", ok(good) and good[1]["session"]["userId"] == user,
                    ["SES-001", "SES-011"], "Session minted on A verifies against B; identity/data owned by Core.")
        self.result("OSS-CSRF-001", not ok(csrf_bad) and csrf_bad[0] in (200, 400),
                    ["SES-007"], "Core anti-CSRF token mismatch rejected; browser cookie behavior remains unqualified.",
                    status=core_status(csrf_bad))
        refreshed = self.required_ok(self.refresh(session), "Cross-replica refresh")
        verified = self.verify(refreshed, replica=0)
        self.result("OSS-REFRESH-001", ok(verified) and refreshed["session"]["handle"] == session["session"]["handle"],
                    ["SES-003"], "Refresh on B and stateful access verification on A preserve authoritative session.")
        self.required_ok(self.revoke(refreshed), "Session revocation")
        start = time.monotonic()
        online = self.verify(refreshed, replica=1)
        latency = round((time.monotonic() - start) * 1000, 3)
        after = self.refresh(refreshed)
        self.result("OSS-REVOKE-001", core_status(online) == core_status(after) == "UNAUTHORISED",
                    ["SES-005", "SES-006"], "First online check and refresh on B reject revocation from A; one sample, not a propagation SLA.",
                    online_status=core_status(online), refresh_status=core_status(after), first_check_duration_ms=latency)
        offline = self.verify(session, online=False)
        self.rows.append({"test_id": "OSS-OFFLINE-REVOCATION-OBSERVED", "outcome": "observed", "requirements": ["SES-002", "SES-006"],
                          "core_status": core_status(offline), "http_status": offline[0],
                          "note": "Core checkDatabase=false characterization only. This is not an independent local JWT verifier; no immediate offline revocation claim."})
        self.refresh_race(user)
        self.response_loss(user)
        self.logout_race(user)

    def refresh_race(self, user):
        original = self.create_session(user)
        barrier = threading.Barrier(2)
        def concurrent_refresh(replica):
            barrier.wait(timeout=10)
            return self.refresh(original, replica=replica)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(concurrent_refresh, (0, 1)))
        if not all(ok(r) for r in responses):
            self.result("OSS-REFRESH-RACE-001", False, ["SES-003", "SES-004"],
                        "Pinned CDI5.3 legacy profile should permit candidate children before promotion.",
                        statuses=[core_status(r) for r in responses])
            return
        children = [r[1] for r in responses]
        selected = self.verify(children[0], replica=0)
        sibling = self.refresh(children[1], replica=1)
        winner = self.refresh(children[0], replica=1)
        same_session = all(s["session"]["handle"] == original["session"]["handle"] for s in children)
        self.result("OSS-REFRESH-RACE-001", ok(selected) and same_session and core_status(sibling) == "TOKEN_THEFT_DETECTED" and ok(winner),
                    ["SES-003", "SES-004"],
                    "CDI5.3 candidates converge after one child is promoted by stateful verification; sibling cannot extend an independent chain. Theft response does not itself prove adapter revocation.",
                    initial_statuses=[core_status(r) for r in responses], sibling_status=core_status(sibling), winner_status=core_status(winner))
        self.required_ok(self.revoke(original), "Race cleanup revocation")

    def response_loss(self, user):
        original = self.create_session(user)
        parsed = urllib.parse.urlparse(self.replicas[0])
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=20)
        data = json.dumps({"refreshToken": token(original, "refreshToken"), "antiCsrfToken": original.get("antiCsrfToken"),
                           "enableAntiCsrf": True, "useDynamicSigningKey": True})
        try:
            connection.request("POST", "/recipe/session/refresh", data,
                               {"Content-Type": "application/json", "api-key": self.key, "cdi-version": self.cdi, "rid": "session"})
            response = connection.getresponse()
            status = response.status
            response.close()  # Deliberately never read/save the issued child token body.
        finally:
            connection.close()
        retry = self.refresh(original, replica=1)
        verified = self.verify(retry[1], replica=0) if ok(retry) else retry
        replay = self.refresh(original, replica=1)
        self.result("OSS-RESPONSE-LOSS-001", status == 200 and ok(retry) and ok(verified) and core_status(replay) == "TOKEN_THEFT_DETECTED",
                    ["SES-003", "SES-004"],
                    "Disconnect after response headers without consuming body, then retry on B. After retry child promotion the original parent is rejected. Pre-commit crashes and partial network transmission remain untested.",
                    discarded_response_http=status, retry_status=core_status(retry), stale_parent_status=core_status(replay))
        self.required_ok(self.revoke(original), "Response-loss cleanup revocation")

    def logout_race(self, user):
        original = self.create_session(user)
        barrier = threading.Barrier(2)
        def race(action):
            barrier.wait(timeout=10)
            return self.refresh(original, replica=1) if action == "refresh" else self.revoke(original, replica=0)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            refresh, revoked = list(pool.map(race, ("refresh", "revoke")))
        candidate = refresh[1] if ok(refresh) else original
        final = self.refresh(candidate, replica=1)
        self.result("OSS-LOGOUT-RACE-001", ok(revoked) and core_status(final) == "UNAUTHORISED",
                    ["SES-003", "SES-005"], "Logout wins after concurrent transactions finish; no refresh resurrection on B.",
                    racing_refresh_status=core_status(refresh), post_race_status=core_status(final))

    def scope_probes(self):
        apps = [f"probe-a-{self.suffix}", f"probe-b-{self.suffix}"]
        scopes = []
        for app in apps:
            response = self.request("PUT", "/recipe/multitenancy/app/v2", {"appId": app}, recipe="multitenancy")
            if not ok(response):
                self.unavailable("OSS-APP-PROVISION-" + app.split("-")[1].upper(), ["IDN-001", "IDN-011", "BAS-003"],
                                 "Application provisioning unavailable on unactivated audited Core", response)
                continue
            for tenant in ("alpha", "beta"):
                response = self.request("PUT", "/recipe/multitenancy/tenant/v2", {
                    "tenantId": tenant, "firstFactors": ["emailpassword", "thirdparty"]}, app=app, recipe="multitenancy")
                if ok(response):
                    scopes.append((app, tenant))
                else:
                    self.unavailable(f"OSS-TENANT-PROVISION-{app.split('-')[1].upper()}-{tenant.upper()}",
                                     ["IDN-003", "IDN-011", "BAS-003"], "Tenant provisioning unavailable", response)
        if len(scopes) != 4:
            self.unavailable("OSS-ISOLATION-FOUR-SCOPES", ["IDN-001", "IDN-003"], "Four required app/tenant scopes were not provisioned")
            # Exercise one independent tenant package even when multiple-app licensing blocks.
            fallback = self.request("PUT", "/recipe/multitenancy/tenant/v2", {
                "tenantId": f"probe-{self.suffix}", "firstFactors": ["emailpassword", "thirdparty"]}, recipe="multitenancy")
            if not ok(fallback):
                self.unavailable("OSS-DEFAULT-APP-TENANT", ["IDN-003", "IDN-011", "BAS-003"], "Default-app tenant provisioning unavailable", fallback)
                return
            scopes = [("public", "public"), ("public", f"probe-{self.suffix}")]
        email = f"same-{self.suffix}@example.test"
        isolated, providers = [], []
        for app, tenant in scopes:
            response, _ = self.signup("isolation", email=email, app=app, tenant=tenant)
            user = self.required_ok(response, "Scoped signup")["recipeUserId"]
            signed = self.signin(email, app=app, tenant=tenant)
            isolated.append(user)
            if not ok(signed) or signed[1].get("recipeUserId") != user:
                raise HarnessError("Scoped password sign-in returned unexpected identity")
            provider = self.request("POST", "/recipe/signinup", {
                "thirdPartyId": "owned-fixture", "thirdPartyUserId": f"same-subject-{self.suffix}",
                "email": {"id": email, "isVerified": False}}, app=app, tenant=tenant, recipe="thirdparty")
            if ok(provider):
                providers.append(provider[1].get("recipeUserId"))
            else:
                self.unavailable("OSS-PROVIDER-STORAGE-" + str(len(providers)), ["IDN-003"], "Provider identity storage path unavailable", provider)
        self.result("OSS-IDENTITY-ISOLATION-001", len(set(isolated)) == len(scopes), ["IDN-001", "IDN-003"],
                    "Equal-email credentials stay isolated in every successfully provisioned scope; four-scope gate remains separately unavailable when blocked.", scopes_tested=len(scopes))
        self.result("OSS-PROVIDER-STORAGE-001", len(providers) == len(scopes) and len(set(providers)) == len(scopes), ["IDN-003"],
                    "Private third-party identity persistence receives synthetic asserted provider data; this is NOT live IdP authentication or proof of provider ownership.", scopes_tested=len(scopes))
        if len(scopes) == 4:
            first = self.create_session(isolated[0], app=scopes[0][0], tenant=scopes[0][1])
            wrong_app = self.verify(first, app=scopes[2][0])
            self.result("OSS-APP-TOKEN-ISOLATION-001", not ok(wrong_app), ["IDN-001", "SES-001"],
                        "App A access token cannot verify under App B.", status=core_status(wrong_app), http_status=wrong_app[0])
        self.sharing(scopes[0], scopes[1])

    def sharing(self, first_scope, second_scope):
        app, tenant_a = first_scope
        other_app, tenant_b = second_scope
        if app != other_app:
            self.unavailable("OSS-SHARING-001", ["IDN-004"], "No pair of same-app tenant scopes was provisioned")
            return
        response, email = self.signup("shared", app=app, tenant=tenant_a)
        user = self.required_ok(response, "Shared identity signup")["recipeUserId"]
        associate = self.request("POST", "/recipe/multitenancy/tenant/user", {"recipeUserId": user},
                                 app=app, tenant=tenant_b, recipe="multitenancy")
        if not ok(associate):
            self.unavailable("OSS-SHARING-001", ["IDN-004", "BAS-003"], "Explicit identity association unavailable without activation", associate)
            return
        login_b = self.signin(email, app=app, tenant=tenant_b)
        self.result("OSS-SHARING-001", ok(login_b) and login_b[1].get("recipeUserId") == user, ["IDN-004"],
                    "Explicit same-storage association shares credentials only after privileged association.")
        session_a = self.create_session(user, app=app, tenant=tenant_a)
        session_b = self.create_session(user, app=app, tenant=tenant_b)
        removal = self.request("POST", "/recipe/session/remove", {"userId": user, "revokeAcrossAllTenants": False},
                               app=app, tenant=tenant_b)
        a_alive, b_dead = self.refresh(session_a, app=app), self.refresh(session_b, app=app)
        distinct = session_a["session"]["handle"] != session_b["session"]["handle"]
        self.result("OSS-SHARED-SESSION-ISOLATION-001", distinct and ok(removal) and ok(a_alive) and core_status(b_dead) == "UNAUTHORISED",
                    ["IDN-004", "SES-001", "SES-005"], "Shared identity has tenant-specific sessions; tenant B logout leaves tenant A refresh usable.")
        disassociate = self.request("POST", "/recipe/multitenancy/tenant/user/remove", {"recipeUserId": user},
                                    app=app, tenant=tenant_b, recipe="multitenancy")
        login_b = self.signin(email, app=app, tenant=tenant_b)
        login_a = self.signin(email, app=app, tenant=tenant_a)
        self.result("OSS-MEMBERSHIP-REMOVAL-001", ok(disassociate) and core_status(login_b) == "WRONG_CREDENTIALS_ERROR" and ok(login_a),
                    ["IDN-006"], "Removing tenant B association stops B password authentication while A survives; permission assignments require separate tests.")

    def linking(self):
        first, _ = self.signup("link-primary")
        second, _ = self.signup("link-method")
        primary = self.required_ok(first, "Link primary signup")["recipeUserId"]
        method = self.required_ok(second, "Link method signup")["recipeUserId"]
        created = self.request("POST", "/recipe/accountlinking/user/primary", {"recipeUserId": primary}, recipe="accountlinking")
        linked = self.request("POST", "/recipe/accountlinking/user/link", {"recipeUserId": method, "primaryUserId": primary}, recipe="accountlinking")
        if not ok(created) or not ok(linked):
            self.unavailable("OSS-LINK-001", ["LNK-001", "LNK-003", "BAS-003"],
                             "Authoritative linking unavailable without activation; no entitlement bypass attempted", created if not ok(created) else linked)
            return
        unlinked = self.request("POST", "/recipe/accountlinking/user/unlink", {"recipeUserId": method}, recipe="accountlinking")
        self.result("OSS-LINK-STORAGE-001", ok(created) and ok(linked) and ok(unlinked), ["LNK-001", "LNK-003", "LNK-006"],
                    "Privileged Core storage link/unlink calls executed. This does not qualify end-user proof of control, concurrent ownership, privilege or recovery policy.")
        self.unavailable("OSS-LINK-POLICY-CONCURRENCY", ["LNK-003", "LNK-007", "LNK-008"],
                         "End-user proof-of-control and link/unlink security race harness not yet integrated")

    def modern_profile(self, user):
        """Bounded version delta; grace=0 is the launcher's declared test configuration."""
        self.cdi = "5.6"
        try:
            original = self.create_session(user)
            child = self.required_ok(self.refresh(original), "CDI5.6 first refresh")
            verified = self.verify(child, replica=0)
            # Move beyond the zero-ms grace boundary, not a network retry loop.
            time.sleep(0.02)
            reused = self.refresh(original, replica=0)
            online = self.verify(child, replica=1)
            descendant = self.refresh(child, replica=1)
            self.result("OSS56-REFRESH-REUSE-001", ok(verified) and core_status(reused) in ("TOKEN_THEFT_DETECTED", "UNAUTHORISED")
                        and core_status(online) == core_status(descendant) == "UNAUTHORISED",
                        ["SES-003", "SES-004", "SES-006"],
                        "Separate CDI5.6/grace0 profile rotates at refresh; old-parent reuse rejects and revokes authoritative session across replicas. This differs from CDI5.3 promotion behavior.",
                        stale_status=core_status(reused), reuse_subtype=reused[1].get("recentTokenReuseSubtype") if isinstance(reused[1], dict) else None,
                        online_status=core_status(online), descendant_status=core_status(descendant))
            original = self.create_session(user)
            barrier = threading.Barrier(2)
            def race(replica):
                barrier.wait(timeout=10)
                return self.refresh(original, replica=replica)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                raced = list(pool.map(race, (0, 1)))
            successful = [r[1] for r in raced if ok(r)]
            final_statuses = [core_status(self.refresh(child, replica=1)) for child in successful]
            self.rows.append({"test_id": "OSS56-GRACE0-RACE-OBSERVED", "outcome": "observed", "requirements": ["SES-003", "SES-004"],
                              "cdi_version": "5.6", "configured_grace_seconds": 0,
                              "initial_statuses": [core_status(r) for r in raced], "successor_refresh_statuses": final_statuses,
                              "note": "Grace0 may classify a legitimate concurrent refresh as reuse and revoke the family. This observation does not qualify availability or response-loss recovery; a declared positive-grace profile needs separate tests."})
            self.required_ok(self.revoke(original), "CDI5.6 cleanup revocation")
        finally:
            self.cdi = CDI

    def save(self, harness_error=None):
        OUT.mkdir(parents=True, exist_ok=True)
        sources = []
        for relative in SOURCE_FILES:
            path = SOURCE / "src/main/java/io/supertokens" / relative
            if path.is_file():
                sources.append({"path": "src/main/java/io/supertokens/" + relative,
                                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "license": "Apache-2.0"})
        report = {"schema": "foundation-characterization-v1", "engine": "audited-supertokens-core-oss",
                  "declared_core_release": "12.2.0", "source_commit": REVISION, "cdi_version": CDI,
                  "additional_characterized_profile": {"cdi_version": "5.6", "refresh_token_rotation_grace_period": 0},
                  "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  "source_handlers": sources, "started_at": self.started,
                  "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                  "environment": {"python": platform.python_version(), "platform": platform.platform(),
                                  "replicas": self.replicas, "shared_database": "launcher PostgreSQL; cross-replica persistence exercised by probe"},
                  "foundation_passed": False, "production_approved": False, "harness_error": harness_error,
                  "results": self.rows, "requests": self.requests,
                  "remaining": ["Representative Node/React and Python adapter contracts", "Embedded intermediate MFA and hooks",
                                "End-user linking proof of control and concurrent privilege changes", "Browser cookie/header and native lifecycle",
                                "Pre-commit crash and network fault injection", "Configured tenant permission isolation",
                                "Independent security review and vendor-egress operational qualification"],
                  "claim_limit": "Passed probe cases are narrow observations; baseline requirements are not individually marked verified by this harness."}
        encoded = json.dumps(report, indent=2) + "\n"
        # Report content is constructed from allowlisted fields. Also guard accidental secret inclusion.
        if self.password in encoded or self.key in encoded:
            raise HarnessError("Secret-redaction invariant failed; refusing to persist report")
        (OUT / f"results-{self.suffix}.json").write_text(encoded, encoding="utf-8")
        (OUT / "results.json").write_text(encoded, encoding="utf-8")
        print(json.dumps({"harness_error": harness_error, "foundation_passed": False,
                          "passed": sum(r["outcome"] == "passed" for r in self.rows),
                          "failed": sum(r["outcome"] == "failed" for r in self.rows),
                          "unavailable": sum(r["outcome"] == "unavailable" for r in self.rows)}), flush=True)


def main():
    probe = None
    try:
        probe = Probe()
        probe.ready()
        user = probe.basic()
        probe.sessions(user)
        probe.scope_probes()
        probe.linking()
        probe.modern_profile(user)
        probe.save()
        # Requirement failures/unavailable outcomes are characterized results, not harness exceptions.
        return 0
    except (HarnessError, KeyError, TypeError, ValueError, OSError, threading.BrokenBarrierError) as exc:
        message = str(exc) if isinstance(exc, HarnessError) else type(exc).__name__
        if probe is not None:
            probe.save(harness_error=message)
        else:
            print(json.dumps({"harness_error": message, "foundation_passed": False}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
