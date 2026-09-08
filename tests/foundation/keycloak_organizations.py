"""Independent real Keycloak organization/session characterization on a disposable realm.

Uses browser forms + authorization-code/PKCE, never the password grant. Source pins
and rendered organization-denial strings come from Keycloak 26.7.3 Apache sources.
HTTP/browser-form automation is not a rendered-browser UX or embedded-login proof.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
from html.parser import HTMLParser
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://keycloak:8080"
REDIRECT = "http://owned-app.example.test/callback"
COMMIT = "6d238b6558037085cc25c915893c3d301a80243e"
ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "evidence/foundation/keycloak-organizations"


class HarnessError(Exception):
    pass


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.current, self.text, self.ignored = [], None, [], 0

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag in ("script", "style"):
            self.ignored += 1
        if tag == "form":
            self.current = {"id": attrs.get("id"), "action": attrs.get("action"), "inputs": {}}
            self.forms.append(self.current)
        if tag == "input" and self.current is not None and attrs.get("name"):
            self.current["inputs"][attrs["name"]] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.current = None
        if tag in ("script", "style") and self.ignored:
            self.ignored -= 1

    def handle_data(self, data):
        if not self.ignored and data.strip():
            self.text.append(data.strip())


class BrowserRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, target):
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme + "://" + parsed.netloc != BASE:
            # Never send credentials/headers to an application callback or an unexpected origin.
            return None
        return super().redirect_request(request, file, code, message, headers, target)


def inspect_claims(encoded):
    """Inspection of a token obtained directly from Keycloak, not a resource verifier."""
    segment = encoded.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def is_tokens(result):
    return result.get("kind") == "tokens"


def orgs(tokens):
    return sorted(inspect_claims(tokens["access_token"]).get("organization", {}))


class Probe:
    def __init__(self):
        self.suffix = secrets.token_hex(6)
        self.realm = "ea-org-proof-" + self.suffix
        self.password = secrets.token_urlsafe(28)
        self.admin = None
        self.organizations, self.clients, self.users = {}, {}, {}
        self.results, self.requests, self.page_evidence = [], [], []
        self.started = dt.datetime.now(dt.timezone.utc).isoformat()
        self.secrets = [self.password, os.environ["KC_BOOTSTRAP_ADMIN_CLIENT_SECRET"]]

    def request(self, method, path, data=None, *, admin=False, form=False, browser=None, bearer=None):
        url = path if path.startswith("http") else BASE + path
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme + "://" + parsed.netloc != BASE:
            raise HarnessError("Refusing request outside owned Keycloak origin")
        headers = {}
        credential = self.admin if admin else bearer
        if credential:
            headers["Authorization"] = "Bearer " + credential
        if data is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
            data = (urllib.parse.urlencode(data) if form else json.dumps(data)).encode()
        start = time.monotonic()
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            response = (browser.open(request, timeout=20) if browser else urllib.request.urlopen(request, timeout=20))
        except urllib.error.HTTPError as exc:
            response = exc
        except (urllib.error.URLError, OSError) as exc:
            raise HarnessError("Keycloak transport failed: " + type(exc).__name__) from None
        with response:
            body = response.read().decode("utf-8", errors="replace")
            status, response_headers = response.status, dict(response.headers)
        try:
            body = json.loads(body)
        except ValueError:
            pass
        if isinstance(body, dict):
            self.secrets.extend(body[k] for k in ("access_token", "refresh_token", "id_token") if isinstance(body.get(k), str))
        self.requests.append({"method": method, "path": parsed.path, "http_status": status,
                              "duration_ms": round((time.monotonic() - start) * 1000, 3),
                              "oauth_error": body.get("error") if isinstance(body, dict) else None,
                              "body_or_credentials_recorded": False})
        return status, body, response_headers

    def required(self, response, expected, label):
        if response[0] != expected:
            raise HarnessError(f"{label}: expected HTTP{expected}, got HTTP{response[0]}")
        return response[1]

    def record(self, identifier, passed, requirements, note, **facts):
        self.results.append({"test_id": identifier, "outcome": "passed" if passed else "failed",
                             "requirements": requirements, "note": note, "observed": facts})
        print(f"{identifier}: {'passed' if passed else 'failed'}", flush=True)

    def observed(self, identifier, requirements, note, **facts):
        self.results.append({"test_id": identifier, "outcome": "observed", "requirements": requirements,
                             "note": note, "observed": facts})
        print(f"{identifier}: observed", flush=True)

    def api(self, path):
        return f"/admin/realms/{self.realm}" + path

    def oidc(self, path):
        return f"/realms/{self.realm}/protocol/openid-connect" + path

    def setup(self):
        auth = self.request("POST", "/realms/master/protocol/openid-connect/token", {
            "grant_type": "client_credentials", "client_id": os.environ["KC_BOOTSTRAP_ADMIN_CLIENT_ID"],
            "client_secret": os.environ["KC_BOOTSTRAP_ADMIN_CLIENT_SECRET"]}, form=True)
        self.admin = self.required(auth, 200, "Bootstrap admin service authentication")["access_token"]
        self.required(self.request("POST", "/admin/realms", {
            "realm": self.realm, "enabled": True, "sslRequired": "none", "organizationsEnabled": True,
            "registrationEmailAsUsername": False, "loginWithEmailAllowed": False, "duplicateEmailsAllowed": True,
            "revokeRefreshToken": True, "refreshTokenMaxReuse": 0, "accessTokenLifespan": 60,
            "eventsEnabled": True, "eventsExpiration": 3600}, admin=True), 201, "Create disposable realm")
        for name in ("alpha", "beta"):
            response = self.request("POST", self.api("/organizations"), {
                "name": name, "alias": name, "enabled": True}, admin=True)
            self.required(response, 201, "Create organization")
            self.organizations[name] = response[2]["Location"].rsplit("/", 1)[-1]
            response = self.request("POST", self.api("/clients"), {
                "clientId": name, "enabled": True, "publicClient": True, "standardFlowEnabled": True,
                "directAccessGrantsEnabled": False, "redirectUris": [REDIRECT], "webOrigins": ["http://owned-app.example.test"],
                "attributes": {"pkce.code.challenge.method": "S256"}}, admin=True)
            self.required(response, 201, "Create PKCE client")
            self.clients[name] = response[2]["Location"].rsplit("/", 1)[-1]
        for name in ("member", "outsider"):
            response = self.request("POST", self.api("/users"), {
                "username": name, "email": f"{name}-{self.suffix}@example.test", "firstName": "Synthetic",
                "lastName": "OrganizationProbe", "emailVerified": True, "enabled": True,
                "credentials": [{"type": "password", "value": self.password, "temporary": False}]}, admin=True)
            self.required(response, 201, "Create synthetic user")
            self.users[name] = response[2]["Location"].rsplit("/", 1)[-1]
        self.member("alpha", add=True)

    def member(self, organization, *, add):
        path = self.api(f"/organizations/{self.organizations[organization]}/members")
        if add:
            self.required(self.request("POST", path, self.users["member"], admin=True), 201, "Associate unmanaged member")
        else:
            self.required(self.request("DELETE", path + "/" + self.users["member"], admin=True), 204, "Remove membership")

    def require_membership(self):
        alias = "org-membership-required"
        self.required(self.request("POST", self.api("/authentication/flows/browser/copy"), {"newName": alias}, admin=True), 201,
                      "Copy supported browser flow")
        executions = self.required(self.request("GET", self.api(f"/authentication/flows/{alias}/executions"), admin=True), 200,
                                   "Inspect copied authentication executions")
        organizations = [execution for execution in executions if execution.get("providerId") == "organization"]
        if not organizations:
            raise HarnessError("Copied browser flow has no organization authenticator")
        for index, execution in enumerate(organizations):
            self.required(self.request("POST", self.api(f"/authentication/executions/{execution['id']}/config"),
                                       {"alias": f"require-membership-{index}", "config": {"requiresUserMembership": "true"}}, admin=True),
                          201, "Require organization membership using supported authenticator configuration")
        self.required(self.request("PUT", self.api(""), {"browserFlow": alias}, admin=True), 204, "Bind configured browser flow")
        self.observed("KCORG-SUPPORTED-MEMBERSHIP-CONFIG", ["CFG-003", "IDN-006"],
                      "Copied browser flow explicitly enables organization requiresUserMembership=true; source and Admin REST configuration are unchanged upstream.",
                      flow=alias, configured_organization_executions=len(organizations))

    def browser(self):
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), BrowserRedirects())

    def authorize(self, client, organization, *, username="member", browser=None, bad_pkce=False):
        browser = browser or self.browser()
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        state, nonce = secrets.token_urlsafe(20), secrets.token_urlsafe(20)
        scope = "openid" + (" organization:" + organization if organization else "")
        query = urllib.parse.urlencode({"client_id": client, "redirect_uri": REDIRECT, "response_type": "code", "scope": scope,
                                       "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"})
        status, body, headers = self.request("GET", self.oidc("/auth?") + query, browser=browser)
        visited = set()
        for _ in range(4):
            if status not in (200, 403) or not isinstance(body, str):
                break
            page = Page()
            page.feed(body)
            visible = " ".join(page.text)
            explicit = ("User is not a member of the organization " + str(organization)) in visible or "User is not a member of any organization" in visible
            if explicit:
                excerpt = re.search(r"User is not a member of (?:the organization [A-Za-z0-9-]+|any organization)", visible)
                evidence = {"http_status": status, "error_text": excerpt.group(0) if excerpt else "membership denial",
                            "html_sha256": hashlib.sha256(body.encode()).hexdigest(),
                            "source_message_keys": ["notMemberOfOrganization", "notMemberOfAnyOrganization"],
                            "code_issued": False, "token_exchange_attempted": False}
                self.page_evidence.append(evidence)
                return {"kind": "explicit-membership-denial", **evidence}, browser
            login_form = next((form for form in page.forms if form["id"] == "kc-form-login"), None)
            if login_form is None:
                # Unknown pages are neither successful authentication nor accepted denial evidence.
                self.page_evidence.append({"http_status": status, "unrecognized_visible_text": visible[:1000],
                                           "html_sha256": hashlib.sha256(body.encode()).hexdigest()})
                return {"kind": "unrecognized-page", "http_status": status, "code_issued": False}, browser
            if status != 200:
                return {"kind": "unexpected-http", "http_status": status, "code_issued": False}, browser
            fingerprint = (login_form["action"], tuple(sorted(login_form["inputs"])))
            if fingerprint in visited:
                return {"kind": "repeated-form", "http_status": status, "code_issued": False}, browser
            visited.add(fingerprint)
            values = dict(login_form["inputs"])
            values.update({"username": username, "password": self.password})
            status, body, headers = self.request("POST", login_form["action"], values, form=True, browser=browser)
        if status != 302 or "Location" not in headers:
            return {"kind": "unexpected-http", "http_status": status, "code_issued": False}, browser
        location = urllib.parse.urlparse(headers["Location"])
        if location.scheme + "://" + location.netloc + location.path != REDIRECT:
            raise HarnessError("Unexpected authorization callback origin/path")
        values = urllib.parse.parse_qs(location.query)
        if values.get("state") != [state]:
            raise HarnessError("Authorization state mismatch")
        if "error" in values:
            return {"kind": "oauth-denial", "error": values["error"][0], "code_issued": "code" in values}, browser
        if "code" not in values:
            raise HarnessError("Authorization callback missing code and error")
        code = values["code"][0]
        self.secrets.append(code)
        response = self.exchange(client, code, secrets.token_urlsafe(48) if bad_pkce else verifier)
        if response[0] != 200:
            return {"kind": "token-endpoint-denial", "http_status": response[0],
                    "error": response[1].get("error") if isinstance(response[1], dict) else None, "code_issued": True}, browser
        tokens = response[1]
        if inspect_claims(tokens["id_token"]).get("nonce") != nonce:
            raise HarnessError("OIDC nonce mismatch")
        accepted = self.request("GET", self.oidc("/userinfo"), bearer=tokens["access_token"])
        if accepted[0] != 200 or accepted[1].get("sub") != self.users[username]:
            raise HarnessError("Engine userinfo did not validate expected token principal")
        return {"kind": "tokens", "tokens": tokens, "code_issued": True,
                "code": code, "verifier": verifier}, browser

    def exchange(self, client, code, verifier):
        return self.request("POST", self.oidc("/token"), {"grant_type": "authorization_code", "client_id": client,
                            "redirect_uri": REDIRECT, "code": code, "code_verifier": verifier}, form=True)

    def login(self, client, organization, *, browser=None):
        result, browser = self.authorize(client, organization, browser=browser)
        if not is_tokens(result):
            raise HarnessError("Expected member authorization unavailable: " + result["kind"])
        return result["tokens"], browser

    def refresh(self, client, tokens, scope=None):
        data = {"grant_type": "refresh_token", "client_id": client, "refresh_token": tokens["refresh_token"]}
        if scope:
            data["scope"] = scope
        return self.request("POST", self.oidc("/token"), data, form=True)

    def pair(self):
        alpha, browser = self.login("alpha", "alpha")
        beta, browser = self.login("beta", "beta", browser=browser)
        return alpha, beta, browser

    def sessions(self):
        counts = {}
        for client, identifier in self.clients.items():
            rows = self.required(self.request("GET", self.api(f"/clients/{identifier}/user-sessions"), admin=True), 200, "Client session inventory")
            counts[client] = sum(row.get("userId") == self.users["member"] for row in rows)
        return counts

    def membership_proof(self):
        default_nonmember, _ = self.authorize("beta", "beta", username="outsider")
        self.observed("KCORG-DEFAULT-MEMBERSHIP-CONFIG", ["IDN-006"],
                      "Default requiresUserMembership=false is characterized separately from the required-membership profile.",
                      outsider_kind=default_nonmember["kind"],
                      outsider_organizations=orgs(default_nonmember["tokens"]) if is_tokens(default_nonmember) else [])
        self.require_membership()
        alpha, browser = self.login("alpha", "alpha")
        nonmember, _ = self.authorize("beta", "beta", browser=browser)
        outsider, _ = self.authorize("beta", "beta", username="outsider")
        self.record("KCORG-NONMEMBER-001", nonmember["kind"] == "explicit-membership-denial" and not nonmember["code_issued"],
                    ["IDN-006"], "Same already-authenticated alpha member receives explicit beta membership denial with no code/token.",
                    kind=nonmember["kind"], http_status=nonmember.get("http_status"))
        self.record("KCORG-OUTSIDER-001", outsider["kind"] == "explicit-membership-denial" and not outsider["code_issued"],
                    ["IDN-006"], "User with valid credentials and zero organization memberships receives explicit denial.", kind=outsider["kind"])
        self.member("beta", add=True)
        beta, _ = self.login("beta", "beta", browser=browser)
        shared = inspect_claims(alpha["access_token"])["sub"] == inspect_claims(beta["access_token"])["sub"]
        self.record("KCORG-EXPLICIT-SHARING-001", shared and orgs(alpha) == ["alpha"] and orgs(beta) == ["beta"],
                    ["IDN-004"], "Same user changes from rejected to admitted after explicit beta association; selected organization claims stay distinct.",
                    alpha_organizations=orgs(alpha), beta_organizations=orgs(beta))
        counts = self.sessions()
        self.record("KCORG-CLIENT-SESSIONS-001", counts["alpha"] >= 1 and counts["beta"] >= 1,
                    ["SES-001", "IDN-004"], "Admin APIs independently enumerate both client attachments to user sessions.", client_session_counts=counts)
        self.observed("KCORG-REALM-SSO-SID", ["SES-001"], "Shared realm sid does not by itself measure client-session independence.",
                      shared_realm_sid=inspect_claims(alpha["access_token"]).get("sid") == inspect_claims(beta["access_token"]).get("sid"))
        switched, _ = self.authorize("alpha", "beta")
        omitted, _ = self.authorize("alpha", None)
        self.observed("KCORG-CLIENT-ORG-POLICY", ["IDN-006"],
                      "Organization scope is an authorization context, not a fixed client-to-tenant binding; the application must require its declared tenant context.",
                      alpha_client_requested_beta_kind=switched["kind"],
                      alpha_client_requested_beta_organizations=orgs(switched["tokens"]) if is_tokens(switched) else [],
                      omitted_scope_kind=omitted["kind"], omitted_scope_organizations=orgs(omitted["tokens"]) if is_tokens(omitted) else [])

    def token_binding(self):
        wrong_pkce, _ = self.authorize("alpha", "alpha", bad_pkce=True)
        self.record("KCORG-PKCE-NEGATIVE-001", wrong_pkce["kind"] == "token-endpoint-denial" and wrong_pkce.get("error") == "invalid_grant",
                    ["OAU-001"], "Wrong PKCE verifier rejected at the real token endpoint.", status=wrong_pkce.get("http_status"), error=wrong_pkce.get("error"))
        result, _ = self.authorize("alpha", "alpha")
        if not is_tokens(result):
            raise HarnessError("Code replay fixture failed to authenticate")
        replay = self.exchange("alpha", result["code"], result["verifier"])
        self.record("KCORG-CODE-REPLAY-001", replay[0] == 400 and replay[1].get("error") == "invalid_grant",
                    ["OAU-001"], "Consumed authorization code cannot be exchanged again.", http_status=replay[0], error=replay[1].get("error"))
        alpha, beta, _ = self.pair()
        wrong_client = self.refresh("beta", alpha)
        self.record("KCORG-REFRESH-CLIENT-BINDING-001", wrong_client[0] == 400 and "access_token" not in wrong_client[1],
                    ["SES-003"], "Alpha refresh token submitted as beta client is rejected.", error=wrong_client[1].get("error"))
        refreshed_a, refreshed_b = self.refresh("alpha", alpha), self.refresh("beta", beta)
        self.record("KCORG-REFRESH-SCOPES-001", refreshed_a[0] == refreshed_b[0] == 200 and orgs(refreshed_a[1]) == ["alpha"] and orgs(refreshed_b[1]) == ["beta"],
                    ["SES-003", "IDN-004"], "Both actual client refresh chains retain their selected organization scopes.",
                    alpha_http=refreshed_a[0], beta_http=refreshed_b[0])
        if refreshed_a[0] == 200:
            substitution = self.refresh("alpha", refreshed_a[1], "openid organization:beta")
            expanded = substitution[0] == 200 and "beta" in orgs(substitution[1])
            self.record("KCORG-REFRESH-SCOPE-SUBSTITUTION-001", not expanded,
                        ["IDN-006", "SES-003"], "Refresh cannot acquire beta context from an alpha-only authorization grant.",
                        http_status=substitution[0], resulting_organizations=orgs(substitution[1]) if substitution[0] == 200 else [])

    def logout_profiles(self):
        alpha, beta, _ = self.pair()
        revoked = self.request("POST", self.oidc("/revoke"), {"client_id": "beta", "token": beta["refresh_token"], "token_type_hint": "refresh_token"}, form=True)
        after_beta, after_alpha = self.refresh("beta", beta), self.refresh("alpha", alpha)
        self.record("KCORG-RFC7009-TENANT-LOGOUT-001", revoked[0] == 200 and after_beta[0] == 400 and after_alpha[0] == 200,
                    ["SES-005", "IDN-004"], "Revoking beta's refresh token detaches that client while alpha refresh remains valid in shared realm SSO.",
                    revoke_http=revoked[0], beta_refresh_http=after_beta[0], alpha_refresh_http=after_alpha[0],
                    beta_error=after_beta[1].get("error"))
        alpha, beta, _ = self.pair()
        logged_out = self.request("POST", self.oidc("/logout"), {"client_id": "beta", "refresh_token": beta["refresh_token"]}, form=True)
        after_beta, after_alpha = self.refresh("beta", beta), self.refresh("alpha", alpha)
        self.observed("KCORG-LEGACY-LOGOUT-SCOPE", ["SES-005", "IDN-004"],
                      "Legacy refresh-token logout invokes realm SSO logout; this operation is not interchangeable with client refresh-token revocation for tenant-local logout.",
                      logout_http=logged_out[0], beta_refresh_http=after_beta[0], alpha_refresh_http=after_alpha[0])

    def removal(self):
        alpha, beta, browser = self.pair()
        self.member("beta", add=False)
        absent = self.request("GET", self.api(f"/organizations/{self.organizations['beta']}/members/{self.users['member']}"), admin=True)
        new_beta, _ = self.authorize("beta", "beta")
        existing_browser_beta, _ = self.authorize("beta", "beta", browser=browser)
        self.record("KCORG-MEMBERSHIP-REMOVAL-LOGIN-001", absent[0] == 404 and
                    new_beta["kind"] == existing_browser_beta["kind"] == "explicit-membership-denial",
                    ["IDN-006"], "Removed unmanaged beta member is absent in admin inventory and denied new authorization with both fresh and existing SSO browser cookies.",
                    membership_http=absent[0], fresh_browser_kind=new_beta["kind"], existing_browser_kind=existing_browser_beta["kind"])
        refreshed_beta = self.refresh("beta", beta)
        refreshed_alpha = self.refresh("alpha", alpha)
        beta_orgs = orgs(refreshed_beta[1]) if refreshed_beta[0] == 200 else []
        self.record("KCORG-MEMBERSHIP-REMOVAL-REFRESH-001", "beta" not in beta_orgs and refreshed_alpha[0] == 200,
                    ["IDN-006", "SES-003"], "Refresh after membership removal must not recreate beta organization authority; alpha chain must survive.",
                    beta_http=refreshed_beta[0], beta_organizations=beta_orgs, beta_error=refreshed_beta[1].get("error"),
                    alpha_http=refreshed_alpha[0])
        original_token = self.request("GET", self.oidc("/userinfo"), bearer=beta["access_token"])
        self.observed("KCORG-MEMBERSHIP-REMOVAL-ACCESS-WINDOW", ["IDN-006", "SES-006"],
                      "Previously issued access JWT retains original signed claims. Userinfo acceptance is measured separately; this is not immediate online resource revocation qualification.",
                      original_access_organizations=orgs(beta), userinfo_http=original_token[0],
                      userinfo_organizations=sorted(original_token[1].get("organization", {})),
                      configured_access_token_lifespan_seconds=60)
        # Resume later probes safely without changing the evidence about the actual removal.
        self.member("beta", add=True)

    def save(self, error=None):
        OUT.mkdir(parents=True, exist_ok=True)
        manifest = OUT / "source-manifest.json"
        report = {"schema": "foundation-characterization-v1", "engine": "Keycloak", "version": "26.7.3", "source_commit": COMMIT,
                  "mapping": "application=realm; selected tenant=organization scope; separate tenant clients for refresh revocation",
                  "fixture_realm": self.realm, "started_at": self.started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                  "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  "source_manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest() if manifest.exists() else None,
                  "environment": {"python": platform.python_version(), "platform": platform.platform(), "origin": BASE},
                  "foundation_passed": False, "production_approved": False, "harness_error": error,
                  "results": self.results, "explicit_denial_page_evidence": self.page_evidence, "requests": self.requests,
                  "remaining": ["Supported headless/embedded first-party MFA and intermediate states", "Primary/method identity link/unlink ownership and proof of control",
                                "Keycloak-backed Node/React/Python compatibility clients; alternative-engine clients do not count",
                                "Tenant-scoped roles/resource checks and bounded online membership revocation", "Multi-replica refresh fault/replay and response-loss proof",
                                "Real rendered browser/native qualification and independent security review"],
                  "claim_limit": "Narrow configured behavior only. No whole-requirement or engine foundation completion inferred."}
        encoded = json.dumps(report, indent=2) + "\n"
        if any(secret and secret in encoded for secret in self.secrets):
            raise HarnessError("Secret-redaction invariant failed; refusing report write")
        (OUT / f"results-{self.suffix}.json").write_text(encoded, encoding="utf-8")
        (OUT / "results.json").write_text(encoded, encoding="utf-8")
        print(json.dumps({"harness_error": error, "foundation_passed": False,
                          "passed": sum(r["outcome"] == "passed" for r in self.results),
                          "failed": sum(r["outcome"] == "failed" for r in self.results),
                          "observed": sum(r["outcome"] == "observed" for r in self.results)}), flush=True)


def main():
    probe = None
    try:
        probe = Probe()
        probe.setup()
        probe.membership_proof()
        probe.token_binding()
        probe.logout_profiles()
        probe.removal()
        probe.save()
        return 0
    except (HarnessError, KeyError, ValueError, TypeError, OSError) as exc:
        message = str(exc) if isinstance(exc, HarnessError) else type(exc).__name__
        if probe:
            probe.save(message)
        else:
            print(json.dumps({"harness_error": message, "foundation_passed": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
