"""Live two-replica candidate session characterization; no mocked responses.

The routing transport changes only the destination replica, retaining canonical
URLs and cookie origin semantics. Synthetic secrets and tokens remain in memory.
"""
from __future__ import annotations

import base64
import concurrent.futures
import hashlib
import json
import pathlib
import secrets
import sys
import threading
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pyotp

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXT = ROOT / "engine-extensions/keycloak-headless"
FIXTURES = json.loads((EXT / ".runtime/cluster/fixtures.json").read_text())
ISSUER = FIXTURES["issuer"]
OIDC = ISSUER + "/protocol/openid-connect"
ORIGIN = "http://kc-cluster.example.test:8080"
REDIRECT = "http://cluster-client.example.test/callback"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class ReplicaTransport(httpx.BaseTransport):
    """Forward actual HTTP to a selected private replica, preserving Host."""
    def __init__(self, replica="kc-a"):
        self.replica = replica
        self.inner = httpx.HTTPTransport(retries=0)

    def handle_request(self, request):
        require(str(request.url).startswith(ORIGIN + "/"), "Request left canonical engine boundary")
        forwarded = httpx.Request(request.method, request.url.copy_with(host=self.replica),
                                  headers=request.headers, stream=request.stream,
                                  extensions=request.extensions)
        return self.inner.handle_request(forwarded)

    def close(self):
        self.inner.close()


class Engine:
    def __init__(self, replica="kc-a"):
        self.transport = ReplicaTransport(replica)
        self.client = httpx.Client(transport=self.transport, trust_env=False,
                                   timeout=20, follow_redirects=False)

    def at(self, replica):
        self.transport.replica = replica
        return self.client

    def refresh(self, token, client_id="cluster-alpha", replica="kc-a"):
        return self.at(replica).post(OIDC + "/token", data={"grant_type": "refresh_token", "client_id": client_id, "refresh_token": token})


class Flow:
    def __init__(self, user, client_id="cluster-alpha", engine=None, replica="kc-a"):
        self.engine = engine or Engine(replica)
        self.user = FIXTURES["users"][user]
        self.client_id = client_id
        self.state = secrets.token_urlsafe(24)
        self.nonce = secrets.token_urlsafe(24)
        self.verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(self.verifier.encode()).digest()).decode().rstrip("=")
        self.response = self.engine.at(replica).get(OIDC + "/auth", params={"client_id": client_id, "redirect_uri": REDIRECT, "response_type": "code", "scope": "openid", "state": self.state, "nonce": self.nonce, "code_challenge": challenge, "code_challenge_method": "S256"})
        self.used_sso = self.response.status_code == 302 and "code=" in self.response.headers.get("location", "")
        if not self.used_sso:
            self.challenge("password")

    def challenge(self, step):
        require(self.response.headers.get("content-type", "").startswith("application/json"), f"Expected JSON {step} challenge; HTTP {self.response.status_code}")
        data = self.response.json()
        require(data.get("step") == step and data.get("authenticated") is False, f"Expected unauthenticated {step} stage")
        action = urlparse(data["action"])
        require(action.scheme + "://" + action.netloc == ORIGIN and action.path == urlparse(ISSUER).path + "/login-actions/authenticate", "Action left engine realm")
        self.action = data["action"]
        return data

    def password(self, replica="kc-b"):
        self.response = self.engine.at(replica).post(self.action, data={"username": self.user["username"], "password": self.user["password"]})
        self.challenge("totp")
        require(not {"KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION"}.intersection(self.engine.client.cookies), "Final engine cookies created before TOTP")

    def finish(self, replica="kc-a"):
        if not self.used_sso:
            self.response = self.engine.at(replica).post(self.action, data={"otp": pyotp.TOTP(self.user["otp_secret"]).now()})
        require(self.response.status_code == 302, f"Final authentication HTTP {self.response.status_code}")
        location = urlparse(self.response.headers.get("location", ""))
        require(location.scheme + "://" + location.netloc + location.path == REDIRECT, "OIDC callback differs")
        query = parse_qs(location.query)
        require(query.get("state") == [self.state] and bool(query.get("code")), "OIDC state or code missing")
        self.code = query["code"][0]
        self.final_cookies = self.response.headers.get_list("set-cookie")

    def exchange(self, replica="kc-b"):
        response = self.engine.at(replica).post(OIDC + "/token", data={"grant_type": "authorization_code", "client_id": self.client_id, "redirect_uri": REDIRECT, "code": self.code, "code_verifier": self.verifier})
        require(response.status_code == 200, f"Code exchange HTTP {response.status_code}")
        self.tokens = response.json()
        self.token_headers = response.headers
        require(all(name in self.tokens for name in ("access_token", "refresh_token", "id_token")), "Token endpoint omitted tokens")
        keys = self.engine.at(replica).get(OIDC + "/certs").json()["keys"]
        self.id_claims = verified(self.tokens["id_token"], keys, self.client_id)
        require(self.id_claims["nonce"] == self.nonce, "Signed nonce differs")
        self.access_claims = verified(self.tokens["access_token"], keys, "expertauth-cluster-api")
        return self.tokens


def verified(token, keys, audience):
    kid = jwt.get_unverified_header(token)["kid"]
    key = jwt.PyJWK.from_dict(next(item for item in keys if item["kid"] == kid)).key
    return jwt.decode(token, key, algorithms=["RS256"], issuer=ISSUER, audience=audience,
                      options={"require": ["exp", "iat", "sub", "iss", "aud"]})


def login(user, client_id="cluster-alpha", engine=None):
    flow = Flow(user, client_id, engine)
    if not flow.used_sso:
        flow.password()
    flow.finish()
    flow.exchange()
    return flow


def error_summary(response):
    body = response.json()
    return {"http_status": response.status_code, "error": body.get("error"), "error_description": body.get("error_description"), "tokens_issued": "access_token" in body}


def main():
    events = []
    shared = {}

    def check(ident, fn, expectation):
        start = time.monotonic()
        details = {}
        try:
            fn(details)
            status, error = "passed", None
        except Exception as exc:
            status = "failed"
            error = str(exc) if isinstance(exc, AssertionError) else type(exc).__name__
        event = {"id": ident, "expectation": expectation, "status": status, "duration_ms": round(1000 * (time.monotonic() - start), 2), "details": details}
        if error:
            event["error"] = error
        events.append(event)
        print(ident + ": " + status, flush=True)

    def members(details):
        startup = json.loads((ROOT / "evidence/foundation/keycloak-sessions/startup-report.json").read_text())
        views = startup["cluster_membership_log_lines"]
        require(len(views) == 2 and all(any("(2) [" in line for line in lines) for lines in views.values()), "Both replicas did not join a two-member view")
        require(startup["network_internal"] and all(not item["published_ports"] for item in startup["containers"]), "Lab exposes a public port")
        for replica in ("kc-a", "kc-b"):
            response = Engine(replica).client.get(ISSUER + "/.well-known/openid-configuration")
            require(response.status_code == 200 and response.json()["issuer"] == ISSUER, "Replica issuer differs")
        details.update(replicas=2, database="shared PostgreSQL 17.11", cluster_members=2, public_ports=0)
    check("KC-CLUSTER-TWO-REPLICAS-SHARED-POSTGRES", members, "Both replicas join the same private engine cluster and publish one issuer")

    def cross_replica(details):
        flow = login("serial")
        shared["serial"] = flow
        details.update(sequence=["password challenge A", "password verify B", "TOTP verify A", "code exchange B"], id_signature_issuer_audience_nonce_verified=True, access_signature_issuer_audience_subject_verified=True)
    check("KC-CLUSTER-CROSS-REPLICA-AUTHENTICATION", cross_replica, "Engine authentication sessions and PKCE code exchange work across replicas")

    def cookies(details):
        flow = shared["serial"]
        cookie_lines = flow.final_cookies
        names = [line.split("=", 1)[0] for line in cookie_lines]
        identity = next(line for line in cookie_lines if line.startswith("KEYCLOAK_IDENTITY="))
        require("HttpOnly" in identity and "SameSite=Lax" in identity, "Engine identity cookie lacks expected private-HTTP profile attributes")
        require("no-store" in flow.token_headers.get("cache-control", ""), "Token response can be cached")
        details.update(engine_cookie_names=names, identity_http_only=True, identity_same_site="Lax", secure_cookie=False, private_http_lab_only=True, token_response_no_store=True, supertokens_transport_compatibility_proven=False)
    check("KC-ENGINE-COOKIE-AND-TOKEN-RESPONSE-CONTRACT", cookies, "Real engine cookie flags and uncached token response are characterized; HTTPS deployment remains unqualified")

    def bearer(details):
        flow = shared["serial"]
        statuses = []
        for replica in ("kc-a", "kc-b"):
            response = flow.engine.at(replica).get(OIDC + "/userinfo", headers={"Authorization": "Bearer " + flow.tokens["access_token"]})
            statuses.append(response.status_code)
            require(response.status_code == 200 and response.json()["sub"] == flow.id_claims["sub"], "Valid bearer session rejected on replica")
        token = flow.tokens["access_token"]
        head, payload, signature = token.split(".")
        corrupted = ".".join((head, payload, ("A" if signature[0] != "A" else "B") + signature[1:]))
        bad = flow.engine.at("kc-b").get(OIDC + "/userinfo", headers={"Authorization": "Bearer " + corrupted})
        absent = flow.engine.at("kc-a").get(OIDC + "/userinfo")
        require(bad.status_code == 401 and absent.status_code == 401, "Missing or tampered bearer accepted")
        details.update(valid_statuses=statuses, invalid_signature_status=bad.status_code, absent_status=absent.status_code)
    check("KC-CLUSTER-BEARER-VALIDATION-ON-BOTH-REPLICAS", bearer, "Real valid bearer works and missing/tampered bearer is rejected")

    def serial(details):
        flow = shared["serial"]
        token = flow.tokens["refresh_token"]
        statuses = []
        for replica in ("kc-a", "kc-b", "kc-a", "kc-b"):
            response = flow.engine.refresh(token, replica=replica)
            statuses.append(response.status_code)
            require(response.status_code == 200, "Serial alternating refresh rejected")
            replacement = response.json()["refresh_token"]
            require(replacement != token, "Rotation did not issue a distinct refresh token")
            token = replacement
        details.update(statuses=statuses, all_refresh_tokens_changed=True)
    check("KC-CLUSTER-SERIAL-REFRESH-ROTATION", serial, "Sequential refresh rotation remains usable across alternating replicas")

    def replay(details):
        flow = login("replay")
        initial = flow.tokens["refresh_token"]
        first = flow.engine.refresh(initial, replica="kc-a")
        require(first.status_code == 200, "Initial rotation failed")
        stale = flow.engine.refresh(initial, replica="kc-b")
        child = flow.engine.refresh(first.json()["refresh_token"], replica="kc-a")
        details.update(stale_refresh=error_summary(stale), rotated_child=error_summary(child))
        require(stale.status_code == 400 and "access_token" not in stale.json(), "Used refresh token was accepted")
        require(child.status_code == 200, "Denying stale-token replay invalidated the legitimate rotated child")
    check("KC-CLUSTER-STALE-REFRESH-DENY-WITH-CHILD-SURVIVAL", replay, "Used refresh is rejected while the legitimate replacement remains usable")

    def race(details):
        flow = login("race")
        initial = flow.tokens["refresh_token"]
        barrier = threading.Barrier(2)
        def send(replica):
            engine = Engine(replica)
            barrier.wait(timeout=10)
            return replica, engine.refresh(initial, replica=replica)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            responses = list(executor.map(send, ("kc-a", "kc-b")))
        winners = [(replica, response) for replica, response in responses if response.status_code == 200]
        details["simultaneous_refresh"] = [{"replica": replica, **error_summary(response)} for replica, response in responses]
        details["successful_rotations"] = len(winners)
        children = []
        for replica, response in winners:
            follow = Engine().refresh(response.json()["refresh_token"], replica="kc-b" if replica == "kc-a" else "kc-a")
            children.append(error_summary(follow))
        details["winner_followup"] = children
        require(len(winners) == 1, "Concurrent same-token refresh did not produce exactly one successful rotation")
        require(children[0]["http_status"] == 200, "Winning refresh token was unusable after the concurrent stale request")
    check("KC-CLUSTER-CONCURRENT-REFRESH-SINGLE-SURVIVING-ROTATION", race, "Two simultaneous replica refreshes yield one usable rotation and reject the stale competitor")

    def lost_response(details):
        flow = login("response-loss")
        initial = flow.tokens["refresh_token"]
        committed = flow.engine.refresh(initial, replica="kc-a")
        require(committed.status_code == 200, "Response-loss precondition did not commit a refresh")
        # Observe server success, then discard response content from the retrying
        # client perspective. No engine state or response is mocked/rewritten.
        del committed
        retry = flow.engine.refresh(initial, replica="kc-b")
        details.update(first_server_response_committed=True, first_response_intentionally_discarded=True, retry=error_summary(retry), configured_max_reuse=0)
        require(retry.status_code == 200, "A committed refresh response lost by the client cannot be recovered by retrying the original token")
    check("KC-CLUSTER-POSTCOMMIT-RESPONSE-LOSS-RECOVERY", lost_response, "Client can recover a refresh after losing the committed response without reauthentication")

    def client_revoke(details):
        alpha = login("client-revoke")
        beta = login("client-revoke", "cluster-beta", alpha.engine)
        require(beta.used_sso, "Second client did not reuse the real engine SSO cookie")
        details.update(second_client_used_sso=True, shared_parent_sid=alpha.id_claims.get("sid") == beta.id_claims.get("sid"), shared_sid_is_failure=False)
        response = alpha.engine.at("kc-a").post(OIDC + "/revoke", data={"client_id": "cluster-alpha", "token_type_hint": "refresh_token", "token": alpha.tokens["refresh_token"]})
        deny = alpha.engine.refresh(alpha.tokens["refresh_token"], replica="kc-b")
        survive = beta.engine.refresh(beta.tokens["refresh_token"], client_id="cluster-beta", replica="kc-b")
        details.update(revoke_http_status=response.status_code, revoked_client=error_summary(deny), other_client=error_summary(survive))
        require(response.status_code == 200 and deny.status_code == 400, "Client-specific revocation did not reject its refresh token")
        require(survive.status_code == 200, "Client-specific revocation invalidated another client's session")
    check("KC-CLUSTER-CLIENT-SPECIFIC-REVOCATION-ISOLATION", client_revoke, "Revoking alpha's refresh token preserves beta's authenticated client session under shared SSO")

    def global_logout(details):
        alpha = login("global-logout")
        beta = login("global-logout", "cluster-beta", alpha.engine)
        require(beta.used_sso, "Second client did not reuse SSO")
        response = alpha.engine.at("kc-b").get(OIDC + "/logout", params={"id_token_hint": alpha.tokens["id_token"], "client_id": "cluster-alpha", "post_logout_redirect_uri": "http://cluster-client.example.test/logout", "state": "logout-proof-state"})
        target = urlparse(response.headers.get("location", ""))
        require(response.status_code == 302 and target.netloc == "cluster-client.example.test" and target.path == "/logout", "RP logout did not return the registered URI")
        require(parse_qs(target.query).get("state") == ["logout-proof-state"], "Logout state changed")
        statuses = []
        for flow, replica in ((alpha, "kc-a"), (beta, "kc-b")):
            denial = flow.engine.refresh(flow.tokens["refresh_token"], flow.client_id, replica)
            statuses.append(denial.status_code)
        cookies = set(alpha.engine.client.cookies)
        details.update(refresh_statuses=statuses, final_engine_cookies_removed=not {"KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION"}.intersection(cookies), global_scope_intentional=True)
        require(statuses == [400, 400], "Global RP logout retained a client refresh session")
        require(not {"KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION"}.intersection(cookies), "Global logout retained final engine cookies")
    check("KC-CLUSTER-GLOBAL-RP-LOGOUT", global_logout, "Explicit global RP logout removes SSO cookies and denies both clients across replicas")

    expected = 10
    failed = sum(event["status"] == "failed" for event in events)
    report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "command": "python tools/run_keycloak_cluster.py probe", "candidate_selected": False, "foundation_gate_passed": False, "keycloak_version": "26.7.3", "source_commit": "6d238b6558037085cc25c915893c3d301a80243e", "expected_tests": expected, "executed": len(events), "passed": len(events) - failed, "failed": failed, "unexecuted": expected - len(events), "skipped": 0, "exit_code": int(bool(failed) or len(events) != expected), "tests": events, "input_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in (pathlib.Path(__file__), ROOT / "tools/run_keycloak_cluster.py", ROOT / "evidence/foundation/keycloak-sessions/startup-report.json", EXT / "Dockerfile.postgres", EXT / "build.gradle")}, "limitations": ["Bounded synthetic candidate characterization, not full M1 or SuperTokens session parity", "HTTP on private network only; public TLS/cookie policy and browser/native transport profiles unqualified", "Two-member cluster with shared PostgreSQL observed; process-crash, full disaster recovery, rolling upgrade and independent security review unqualified", "Explicit strict refresh rotation policy; failures are retained rather than disabled or treated as passing"]}
    destination = ROOT / "evidence/foundation/keycloak-sessions/probe-report.json"
    destination.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("executed", "passed", "failed", "unexecuted", "exit_code")}))
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
