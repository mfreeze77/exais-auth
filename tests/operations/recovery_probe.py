"""Real HTTP worker for a host-controlled, isolated backup/restore drill.

Stdout emits JSON control requests: snapshot, restore, start_restored_app.
Each requires one stdin JSON line {"ok": true}. No restored application request
is made before the two owned post-snapshot actions have been reconciled.
Private fixture/journal files are never copied into public evidence.
"""
from __future__ import annotations

from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import sys
import threading
import time
from urllib.parse import urlsplit
import uuid

import httpx


STAGES = [
    "RECOVERY-SOURCE-INITIAL-IDENTITY-SET", "RECOVERY-SOURCE-TWO-SIGNUPS",
    "RECOVERY-SOURCE-SNAPSHOT-SESSIONS", "RECOVERY-HOST-SNAPSHOT",
    "RECOVERY-SOURCE-REVOKE", "RECOVERY-SOURCE-DELETE", "RECOVERY-HOST-RESTORE",
    "RECOVERY-HISTORICAL-STATE-CHARACTERIZATION", "RECOVERY-RESTORED-REVOKE",
    "RECOVERY-RESTORED-DELETE", "RECOVERY-RECONCILED-CORE-STATE",
    "RECOVERY-HOST-START-RESTORED-APP", "RECOVERY-SOURCE-OLD-REFRESH-DENIED",
    "RECOVERY-RESTORED-OLD-REFRESH-DENIED", "RECOVERY-DELETED-SIGNIN-DENIED",
    "RECOVERY-SURVIVOR-NEW-SIGNIN-PROTECTED", "RECOVERY-SURVIVOR-LOGOUT-REFRESH-DENIED",
    "RECOVERY-CLEANUP-SOURCE", "RECOVERY-CLEANUP-RESTORED", "RECOVERY-SOURCE-IDENTITY-SET-RESTORED",
]
CHARACTERIZATION = "RECOVERY-HISTORICAL-STATE-CHARACTERIZATION"


class ProbeFailure(Exception):
    """Only fixed, source-authored messages may reach the public report."""


def require(condition, fixed_message):
    if not condition:
        raise ProbeFailure(fixed_message)


def now():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path, value, private=False):
    raw = (json.dumps(value, indent=2) + "\n").encode("utf-8")
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def response_json(response):
    try:
        value = response.json()
    except ValueError:
        raise ProbeFailure("Endpoint returned invalid JSON") from None
    require(isinstance(value, dict), "Endpoint returned an invalid object")
    return value


def identity_emails(user):
    values = user.get("emails", [])
    if not isinstance(values, list):
        values = []
    return {value for value in [user.get("email"), *values] if isinstance(value, str)}


class Worker:
    def __init__(self, cleanup_only=False):
        self.cleanup_only = cleanup_only
        required = ("EVIDENCE_DIR", "PRIVATE_DIR", "SOURCE_APP_URL", "RESTORED_APP_URL",
                    "SOURCE_CORE_URL", "RESTORED_CORE_URL", "LOGICAL_ORIGIN", "EXPERTAUTH_CORE_API_KEY")
        require(all(os.environ.get(name) for name in required), "Required worker configuration is missing")
        self.out = Path(os.environ["EVIDENCE_DIR"]).resolve()
        self.private = Path(os.environ["PRIVATE_DIR"]).resolve()
        require(self.out != self.private and not self.out.is_relative_to(self.private) and not self.private.is_relative_to(self.out),
                "Private and evidence directories must be separate")
        self.out.mkdir(parents=True, exist_ok=True)
        self.private.mkdir(parents=True, exist_ok=True)
        self.report_name = "cleanup-report.json" if cleanup_only else "probe-report.json"
        require(not (self.out / self.report_name).exists(), "Existing public evidence must be preserved")
        if not cleanup_only:
            require(not (self.private / "state.json").exists() and not (self.private / "reconciliation.json").exists(),
                    "Existing private fixture state must be preserved")
        self.urls = {key: os.environ[key].rstrip("/") for key in required if key.endswith("_URL")}
        self.origin = os.environ["LOGICAL_ORIGIN"].rstrip("/")
        for value in [*self.urls.values(), self.origin]:
            parsed = urlsplit(value)
            require(parsed.scheme in ("http", "https") and parsed.netloc and parsed.path in ("", "/") and not parsed.query and not parsed.fragment and parsed.username is None,
                    "Worker endpoint configuration is invalid")
        require(self.urls["SOURCE_CORE_URL"] != self.urls["RESTORED_CORE_URL"] and self.urls["SOURCE_APP_URL"] != self.urls["RESTORED_APP_URL"],
                "Source and restored endpoints must be distinct")
        self.key = os.environ["EXPERTAUTH_CORE_API_KEY"]
        self.client = httpx.Client(timeout=10, trust_env=False, follow_redirects=False)
        self.started = time.monotonic()
        self.rows = []
        self.journal = None
        self.state = {"schema": "expertauth-private-recovery-fixtures-v1", "phase": "initializing", "started": now(),
                      "before_source_identity_ids": None, "snapshot_session_handles": {}, "restore_requested": False,
                      "restored_core_observed": False, "restored_app_started": False, "users": []}
        for role in ("survivor", "deleted"):
            self.state["users"].append({"role": role, "email": "recovery-" + uuid.uuid4().hex + "@example.test",
                                        "password": "Synthetic-" + uuid.uuid4().hex + "-9a!", "signup_attempted": False,
                                        "user_id": None, "access_token": None, "refresh_token": None})
        if cleanup_only:
            self.state = json.loads((self.private / "state.json").read_text(encoding="utf-8"))
            require(isinstance(self.state, dict) and self.state.get("schema") == "expertauth-private-recovery-fixtures-v1",
                    "Private fixture state schema differs")
            users = self.state.get("users")
            require(isinstance(users, list) and len(users) == 2 and all(isinstance(user, dict) for user in users)
                    and [user.get("role") for user in users] == ["survivor", "deleted"], "Private fixture roles differ")
            baseline = self.state.get("before_source_identity_ids")
            require(isinstance(baseline, list) and all(isinstance(value, str) and value for value in baseline)
                    and len(set(baseline)) == len(baseline), "Private initial identity set is invalid")
            require(isinstance(self.state.get("snapshot_session_handles"), dict)
                    and isinstance(self.state.get("restore_requested"), bool), "Private recovery state is invalid")
            require(len({user.get("email") for user in users}) == 2, "Private fixture emails are not distinct")
            for user in users:
                self.validate_fixture(user)
        self.stage_ids = ([STAGES[17]] + ([STAGES[18]] if self.state["restore_requested"] else []) + [STAGES[19]]) if cleanup_only else STAGES
        self.report = {"schema": "expertauth-isolated-recovery-http-worker-v1", "started": now(),
                       "scope": "Two owned post-snapshot actions reconciled before restored application startup",
                       "foundation_passed": False, "full_recovery_qualified": False, "full_AT_OPS_006_passed": False,
                       "full_WP033_passed": False, "drill_passed": False, "ok": False, "cleanup_only": cleanup_only,
                       "fdi_version": "4.2", "cdi_version": "5.4",
                       "transport": "Maintained Python SDK header sessions and real Core HTTP",
                       "input_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                       "private_fixture_values_in_evidence": False, "restored_app_contacted_before_reconciliation": False,
                       "errors": [], "rows": self.rows, "expected_checks": len(self.stage_ids), "skipped": 0,
                       "blocked": ["Generalized durable reconciliation journal and transactional capture of all security changes",
                                   "Credential-policy, identity-policy and key changes after snapshot",
                                   "Backup encryption/key management and recipient recovery governance",
                                   "Production recovery objectives, full operational matrix and independent review"]}
        self.save_private()
        self.flush()

    def save_private(self):
        self.state["updated"] = now()
        atomic_json(self.private / "state.json", self.state, private=True)
        if self.journal is not None:
            atomic_json(self.private / "reconciliation.json", self.journal, private=True)

    def flush(self, final=False):
        self.report.update({"updated": now(), "executed": sum(row["status"] != "unexecuted" for row in self.rows),
                            "passed": sum(row["status"] == "passed" for row in self.rows),
                            "characterized": sum(row["status"] == "characterized" for row in self.rows),
                            "failed": sum(row["status"] == "failed" for row in self.rows),
                            "unexecuted": len(self.stage_ids) - sum(row["status"] != "unexecuted" for row in self.rows),
                            "elapsed_ms": round((time.monotonic() - self.started) * 1000, 2),
                            "fixtures_with_recorded_identity": sum(bool(user["user_id"]) for user in self.state["users"]),
                            "final": final})
        # No remote exception/response body is included; additionally reject any
        # private fixture material accidentally added to public details.
        encoded = json.dumps(self.report)
        secrets = [self.key]
        for user in self.state["users"]:
            secrets.extend(user.get(key) for key in ("email", "password", "user_id", "access_token", "refresh_token", "new_access_token", "new_refresh_token"))
        secrets.extend(self.state.get("before_source_identity_ids") or [])
        for handles in self.state["snapshot_session_handles"].values():
            secrets.extend(handles)
        require(not any(value and value in encoded for value in secrets), "Public evidence contained private fixture material")
        atomic_json(self.out / self.report_name, self.report)

    def step(self, identifier, function, characterization=False):
        self.state["phase"] = identifier
        self.save_private()
        started = time.monotonic()
        try:
            details = function() or {}
            self.rows.append({"id": identifier, "status": "characterized" if characterization else "passed",
                              "elapsed_ms": round((time.monotonic() - started) * 1000, 2), "details": details})
        except Exception as error:
            self.rows.append({"id": identifier, "status": "failed", "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
                              "error": str(error) if isinstance(error, ProbeFailure) else "Worker operation failed"})
            self.flush()
            raise ProbeFailure("Required recovery stage failed") from None
        self.flush()

    def core(self, target, path, body=None, params=None):
        return self.client.request("GET" if body is None else "POST", self.urls[target.upper() + "_CORE_URL"] + path,
                                   headers={"api-key": self.key, "cdi-version": "5.4", "rid": "session"} if path.startswith("/recipe/session") else {"api-key": self.key, "cdi-version": "5.4"},
                                   json=body, params=params)

    def users(self, target):
        response = self.core(target, "/users", params={"limit": 500})
        require(response.status_code == 200, "Core identity enumeration failed")
        value = response_json(response)
        require(value.get("status") == "OK" and not value.get("nextPaginationToken"), "Identity enumeration exceeded the bounded single page")
        users = value.get("users")
        require(isinstance(users, list) and all(isinstance(user, dict) and isinstance(user.get("id"), str) and user["id"] for user in users),
                "Core identity enumeration shape differs")
        require(len({user["id"] for user in users}) == len(users), "Core identity enumeration contains duplicate IDs")
        return users

    def ids(self, target):
        return {user["id"] for user in self.users(target)}

    def headers(self, recipe="session", token=None):
        return {"origin": self.origin, "fdi-version": "4.2", "rid": recipe, "st-auth-mode": "header",
                **({"authorization": "Bearer " + token} if token else {})}

    def app(self, target, method, path, user=None, token=None):
        if target == "restored":
            require(self.state["restored_app_started"] and self.journal is not None and all(action["restored_applied"] for action in self.journal["actions"]),
                    "Restored application was requested before reconciliation")
        body = {"formFields": [{"id": "email", "value": user["email"]}, {"id": "password", "value": user["password"]}]} if user else None
        return self.client.request(method, self.urls[target.upper() + "_APP_URL"] + path,
                                   headers=self.headers("emailpassword" if user else "session", token), json=body)

    def sessions(self, target, user):
        response = self.core(target, "/recipe/session/user", params={"userId": user["user_id"], "fetchAcrossAllTenants": "true", "fetchSessionsForAllLinkedAccounts": "false"})
        require(response.status_code == 200, "Core session enumeration failed")
        value = response_json(response)
        handles = value.get("sessionHandles")
        require(value.get("status") == "OK" and isinstance(handles, list) and all(isinstance(handle, str) and handle for handle in handles),
                "Core session enumeration shape differs")
        require(len(handles) == len(set(handles)), "Core session enumeration contains duplicates")
        return set(handles)

    def session_expiry(self, target, user, handle):
        response = self.core(target, "/recipe/session", params={"sessionHandle": handle})
        value = response_json(response)
        require(response.status_code == 200 and value.get("status") == "OK" and value.get("userId") == user["user_id"]
                and value.get("tenantId") == "public", "Session lifetime lookup did not identify the owned session")
        expiry = value.get("expiry")
        require(type(expiry) is int and expiry > int(time.time() * 1000) + 30000, "Session refresh lifetime was missing or too short")
        return expiry

    def jwks(self, target):
        response = self.core(target, "/.well-known/jwks.json")
        value = response_json(response)
        keys = value.get("keys")
        require(response.status_code == 200 and isinstance(keys, list) and keys
                and all(isinstance(key, dict) and isinstance(key.get("kty"), str) and key.get("kty") for key in keys),
                "Core public signing key set was empty or invalid")
        value["keys"] = sorted(keys, key=lambda key: json.dumps(key, sort_keys=True, separators=(",", ":")))
        return {"key_count": len(keys), "canonical_json_sha256": hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest(),
            "canonicalization": "Object keys sorted; JWKS keys ordered by canonical key JSON"}

    def await_restored_core(self):
        started = time.monotonic()
        attempts = 0
        deadline = started + 40
        while time.monotonic() < deadline:
            attempts += 1
            try:
                response = self.client.get(self.urls["RESTORED_CORE_URL"] + "/users", params={"limit": 500},
                                           headers={"api-key": self.key, "cdi-version": "5.4"},
                                           timeout=min(2, max(0.1, deadline - time.monotonic())))
                if response.status_code == 200 and response_json(response).get("status") == "OK":
                    return {"database_backed_readiness": True, "readiness_attempts": attempts,
                            "readiness_elapsed_ms": round((time.monotonic() - started) * 1000, 2), "readiness_limit_seconds": 40}
            except (httpx.HTTPError, ProbeFailure):
                pass
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))
        raise ProbeFailure("Restored Core database readiness was not established within the bounded timeout")

    def control(self, action):
        if action == "restore":
            self.state["restore_requested"] = True
        self.state["waiting_for_control"] = action
        self.save_private()
        self.flush()
        print(json.dumps({"control": action}), flush=True)
        answers = queue.Queue(maxsize=1)

        def read_answer():
            try:
                answers.put(sys.stdin.readline(4097))
            except Exception:
                answers.put("")

        threading.Thread(target=read_answer, daemon=True).start()
        try:
            raw = answers.get(timeout=180)
            answer = json.loads(raw) if raw and len(raw) <= 4096 else None
        except Exception:
            raise ProbeFailure("Host control response was absent or invalid") from None
        require(isinstance(answer, dict) and answer.get("ok") is True, "Host control did not succeed")
        self.state["waiting_for_control"] = None
        self.state[action + "_acknowledged"] = now()
        if action == "start_restored_app":
            self.state["restored_app_started"] = True
        self.save_private()
        details = {"host_control": action, "acknowledged": True}
        if action == "restore":
            details.update(self.await_restored_core())
        return details

    def baseline(self):
        self.state["before_source_identity_ids"] = sorted(self.ids("source"))
        self.save_private()
        return {"source_identity_count": len(self.state["before_source_identity_ids"]), "pagination_present": False}

    def signup(self):
        for user in self.state["users"]:
            user["signup_attempted"] = True
            self.save_private()
            response = self.app("source", "POST", "/auth/signup", user=user)
            body = response_json(response)
            created = body.get("user", {})
            if body.get("status") == "OK" and isinstance(created, dict) and isinstance(created.get("id"), str) and created["id"]:
                require(created["id"] not in self.state["before_source_identity_ids"] and created["id"] not in {item["user_id"] for item in self.state["users"]},
                        "Signup returned an identity outside the owned fixture boundary")
                user["user_id"] = created["id"]
                user["access_token"] = response.headers.get("st-access-token")
                user["refresh_token"] = response.headers.get("st-refresh-token")
                self.save_private()
            require(response.status_code == 200 and body.get("status") == "OK" and user["user_id"], "Source SDK signup failed")
            require(user["access_token"] and user["refresh_token"], "Source SDK did not return header session tokens")
        require(self.ids("source") == set(self.state["before_source_identity_ids"]) | {user["user_id"] for user in self.state["users"]},
                "Source identity set changed outside the two fixtures")
        return {"signup_http_statuses": [200, 200], "created_fixtures": 2}

    def protected(self, target, user, token):
        response = self.app(target, "GET", "/protected", token=token)
        require(response.status_code == 200, "Verified session was denied")
        value = response_json(response)
        require(value.get("userId") == user["user_id"] and value.get("tenantId") == "public" and value.get("verification") == "signature-and-online-session-check",
                "Protected response did not prove the owned online session")

    def snapshot_sessions(self):
        for user in self.state["users"]:
            self.protected("source", user, user["access_token"])
            handles = self.sessions("source", user)
            self.state["snapshot_session_handles"][user["role"]] = sorted(handles)
            self.save_private()
            require(len(handles) == 1, "Expected one real signup session for each snapshot fixture")
            user["snapshot_refresh_expiry_ms"] = self.session_expiry("source", user, next(iter(handles)))
            self.save_private()
        self.state["snapshot_jwks"] = self.jwks("source")
        self.save_private()
        return {"protected_http_statuses": [200, 200], "snapshot_sessions": 2, "online_session_verification": True,
                "refresh_lifetime_source": "Core stored session expiry in milliseconds; no token decoding",
                "public_jwks": self.state["snapshot_jwks"]}

    def prepare_journal(self):
        self.journal = {"schema": "expertauth-private-two-action-reconciliation-v1", "created": now(),
                        "scope": "Only the two owned synthetic post-snapshot actions; not a generalized durable journal",
                        "actions": [{"sequence": index + 1, "operation": operation, "user_id": self.state["users"][index]["user_id"],
                                     "source_applied": False, "restored_applied": False}
                                    for index, operation in enumerate(("revoke_all_sessions", "delete_user"))]}
        self.save_private()

    def apply_action(self, target, index):
        action = self.journal["actions"][index]
        user = self.state["users"][index]
        require(action["user_id"] == user["user_id"] and user["user_id"] not in self.state["before_source_identity_ids"],
                "Reconciliation action escaped the owned fixture boundary")
        self.save_private()
        if index == 0:
            response = self.core(target, "/recipe/session/remove", {"userId": user["user_id"], "revokeSessionsForLinkedAccounts": False})
            value = response_json(response)
            require(response.status_code == 200 and value.get("status") == "OK", "Owned session revocation failed")
            revoked = value.get("sessionHandlesRevoked")
            require(isinstance(revoked, list) and set(revoked) == set(self.state["snapshot_session_handles"][user["role"]]),
                    "Owned session revocation did not remove the snapshotted session set")
            require(not self.sessions(target, user), "Owned sessions remained after revocation")
            details = {"http_status": 200, "session_handles_revoked": len(revoked)}
        else:
            response = self.core(target, "/user/remove", {"userId": user["user_id"], "removeAllLinkedAccounts": False})
            require(response.status_code == 200 and response_json(response).get("status") == "OK", "Owned identity deletion failed")
            require(user["user_id"] not in self.ids(target), "Owned deleted identity remained present")
            details = {"http_status": 200, "deleted_identity_absent": True}
        action[target + "_applied"] = True
        action[target + "_applied_at"] = now()
        self.save_private()
        return details

    def historical_state(self):
        restored_ids = self.ids("restored")
        self.state["restored_core_observed"] = True
        self.save_private()
        require(restored_ids == set(self.state["before_source_identity_ids"]) | {user["user_id"] for user in self.state["users"]},
                "Restored Core did not contain the exact snapshot identity set")
        for user in self.state["users"]:
            require(self.sessions("restored", user) == set(self.state["snapshot_session_handles"][user["role"]]),
                    "Restored Core did not contain the exact historical session set")
            handle = self.state["snapshot_session_handles"][user["role"]][0]
            require(self.session_expiry("restored", user, handle) == user["snapshot_refresh_expiry_ms"],
                    "Restored historical session lifetime differs from snapshot")
        restored_jwks = self.jwks("restored")
        require(restored_jwks == self.state["snapshot_jwks"], "Restored public signing key set differs from snapshot")
        self.state["restored_jwks"] = restored_jwks
        self.save_private()
        return {"historical_fixture_users_present": 2, "historical_sessions_present": 2,
                "historical_refresh_lifetimes_preserved": True, "public_jwks": restored_jwks,
                "public_jwks_matches_snapshot": True,
                "acceptable_final_recovery": False, "application_start_gate": "reconciliation-required",
                "classification": "Historical snapshot state characterized; not a passed final recovery check"}

    def reconciled_state(self):
        survivor, deleted = self.state["users"]
        expected = set(self.state["before_source_identity_ids"]) | {survivor["user_id"]}
        require(self.ids("restored") == expected and self.ids("source") == expected, "Reconciled source/restored identity sets differ")
        require(not self.sessions("restored", survivor) and not self.sessions("restored", deleted), "Historical sessions survived reconciliation")
        return {"owned_actions_replayed": 2, "survivor_present": True, "deleted_identity_absent": True, "old_sessions_remaining": 0,
                "restored_application_not_started": not self.state["restored_app_started"]}

    def old_refresh_denied(self, target):
        statuses = []
        remaining_lifetimes = []
        for user in self.state["users"]:
            remaining_ms = user["snapshot_refresh_expiry_ms"] - int(time.time() * 1000)
            require(remaining_ms > 30000, "Old refresh denial cannot be distinguished from lifetime expiry")
            response = self.app(target, "POST", "/auth/session/refresh", token=user["refresh_token"])
            statuses.append(response.status_code)
            require(response.status_code == 401 and not response.headers.get("st-access-token") and not response.headers.get("st-refresh-token"),
                    "A post-snapshot revoked or deleted session refreshed")
            remaining_ms = user["snapshot_refresh_expiry_ms"] - int(time.time() * 1000)
            require(remaining_ms > 0, "Old refresh token expired during the denial request")
            remaining_lifetimes.append(round(remaining_ms / 1000, 2))
        return {"http_statuses": statuses, "owned_old_refresh_tokens_denied": 2,
                "denial_while_original_refresh_lifetime_remaining": True, "remaining_lifetime_seconds": remaining_lifetimes}

    def deleted_signin(self):
        deleted = self.state["users"][1]
        statuses = []
        for target in ("source", "restored"):
            response = self.app(target, "POST", "/auth/signin", user=deleted)
            statuses.append(response.status_code)
            require(response.status_code == 200 and response_json(response).get("status") == "WRONG_CREDENTIALS_ERROR" and not response.headers.get("st-access-token") and not response.headers.get("st-refresh-token"),
                    "Deleted identity authenticated after reconciliation")
        return {"http_statuses": statuses, "source_and_restored_credentials_rejected": True}

    def new_signin(self):
        user = self.state["users"][0]
        response = self.app("restored", "POST", "/auth/signin", user=user)
        user["new_access_token"] = response.headers.get("st-access-token")
        user["new_refresh_token"] = response.headers.get("st-refresh-token")
        self.save_private()
        value = response_json(response)
        require(response.status_code == 200 and value.get("status") == "OK" and value.get("user", {}).get("id") == user["user_id"],
                "Surviving identity could not sign in after recovery")
        require(user["new_access_token"] and user["new_refresh_token"], "Recovered signin omitted header session tokens")
        self.protected("restored", user, user["new_access_token"])
        handles = self.sessions("restored", user)
        require(len(handles) == 1, "Recovered signin did not create exactly one owned session")
        user["new_refresh_expiry_ms"] = self.session_expiry("restored", user, next(iter(handles)))
        self.save_private()
        return {"signin_http_status": 200, "protected_http_status": 200, "original_survivor_identity_preserved": True}

    def new_logout(self):
        user = self.state["users"][0]
        response = self.app("restored", "POST", "/auth/signout", token=user["new_access_token"])
        require(response.status_code == 200 and response_json(response).get("status") == "OK", "Recovered session logout failed")
        self.state["survivor_new_session_logged_out"] = True
        self.save_private()
        require(user["new_refresh_expiry_ms"] > int(time.time() * 1000) + 30000,
                "Recovered logout denial cannot be distinguished from lifetime expiry")
        response = self.app("restored", "POST", "/auth/session/refresh", token=user["new_refresh_token"])
        require(response.status_code == 401 and not response.headers.get("st-access-token") and not response.headers.get("st-refresh-token"),
                "Recovered logged-out session refreshed")
        require(not self.sessions("restored", user), "Recovered logged-out session remained stored")
        remaining_ms = user["new_refresh_expiry_ms"] - int(time.time() * 1000)
        require(remaining_ms > 0, "Recovered refresh token expired during the denial request")
        return {"logout_http_status": 200, "refresh_after_logout_http_status": 401,
                "denial_while_original_refresh_lifetime_remaining": True, "remaining_lifetime_seconds": round(remaining_ms / 1000, 2)}

    def validate_fixture(self, user):
        require(isinstance(user.get("email"), str) and re.fullmatch(r"recovery-[0-9a-f]{32}@example\.test", user["email"]),
                "Private fixture email is outside the exact owned format")
        require(type(user.get("signup_attempted")) is bool, "Private fixture signup marker is invalid")
        require(user.get("user_id") is None or (isinstance(user["user_id"], str) and user["user_id"]),
                "Private fixture identity is invalid")
        require(user.get("user_id") is None or user["signup_attempted"], "Private identity has no attempted fixture signup")

    def cleanup(self, target):
        baseline = set(self.state["before_source_identity_ids"] or [])
        observed = self.users(target)
        by_id = {row["id"]: row for row in observed}
        # A signup response may be lost after the Core commits. Recover only an
        # exact generated email whose signup was attempted, never a prefix match.
        for user in self.state["users"]:
            self.validate_fixture(user)
            if not user["signup_attempted"]:
                continue
            candidates = [row["id"] for row in observed if user["email"] in identity_emails(row) and row["id"] not in baseline]
            require(len(candidates) <= 1, "Cleanup found ambiguous fixture ownership")
            if user["user_id"] is None and candidates:
                user["user_id"] = candidates[0]
                self.save_private()
            elif candidates:
                require(candidates[0] == user["user_id"], "Cleanup fixture identity mapping changed")
            if user["user_id"] in by_id:
                require(user["email"] in identity_emails(by_id[user["user_id"]]),
                        "Cleanup existing identity does not retain the exact owned email")
        owned = {user["user_id"] for user in self.state["users"] if user["user_id"]}
        require(len(owned) == sum(bool(user["user_id"]) for user in self.state["users"]), "Private fixture identities are not distinct")
        require(not owned & baseline, "Cleanup attempted to remove a preexisting identity")
        self.state["cleanup_" + target + "_started"] = True
        self.save_private()
        requests = 0
        for user_id in sorted(owned):
            if user_id not in by_id:
                continue
            response = self.core(target, "/user/remove", {"userId": user_id, "removeAllLinkedAccounts": False})
            require(response.status_code == 200 and response_json(response).get("status") == "OK", "Owned fixture cleanup request failed")
            requests += 1
        remaining = self.ids(target)
        require(not owned & remaining, "Owned fixture remained after cleanup")
        self.state["cleanup_" + target + "_complete"] = True
        self.save_private()
        return {"owned_identity_count": len(owned), "delete_requests": requests, "owned_identities_confirmed_absent": len(owned),
                "existing_identity_email_ownership_required": True}

    def restored_baseline(self):
        require(self.state["before_source_identity_ids"] is not None, "Initial source identity snapshot was unavailable")
        require(self.ids("source") == set(self.state["before_source_identity_ids"]), "Source identity set did not return to its initial value")
        return {"source_identity_set_exactly_restored": True, "source_identity_count": len(self.state["before_source_identity_ids"])}

    def run_cleanup(self):
        functions = {STAGES[17]: lambda: self.cleanup("source"), STAGES[18]: lambda: self.cleanup("restored"),
                     STAGES[19]: self.restored_baseline}
        try:
            for identifier in self.stage_ids:
                try:
                    self.step(identifier, functions[identifier])
                except Exception:
                    self.report["errors"].append("Fallback fixture cleanup or source restoration verification was incomplete")
            self.report["ok"] = not self.report["errors"] and len(self.rows) == len(self.stage_ids) and all(row["status"] == "passed" for row in self.rows)
            self.report["exit_code"] = 0 if self.report["ok"] else 1
            self.report["finished"] = now()
            self.report["scope"] = "Fallback exact-owned fixture cleanup only; original recovery report preserved"
            self.report["original_probe_report_overwritten"] = False
            self.report["restored_cleanup_required"] = self.state["restore_requested"]
            self.save_private()
            self.flush(final=True)
        finally:
            self.client.close()
        print(json.dumps({"complete": True, "cleanup_only": True, "ok": self.report["ok"], "exit_code": self.report["exit_code"]}), flush=True)
        return self.report["exit_code"]

    def run(self):
        try:
            self.step(STAGES[0], self.baseline)
            self.step(STAGES[1], self.signup)
            self.step(STAGES[2], self.snapshot_sessions)
            self.step(STAGES[3], lambda: self.control("snapshot"))
            self.prepare_journal()
            self.step(STAGES[4], lambda: self.apply_action("source", 0))
            self.step(STAGES[5], lambda: self.apply_action("source", 1))
            self.step(STAGES[6], lambda: self.control("restore"))
            self.step(STAGES[7], self.historical_state, characterization=True)
            self.step(STAGES[8], lambda: self.apply_action("restored", 0))
            self.step(STAGES[9], lambda: self.apply_action("restored", 1))
            self.step(STAGES[10], self.reconciled_state)
            self.step(STAGES[11], lambda: self.control("start_restored_app"))
            self.step(STAGES[12], lambda: self.old_refresh_denied("source"))
            self.step(STAGES[13], lambda: self.old_refresh_denied("restored"))
            self.step(STAGES[14], self.deleted_signin)
            self.step(STAGES[15], self.new_signin)
            self.step(STAGES[16], self.new_logout)
        except Exception:
            self.report["errors"].append("Recovery worker did not complete its required sequence")
        finally:
            for identifier, function in ((STAGES[17], lambda: self.cleanup("source")),
                                          (STAGES[18], lambda: self.cleanup("restored")),
                                          (STAGES[19], self.restored_baseline)):
                if identifier == STAGES[18] and not self.state["restore_requested"]:
                    continue
                try:
                    self.step(identifier, function)
                except Exception:
                    self.report["errors"].append("Owned fixture cleanup or source restoration verification was incomplete")
            recorded = {row["id"] for row in self.rows}
            for identifier in STAGES:
                if identifier not in recorded:
                    self.rows.append({"id": identifier, "status": "unexecuted", "reason": "Required prerequisite was not established"})
            self.report["drill_passed"] = not self.report["errors"] and len(self.rows) == len(STAGES) and all(
                row["status"] == ("characterized" if row["id"] == CHARACTERIZATION else "passed") for row in self.rows)
            self.report["ok"] = self.report["drill_passed"]
            self.report["exit_code"] = 0 if self.report["drill_passed"] else 1
            self.report["finished"] = now()
            self.state["phase"] = "finished" if self.report["drill_passed"] else "partial"
            self.save_private()
            self.flush(final=True)
            self.client.close()
        print(json.dumps({"complete": True, "ok": self.report["drill_passed"], "exit_code": self.report["exit_code"],
                          "passed": self.report["passed"], "characterized": self.report["characterized"],
                          "failed": self.report["failed"], "unexecuted": self.report["unexecuted"]}), flush=True)
        return self.report["exit_code"]


def main():
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--cleanup-only", action="store_true", help="Delete only privately recorded, live email-verified fixtures; preserve original report")
        args = parser.parse_args()
        worker = Worker(cleanup_only=args.cleanup_only)
        return worker.run_cleanup() if args.cleanup_only else worker.run()
    except Exception:
        # Initialization/failed evidence storage must not emit a traceback with
        # private values. Existing reports/private state are deliberately kept.
        print(json.dumps({"complete": True, "ok": False, "exit_code": 1, "error": "Worker initialization or durable evidence persistence failed"}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
