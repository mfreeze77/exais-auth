"""Exact-owned Core HTTP cleanup for a persisted password-reset lab fixture.

The entire fixture-to-current-identity mapping is validated before deletion.
No credentials, mail, identity IDs, private paths, or remote errors are reported.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, ProxyHandler, Request


EMAIL = re.compile(r"reset-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}@example\.test")
MAX_BYTES = 4 * 1024 * 1024


class CleanupFailure(Exception):
    """Only fixed source-authored error codes are used."""


def require(condition, code):
    if not condition:
        raise CleanupFailure(code)


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def identifier(value):
    return isinstance(value, str) and 0 < len(value) <= 1024 and not re.search(r"[\x00-\x1f\x7f]", value)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_FIELD")
        result[key] = value
    return result


def load_fixtures(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "FIXTURE_FILE_TOO_LARGE")
    value = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(value, dict), "INVALID_FIXTURE_OBJECT")
    baseline, users = value.get("baseline"), value.get("users")
    require(isinstance(baseline, list) and len(baseline) <= 500 and all(identifier(item) for item in baseline), "INVALID_BASELINE_IDS")
    require(len(baseline) == len(set(baseline)), "DUPLICATE_BASELINE_ID")
    require(isinstance(users, list) and len(users) <= 500, "INVALID_FIXTURE_USERS")
    emails, recorded = set(), set()
    for user in users:
        require(isinstance(user, dict) and isinstance(user.get("email"), str) and EMAIL.fullmatch(user["email"]), "INVALID_OWNED_FIXTURE_EMAIL")
        require(user["email"] not in emails, "DUPLICATE_FIXTURE_EMAIL")
        emails.add(user["email"])
        if "id" in user:
            require(identifier(user["id"]), "INVALID_RECORDED_FIXTURE_ID")
            require(user["id"] not in baseline and user["id"] not in recorded, "RECORDED_FIXTURE_ID_OUTSIDE_OWNERSHIP")
            recorded.add(user["id"])
    return set(baseline), users


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


class Core:
    def __init__(self):
        self.url = os.environ.get("CORE_URL", "http://core-a:3567").rstrip("/")
        parsed = urlsplit(self.url)
        require(parsed.scheme in ("http", "https") and parsed.netloc and parsed.path == "" and
                parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment and
                not re.search(r"[\x00-\x20\x7f]", self.url), "INVALID_CORE_CONFIGURATION")
        self.key = os.environ.get("EXPERTAUTH_CORE_API_KEY")
        require(isinstance(self.key, str) and 0 < len(self.key) <= 4096 and not re.search(r"[\x00-\x1f\x7f]", self.key), "INVALID_CORE_CONFIGURATION")
        self.opener = build_opener(ProxyHandler({}), NoRedirects())

    def request(self, path, body=None):
        request = Request(self.url + path, method="GET" if body is None else "POST",
                          data=None if body is None else json.dumps(body).encode("utf-8"),
                          headers={"api-key": self.key, "cdi-version": "5.4", "content-type": "application/json"})
        try:
            with self.opener.open(request, timeout=10) as response:
                require(response.status == 200, "CORE_HTTP_REQUEST_FAILED")
                raw = response.read(MAX_BYTES + 1)
            require(len(raw) <= MAX_BYTES, "CORE_RESPONSE_TOO_LARGE")
            value = json.loads(raw, object_pairs_hook=unique_object)
            require(isinstance(value, dict) and value.get("status") == "OK", "CORE_RESPONSE_NOT_OK")
            return value
        except CleanupFailure:
            raise
        except Exception:
            raise CleanupFailure("CORE_HTTP_REQUEST_FAILED") from None

    def users(self):
        value = self.request("/users?limit=500")
        require(not value.get("nextPaginationToken"), "CORE_IDENTITY_PAGINATION_NOT_ALLOWED")
        users = value.get("users")
        require(isinstance(users, list) and len(users) <= 500 and all(isinstance(user, dict) and identifier(user.get("id")) for user in users), "INVALID_CORE_IDENTITY_SET")
        require(len({user["id"] for user in users}) == len(users), "DUPLICATE_CORE_IDENTITY_ID")
        for user in users:
            require("emails" not in user or (isinstance(user["emails"], list) and all(isinstance(item, str) for item in user["emails"])), "INVALID_CORE_EMAIL_SET")
            require(user.get("email") is None or isinstance(user["email"], str), "INVALID_CORE_EMAIL_SET")
        return users


def ownership_plan(baseline, fixtures, current):
    by_id = {user["id"]: user for user in current}
    plan, absent = set(), 0
    for fixture in fixtures:
        matches = [user for user in current if fixture["email"] in [user.get("email"), *user.get("emails", [])]]
        require(len(matches) <= 1, "AMBIGUOUS_LIVE_FIXTURE_OWNERSHIP")
        if "id" in fixture and fixture["id"] in by_id:
            require(matches and matches[0]["id"] == fixture["id"], "LIVE_RECORDED_ID_EMAIL_MISMATCH")
        if not matches:
            absent += 1
            continue
        user_id = matches[0]["id"]
        require(user_id not in baseline and ("id" not in fixture or fixture["id"] == user_id), "LIVE_FIXTURE_ID_OUTSIDE_OWNERSHIP")
        require(user_id not in plan, "FIXTURE_EMAILS_SHARE_ONE_IDENTITY")
        plan.add(user_id)
    return sorted(plan), absent


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise CleanupFailure("INVALID_ARGUMENTS")


def main():
    report = {"schema": "expertauth-password-reset-cleanup-followup-v1", "started": timestamp(), "ok": False,
              "foundation_passed": False, "full_PWD_006_qualified": False, "cdi_version": "5.4",
              "ownership_validated_before_mutation": False, "original_identity_set_restored": False,
              "baseline_identity_count": None, "fixture_count": None, "initial_identity_count": None,
              "final_identity_count": None, "planned_delete_count": 0, "already_absent_fixture_count": 0,
              "delete_requests_attempted": 0, "delete_requests_succeeded": 0, "errors": []}
    started = time.monotonic()
    output = None
    core = baseline = None

    def persist():
        if output is not None:
            output.seek(0)
            json.dump(report, output, indent=2)
            output.write("\n")
            output.truncate()
            output.flush()
            os.fsync(output.fileno())

    try:
        parser = Arguments(description=__doc__)
        parser.add_argument("--fixtures", required=True)
        parser.add_argument("--output", required=True)
        args = parser.parse_args()
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        output = path.open("x", encoding="utf-8")  # Never overwrite prior evidence, including failed evidence.
        report["source_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        persist()
        baseline, fixtures = load_fixtures(Path(args.fixtures))
        report.update(baseline_identity_count=len(baseline), fixture_count=len(fixtures))
        core = Core()
        current = core.users()
        report["initial_identity_count"] = len(current)
        plan, absent = ownership_plan(baseline, fixtures, current)
        report.update(ownership_validated_before_mutation=True, planned_delete_count=len(plan), already_absent_fixture_count=absent)
        persist()
        for user_id in plan:
            report["delete_requests_attempted"] += 1
            persist()
            try:
                core.request("/user/remove", {"userId": user_id, "removeAllLinkedAccounts": False})
                report["delete_requests_succeeded"] += 1
            except CleanupFailure:
                report["errors"].append("OWNED_FIXTURE_DELETE_FAILED")
            persist()
    except CleanupFailure as error:
        report["errors"].append(str(error))
    except Exception:
        report["errors"].append("CLEANUP_CONFIGURATION_OR_OPERATION_FAILED")
    finally:
        if core is not None and baseline is not None:
            try:
                after = {user["id"] for user in core.users()}
                report["final_identity_count"] = len(after)
                report["original_identity_set_restored"] = after == baseline
                if after != baseline:
                    report["errors"].append("ORIGINAL_IDENTITY_SET_NOT_RESTORED")
            except Exception:
                report["errors"].append("FINAL_CORE_IDENTITY_VERIFICATION_FAILED")
        report["finished"] = timestamp()
        report["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
        report["ok"] = not report["errors"] and report["ownership_validated_before_mutation"] and report["original_identity_set_restored"]
        try:
            persist()
        except Exception:
            report["ok"] = False
        finally:
            if output is not None:
                try:
                    output.close()
                except Exception:
                    report["ok"] = False
    print(json.dumps({"ok": report["ok"], "cleanup_only": True, "original_identity_set_restored": report["original_identity_set_restored"]}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
