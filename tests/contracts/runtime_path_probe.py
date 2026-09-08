"""Resolve exactly four frozen path artifacts from licensed source and live I/O.

No unlicensed OpenAPI is fetched/copied, and the original capture is never edited.
Run --capture in a network-enabled Linux container, then --run on the Docker host.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import pathlib
import secrets
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "evidence/contracts/runtime-paths"
TARGETS = ("FDI-026", "CDI-099", "CDI-104", "CDI-116")
PINS = {"core": "b2219c4aa019a501e4dfea76cf06ef802ca93fc0", "node": "9b82aefb46da4c0f0a388d8f6656c39a62d7642c"}
NODE_IMAGE = "expertauth-node-react:0.0.5"
CLIENT_IMAGE = "expertauth-python-app:0.1.0"
NETWORK = "expertauth-oss-proof"
CONTAINER = "expertauth-runtime-path-node"
SOURCE_PATHS = {
    "core": ["LICENSE.md", "src/main/java/io/supertokens/webserver/Webserver.java", "src/main/java/io/supertokens/webserver/RecipeRouter.java", "src/main/java/io/supertokens/webserver/WebserverAPI.java", "src/main/java/io/supertokens/webserver/api/passwordless/UserAPI.java", "src/main/java/io/supertokens/webserver/api/passwordless/CreateCodeAPI.java", "src/main/java/io/supertokens/webserver/api/passwordless/ConsumeCodeAPI.java", "src/main/java/io/supertokens/webserver/api/thirdparty/UserAPI.java", "src/main/java/io/supertokens/webserver/api/thirdparty/SignInUpAPI.java"],
    "node": ["LICENSE.md", "package.json", "lib/ts/recipe/passwordless/recipe.ts", "lib/ts/recipe/passwordless/constants.ts", "lib/ts/recipe/passwordless/api/emailExists.ts", "lib/ts/recipe/passwordless/api/implementation.ts", "lib/ts/recipe/passwordless/recipeImplementation.ts", "lib/ts/recipeModule.ts", "lib/ts/normalisedURLPath.ts", "lib/build/recipe/passwordless/recipe.js", "lib/build/recipe/passwordless/constants.js", "lib/build/recipe/passwordless/api/emailExists.js"],
}
NODE_APP = '''import express from '/app/node_modules/express/index.js';
import supertokens from '/app/node_modules/supertokens-node/lib/build/index.js';
import Passwordless from '/app/node_modules/supertokens-node/recipe/passwordless/index.js';
import Session from '/app/node_modules/supertokens-node/recipe/session/index.js';
import framework from '/app/node_modules/supertokens-node/framework/express/index.js';
const apiKey = process.env.EXPERTAUTH_CORE_API_KEY;
if (!apiKey) throw new Error('Private Core API key required');
supertokens.init({ framework: 'express', telemetry: false,
 supertokens: { connectionURI: 'http://core-a:3567', apiKey },
 appInfo: { appName: 'ExpertAuth four-path probe', apiDomain: 'http://runtime-path.example.test:3002', websiteDomain: 'http://runtime-path.example.test:3002', apiBasePath: '/auth' },
 recipeList: [Passwordless.init({ contactMethod: 'EMAIL', flowType: 'USER_INPUT_CODE',
   emailDelivery: { service: { async sendEmail() { throw new Error('Delivery disabled in path probe'); } } }
 }), Session.init({cookieSecure: false})]
});
const app=express();
app.use((req,res,next)=>req.method==='GET'?next():res.status(405).json({error:'READ_ONLY_FDI_PATH_PROBE'}));
app.get('/health',(_req,res)=>res.json({status:'OK'}));
app.use(framework.middleware());
app.use(framework.errorHandler());
app.use((_req,res)=>res.status(404).json({error:'ROUTE_NOT_FOUND'}));
app.use((_err,_req,res,_next)=>res.status(500).json({error:'SDK_ERROR'}));
app.listen(3002,'0.0.0.0',()=>process.stdout.write('Four-path SDK probe ready\\n'));
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def manifest(kind):
    return json.loads((ROOT / f"reuse/files/supertokens__supertokens-{kind}__{PINS[kind]}.json").read_text(encoding="utf-8"))


def capture():
    records = []
    for kind, paths in SOURCE_PATHS.items():
        audit = {row["source_path"]: row for row in manifest(kind)["files"]}
        for path in paths:
            item = audit[path]
            if item["license"] != "Apache-2.0" or "ee" in pathlib.PurePosixPath(path).parts:
                raise RuntimeError("Source outside audited Apache boundary")
            url = f"https://raw.githubusercontent.com/supertokens/supertokens-{kind}/{PINS[kind]}/{path}"
            raw = urllib.request.urlopen(url, timeout=30).read()
            if hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise RuntimeError("Pinned source differs from immutable reuse audit")
            destination = OUT / "source" / kind / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
            records.append({"repository": f"supertokens/supertokens-{kind}", "commit": PINS[kind], "source_path": path, "url": url, "sha256": item["sha256"], "license": "Apache-2.0", "retained_path": destination.relative_to(ROOT).as_posix(), "modifications": [], "purpose": "Read-only route/dispatch/schema facts or synthetic fixture setup; no new engine implementation"})
    write(OUT / "source-report.json", {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "exit_code": 0, "source_count": len(records), "files": records, "unlicensed_openapi_copied": False, "input_sha256": {str(pathlib.Path(__file__).relative_to(ROOT)): sha(pathlib.Path(__file__))}})
    print(f"Verified and retained {len(records)} selected Apache-licensed source files")


def command(args, check=True):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(f"Command failed: {args[0]} {args[1]}; inspect owned probe logs")
    return result


def run():
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "node-path-app.mjs").write_text(NODE_APP, encoding="utf-8")
    existing = command(["docker", "inspect", CONTAINER], check=False)
    if existing.returncode == 0:
        item = json.loads(existing.stdout)[0]
        if item["Config"].get("Labels", {}).get("org.expertauth.lab") != "runtime-paths":
            raise RuntimeError("Refusing to replace an unowned container")
        command(["docker", "rm", "-f", CONTAINER])
    args = ["docker", "run", "-d", "--name", CONTAINER, "--label", "org.expertauth.lab=runtime-paths", "--network", NETWORK, "--network-alias", "runtime-path.example.test", "--env-file", str(ROOT / ".runtime/oss-core/runtime.env"), "--mount", f"type=bind,source={OUT / 'node-path-app.mjs'},target=/work/node-path-app.mjs,readonly", "--entrypoint", "node", NODE_IMAGE, "/work/node-path-app.mjs"]
    command(args)
    inspect_names = (CONTAINER, "expertauth-oss-core-a")
    runtime = []
    for name in inspect_names:
        value = json.loads(command(["docker", "inspect", name]).stdout)[0]
        runtime.append({"container": name, "container_id": value["Id"], "image_id": value["Image"], "published_ports": value["HostConfig"]["PortBindings"]})
    installed = command(["docker", "exec", CONTAINER, "node", "-e", "const fs=require('fs'),crypto=require('crypto'); const base='/app/node_modules/supertokens-node/'; const paths=['lib/build/recipe/passwordless/recipe.js','lib/build/recipe/passwordless/constants.js','lib/build/recipe/passwordless/api/emailExists.js']; process.stdout.write(JSON.stringify({version:require(base+'package.json').version,files:Object.fromEntries(paths.map(p=>[p,crypto.createHash('sha256').update(fs.readFileSync(base+p)).digest('hex')]))}));"])
    sdk = json.loads(installed.stdout)
    expected = {item["source_path"]: item["sha256"] for item in manifest("node")["files"]}
    if sdk["version"] != "24.0.3" or not all(expected[path] == digest for path, digest in sdk["files"].items()):
        raise RuntimeError("Installed route implementation differs from audited SDK")
    write(OUT / "runtime-report.json", {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "exit_code": 0, "containers": runtime, "sdk_runtime": sdk, "sdk_files_match_pinned_source": True, "node_app_sha256": sha(OUT / "node-path-app.mjs"), "candidate_selected": False})
    # Source evidence was created by the root-owned capture container. This
    # short-lived test writer uses that UID only to persist public artifacts;
    # the actual SDK server continues to run as the image's non-root user.
    args = ["docker", "run", "--rm", "--user", "0:0", "--network", NETWORK, "--env-file", str(ROOT / ".runtime/oss-core/runtime.env"), "--mount", f"type=bind,source={ROOT},target=/work,readonly", "--mount", f"type=bind,source={OUT},target=/work/evidence/contracts/runtime-paths", "--mount", f"type=bind,source={ROOT / 'contracts'},target=/work/contracts", "-w", "/work", CLIENT_IMAGE, "python", "tests/contracts/runtime_path_probe.py", "--probe"]
    result = command(args, check=False)
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    write(OUT / "command-report.json", {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "command_argv": args, "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
    return result.returncode


def probe():
    import httpx
    client = httpx.Client(timeout=15, trust_env=False)
    sdk = "http://runtime-path.example.test:3002"
    for _ in range(20):
        try:
            if client.get(sdk + "/health").status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.5)
    else:
        raise RuntimeError("Owned SDK path probe did not become ready")
    original_paths = [ROOT / "contracts/api-contracts.json", ROOT / "contracts/operation-map.json", ROOT / "baseline-lock.json"]
    original_hashes = {path.relative_to(ROOT).as_posix(): sha(path) for path in original_paths}
    captured = json.loads(original_paths[0].read_text(encoding="utf-8"))
    original = {row["id"]: row for row in captured["operations"] if row["id"] in TARGETS}
    require(set(original) == set(TARGETS), "Original IDs missing from capture")
    evidence = []
    nonce = secrets.token_hex(9)
    email = f"runtime-path-{nonce}@example.invalid"
    new_email = f"runtime-path-updated-{nonce}@example.invalid"
    core = "http://core-a:3567"
    path = "/appid-public/public/recipe/user"
    key = os.environ["EXPERTAUTH_CORE_API_KEY"]

    def request(method, endpoint, rid, version="5.3", params=None, body=None, auth=True):
        headers = {"rid": rid, "cdi-version": version}
        if auth:
            headers["api-key"] = key
        return client.request(method, core + endpoint, headers=headers, params=params, json=body)

    def summary(response):
        try:
            body = response.json()
        except ValueError:
            body = None
        return {"http_status": response.status_code, "content_type": response.headers.get("content-type"), "application_status": body.get("status") if isinstance(body, dict) else None, "top_level_fields": sorted(body) if isinstance(body, dict) else [], "raw_path_ascii": response.request.url.raw_path.decode("ascii"), "set_cookie_count": len(response.headers.get_list("set-cookie"))}

    def check(ident, name, fn):
        details = {}
        try:
            fn(details)
            state, error = "passed", None
        except Exception as exc:
            state = "failed"
            error = str(exc) if isinstance(exc, AssertionError) else type(exc).__name__
        result = {"original_id": ident, "test": name, "status": state, "details": details}
        if error:
            result["error"] = error
        evidence.append(result)
        print(ident + " " + name + ": " + state, flush=True)

    # Internal Core fixture creation consumes a generated code directly. No
    # delivery/provider service is configured or contacted; this is not proof
    # of external email/SMS/OAuth delivery or provider authentication.
    created = request("POST", "/appid-public/public/recipe/signinup/code", "passwordless", body={"email": email})
    require(created.status_code == 200 and created.json().get("status") == "OK", "Passwordless fixture code creation failed")
    code = created.json()
    consumed = request("POST", "/appid-public/public/recipe/signinup/code/consume", "passwordless", body={"preAuthSessionId": code["preAuthSessionId"], "deviceId": code["deviceId"], "userInputCode": code["userInputCode"]})
    require(consumed.status_code == 200 and consumed.json().get("status") == "OK", "Synthetic passwordless fixture consumption failed")
    fixture = consumed.json()
    uid = fixture["user"]["id"]
    recipe_uid = fixture["recipeUserId"]
    provider = "runtime-path-fixture"
    provider_subject = "synthetic-" + nonce
    third = request("POST", "/appid-public/public/recipe/signinup", "thirdparty", body={"thirdPartyId": provider, "thirdPartyUserId": provider_subject, "email": {"id": f"runtime-third-{nonce}@example.invalid", "isVerified": False}})
    require(third.status_code == 200 and third.json().get("status") == "OK", "Synthetic third-party record creation failed")
    third_uid = third.json()["user"]["id"]

    def fdi(details):
        results = []
        for endpoint in ("/auth/public/signup/email/exists", "/auth/signup/email/exists"):
            found = client.get(sdk + endpoint, params={"email": email}, headers={"rid": "passwordless", "fdi-version": "4.2"})
            absent = client.get(sdk + endpoint, params={"email": "absent-" + email}, headers={"rid": "passwordless", "fdi-version": "4.2"})
            results += [summary(found), summary(absent)]
            require(found.status_code == 200 and found.json() == {"status": "OK", "exists": True}, "Deprecated FDI existing email route failed")
            require(absent.status_code == 200 and absent.json() == {"status": "OK", "exists": False}, "Deprecated FDI absent email route failed")
        missing = client.get(sdk + "/auth/public/signup/email/exists", headers={"rid": "passwordless", "fdi-version": "4.2"})
        require(missing.status_code == 400, "Missing required email was accepted")
        details.update(requests=results, missing_email_http=missing.status_code, deprecated_route_supported=True)
    check("FDI-026", "deprecated-fdi-existing-absent-required-query", fdi)

    def read_pwless(details):
        results = []
        for params in ({"userId": uid}, {"email": email}):
            response = request("GET", path, "passwordless", params=params)
            results.append(summary(response))
            require(response.status_code == 200 and response.json()["status"] == "OK" and response.json()["user"]["id"] == uid, "Passwordless read returned wrong identity")
        missing = request("GET", path, "passwordless", params={"email": "absent-" + email})
        invalid = request("GET", path, "passwordless", params={"userId": uid, "email": email})
        require(missing.json().get("status") == "UNKNOWN_EMAIL_ERROR" and invalid.status_code == 400, "Passwordless query selector contract differs")
        details.update(requests=results, absent_email_status=missing.json()["status"], ambiguous_selector_http=invalid.status_code)
    check("CDI-099", "deprecated-passwordless-read-by-id-and-email", read_pwless)

    def update(details):
        missing = request("PUT", path, "passwordless", body={"userId": recipe_uid, "email": new_email})
        response = request("PUT", path, "passwordless", body={"recipeUserId": recipe_uid, "email": new_email})
        require(missing.status_code == 400, "CDI 5.3 accepted legacy userId in place of recipeUserId")
        require(response.status_code == 200 and response.json() == {"status": "OK"}, "Passwordless contact update failed")
        reread = request("GET", path, "passwordless", params={"email": new_email})
        old = request("GET", path, "passwordless", params={"email": email})
        require(reread.json().get("status") == "OK" and reread.json()["user"]["id"] == uid and old.json().get("status") == "UNKNOWN_EMAIL_ERROR", "Persisted contact change failed")
        clear = request("PUT", path, "passwordless", body={"recipeUserId": recipe_uid, "email": None})
        require(clear.status_code == 400, "Clearing sole contact was accepted")
        details.update(update=summary(response), legacy_identifier_http=missing.status_code, persisted_reread=True, old_contact_no_longer_matches=True, clearing_sole_contact_http=clear.status_code, source_schema_delta="CDI >=4.0 requires recipeUserId; published 5.3 required userId conflicts with property/source")
    check("CDI-104", "passwordless-update-persisted-and-negative-fields", update)

    def read_third(details):
        results = []
        for params in ({"userId": third_uid}, {"thirdPartyId": provider, "thirdPartyUserId": provider_subject}):
            response = request("GET", path, "thirdparty", params=params)
            results.append(summary(response))
            require(response.status_code == 200 and response.json()["status"] == "OK" and response.json()["user"]["id"] == third_uid, "Third-party record lookup failed")
        absent = request("GET", path, "thirdparty", params={"thirdPartyId": provider, "thirdPartyUserId": "missing-" + nonce})
        invalid = request("GET", path, "thirdparty", params={"thirdPartyId": provider})
        require(absent.json().get("status") == "UNKNOWN_THIRD_PARTY_USER_ERROR" and invalid.status_code == 400, "Third-party selector contract differs")
        details.update(requests=results, absent_pair_status=absent.json()["status"], incomplete_pair_http=invalid.status_code, live_provider_authentication_qualified=False)
    check("CDI-116", "deprecated-thirdparty-read-by-id-and-provider-pair", read_third)

    for ident in TARGETS:
        def literal(details, ident=ident):
            variant = original[ident]["variants"][0]
            published = variant["path_as_published"]
            if ident == "FDI-026":
                actual = published.replace("/{apiBasePath}", "/auth").replace("<tenantId>", "public")
                response = client.get(sdk + actual, params={"email": new_email}, headers={"rid": "passwordless", "fdi-version": "4.2"})
            else:
                actual = published.replace("<appId>", "public").replace("<tenantId>", "public")
                response = request(variant["method"], actual, "thirdparty" if ident == "CDI-116" else "passwordless", params={"userId": third_uid if ident == "CDI-116" else uid} if variant["method"] == "GET" else None, body={"recipeUserId": recipe_uid, "email": new_email} if variant["method"] == "PUT" else None)
            details.update(response=summary(response), literal_unicode_escape=actual.encode("unicode_escape").decode("ascii"), suffix_codepoints=[f"U+{ord(ch):04X}" for ch in actual if ord(ch) > 127])
            require(response.status_code == 404, "Published Unicode suffix unexpectedly routes; do not assume it is a presentation artifact")
        check(ident, "literal-published-unicode-path-not-a-wire-route", literal)

    def protocol(details):
        unauthorized = request("GET", path, "passwordless", params={"userId": uid}, auth=False)
        unsupported = request("GET", path, "passwordless", version="99.0", params={"userId": uid})
        require(unauthorized.status_code == 401 and unsupported.status_code == 400, "Core key/version boundary differs")
        details.update(missing_api_key_http=unauthorized.status_code, unsupported_cdi_http=unsupported.status_code, api_key_header="api-key", cdi_version="5.3")
    check("CDI-099", "core-authentication-and-version-boundary", protocol)

    for rel, digest in original_hashes.items():
        require(sha(ROOT / rel) == digest, "Immutable capture/baseline changed during probe")
    failed = sum(event["status"] == "failed" for event in evidence)
    report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "command": "python tests/contracts/runtime_path_probe.py --run", "original_ids": list(TARGETS), "expected_checks": 9, "executed": len(evidence), "passed": len(evidence) - failed, "failed": failed, "skipped": 0, "exit_code": int(bool(failed) or len(evidence) != 9), "tests": evidence, "fixture": {"passwordless": "Real Core-generated code consumed internally, synthetic contact updated and read back", "thirdparty": "Trusted internal Core synthetic identity record only; no live OAuth/provider authentication claim", "external_delivery_calls": 0}, "candidate_selected": False, "complete_api_contracts": False, "original_input_sha256": original_hashes, "input_sha256": {path.relative_to(ROOT).as_posix(): sha(path) for path in (pathlib.Path(__file__), OUT / "source-report.json", OUT / "runtime-report.json", OUT / "node-path-app.mjs")}}
    write(OUT / "probe-report.json", report)
    write_resolutions(original, report)
    print(json.dumps({key: report[key] for key in ("executed", "passed", "failed", "exit_code")}))
    return report["exit_code"]


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def write_resolutions(original, report):
    rows = []
    for ident in TARGETS:
        fdi = ident == "FDI-026"
        row_tests = [item for item in report["tests"] if item["original_id"] == ident]
        rows.append({"id": ident, "original_capture_unchanged": True, "original_path_unicode_escape": original[ident]["variants"][0]["path_unicode_escape"], "original_capture_source": original[ident]["source_id"], "method": original[ident]["baseline"]["method"], "rid": "thirdparty" if ident == "CDI-116" else "passwordless", "version_header": "fdi-version" if fdi else "cdi-version", "tested_version_header_value": "4.2" if fdi else "5.3", "runtime_path_template": "/{apiBasePath}/<tenantId>/signup/email/exists" if fdi else "/appid-<appId>/<tenantId>/recipe/user", "tested_wire_paths": ["/auth/public/signup/email/exists", "/auth/signup/email/exists"] if fdi else ["/appid-public/public/recipe/user"], "path_derivation": "Independently read exact ASCII route constants/getPath implementations and recipe dispatch in pinned Apache sources, then tested both implementation route and unaltered published Unicode path", "deprecated_in_baseline": original[ident]["baseline"]["deprecated"], "deprecated_route_runtime_support": "supported-at-tested-pin" if not any(item["status"] == "failed" for item in row_tests) else "blocked-or-failed-see-evidence", "path_resolution_status": "resolved-source-and-runtime" if not any(item["status"] == "failed" for item in row_tests) else "blocked-runtime-evidence", "tested_scope": "default app/public tenant only", "behavioral_evidence": "evidence/contracts/runtime-paths/probe-report.json", "source_evidence": "evidence/contracts/runtime-paths/source-report.json", "full_schema_redistribution": "unresolved-original-OpenAPI; only independent licensed-source facts added", "full_operation_qualification": False, "unknowns": ["all non-public app/tenant enforcement cases", "full legacy version matrix", "exhaustive schema/errors and all SDK/profile behavior"]})
    rows[0]["minimal_source_schema_facts"] = {"query": {"email": "required string"}, "success": {"status": "OK", "exists": "boolean"}, "missing_email_http": 400, "mutates_identity": False}
    rows[1]["minimal_source_schema_facts"] = {"selectors": "Exactly one of userId, email, phoneNumber", "lookup_scope": "userId app-specific/public tenant; email or phone tenant-specific", "success_status": "OK", "unknown_statuses": ["UNKNOWN_USER_ID_ERROR", "UNKNOWN_EMAIL_ERROR", "UNKNOWN_PHONE_NUMBER_ERROR"]}
    rows[2]["minimal_source_schema_facts"] = {"required_identifier": {"CDI_below_4.0": "userId", "CDI_4.0_and_later": "recipeUserId"}, "optional_updates": {"email": "omitted leaves unchanged; string replaces; null requests removal", "phoneNumber": "omitted leaves unchanged; string replaces; null requests removal"}, "sole_contact_removal": "HTTP 400", "scope": "app-specific/public tenant", "success_status": "OK", "published_schema_conflict": "CDI 5.3 source capture declares required userId while defining recipeUserId; live/pinned implementation requires recipeUserId"}
    rows[3]["minimal_source_schema_facts"] = {"selectors": "Either userId or both thirdPartyId and thirdPartyUserId; not both forms", "success_status": "OK", "unknown_statuses": ["UNKNOWN_USER_ID_ERROR", "UNKNOWN_THIRD_PARTY_USER_ERROR"], "lookup_scope": "userId app-specific/public tenant; provider pair tenant-specific"}
    for row in rows[1:]:
        row["rid_dispatch_fact"] = "RecipeRouter selects exact rid; missing/unmatched rid falls back to the first registered emailpassword handler, so it must not be relied on to select this operation"
    write(ROOT / "contracts/runtime-path-resolutions.json", {"format_version": "1.0", "purpose": "Supplement to immutable capture for exactly four original IDs; no original schema replacement", "candidate_selected": False, "complete": False, "original_capture_sha256": sha(ROOT / "contracts/api-contracts.json"), "source_pins": PINS, "resolution_count": len(rows), "operations": rows, "probe_exit_code": report["exit_code"]})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--capture", action="store_true")
    modes.add_argument("--run", action="store_true")
    modes.add_argument("--probe", action="store_true")
    args = parser.parse_args()
    if args.capture:
        capture()
    else:
        raise SystemExit(run() if args.run else probe())
