"""Fail-closed release evidence gate. Validates attestations, not reviewer identity or test honesty."""
from __future__ import annotations

import argparse
import collections
import datetime as dt
from pathlib import Path
import json

from ledger import (ROOT, COUNTS, artifact, frozen_records, integrity_errors, object_hash,
                    read_json, safe_path, sha256, source_snapshot)

API_FIELDS = ("method", "path", "recipe", "protocol_version", "request_schema", "response_schema",
              "request_headers", "response_headers_and_cookies", "error_variants", "query_schema",
              "defaults", "missing_versus_null", "claims", "pagination", "side_effects",
              "tenant_scope", "idempotency", "deprecation", "provenance")
QUALIFICATIONS = ("functional", "behavioral", "api_sdk", "security_effectiveness",
                  "operational_independence", "migration_recovery", "vendor_egress_blocked")


def claims_hash(ledger):
    # Exclude only the review reference to avoid a self-referential artifact hash.
    return object_hash({k: v for k, v in ledger.items() if k != "independent_security_review"})


def present(value):
    if isinstance(value, str) and value.strip().lower() in ("todo", "tbd", "pending", "unknown", "unfilled", "not-captured"):
        return False
    return value is not None and value != "" and value != [] and value != {}


def checked_artifact(root, reference):
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
        raise ValueError("Artifact needs path and SHA-256")
    path = safe_path(root, reference["path"])
    if not path.is_file() or sha256(path) != reference["sha256"]:
        raise ValueError(f"Artifact missing or hash changed: {reference['path']}")
    return path


def check_run(root, ref, snapshot, dependencies):
    path = checked_artifact(root, ref)
    run = read_json(path)
    if run.get("schema") != "test-execution-v1":
        raise ValueError("Unknown test execution schema")
    if run.get("profile") not in ("integration", "security", "native", "browser", "migration", "operational"):
        raise ValueError("Integrity/mock/scaffold tests cannot qualify authentication")
    if run.get("exit_code") != 0 or run.get("source_changed_during_run") is not False:
        raise ValueError("Failed run or source changed while tests ran")
    if run.get("source_snapshot") != snapshot or run.get("source_tree_sha256") != object_hash(snapshot):
        raise ValueError("Stale source tree in test evidence")
    if run.get("dependency_hashes") != dependencies or not dependencies:
        raise ValueError("Stale or absent dependency evidence")
    if not run.get("command") or not run.get("runner") or not run.get("environment"):
        raise ValueError("Missing command, runner or environment")
    try:
        start, end = (dt.datetime.fromisoformat(run[key]) for key in ("started_at", "finished_at"))
        if start.tzinfo is None or end.tzinfo is None or end < start or end > dt.datetime.now(dt.timezone.utc):
            raise ValueError("Invalid test execution times")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Missing or invalid test execution times") from exc
    checked_artifact(root, run.get("output"))
    tests = run.get("tests")
    if not isinstance(tests, list) or not tests or run.get("test_count") != len(tests):
        raise ValueError("Missing executed tests or incorrect test count")
    if any(not isinstance(t, dict) or not t.get("id") or t.get("status") != "passed" for t in tests):
        raise ValueError("Skipped, xfail, failed or malformed test evidence")
    ids = [t["id"] for t in tests]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate executed test IDs")
    return run


def check_verified_row(root, group, row, original, snapshot, dependencies, run_cache):
    errors, identifier = [], row["id"]
    implementation = row.get("implementation", [])
    if not implementation:
        errors.append(f"{identifier}: no implementation file hashes")
    for ref in implementation:
        try:
            checked_artifact(root, ref)
            if ref["path"] not in snapshot:
                raise ValueError("Implementation must be release source, not evidence/baseline")
        except (OSError, ValueError, TypeError) as exc:
            errors.append(f"{identifier}: {exc}")
    if not row.get("environment"):
        errors.append(f"{identifier}: no environment/dependency version qualification")
    review = row.get("review", {})
    if not isinstance(review, dict) or review.get("disposition") != "accepted" or not review.get("reviewer"):
        errors.append(f"{identifier}: missing accepted reviewer disposition")
    if row.get("blockers"):
        errors.append(f"{identifier}: verified row retains unresolved blockers")
    ids = set()
    profiles = set()
    if not row.get("runs"):
        errors.append(f"{identifier}: no test-run artifact")
    for ref in row.get("runs", []):
        try:
            key = object_hash(ref)
            if key not in run_cache:
                run_cache[key] = check_run(root, ref, snapshot, dependencies)
            run = run_cache[key]
            ids.update(t["id"] for t in run["tests"])
            profiles.add(run["profile"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"{identifier}: {exc}")
    positive, negative = row.get("positive_test_ids", []), row.get("negative_test_ids", [])
    if not positive or not negative or set(positive) & set(negative):
        errors.append(f"{identifier}: distinct positive and negative tests required")
    if not set(positive + negative).issubset(ids):
        errors.append(f"{identifier}: declared test IDs were not executed successfully")
    # Preserve the original acceptance-ID mapping while using actual runner IDs.
    mappings = row.get("baseline_test_mapping", {})
    for baseline_id in original.get("test_ids", []):
        mapped = mappings.get(baseline_id, [])
        if not mapped or not set(mapped).issubset(ids):
            errors.append(f"{identifier}: missing executed mapping for {baseline_id}")
    if group == "apis":
        contract = row.get("contract", {})
        try:
            ref = row.get("contract_artifact")
            contract_path = checked_artifact(root, ref)
            if ref["path"] not in snapshot or read_json(contract_path) != contract:
                raise ValueError("API contract must match a hashed release source artifact")
        except (OSError, ValueError, TypeError, KeyError) as exc:
            errors.append(f"{identifier}: contract evidence: {exc}")
        for field in API_FIELDS:
            if not present(contract.get(field)):
                errors.append(f"{identifier}: unfilled API contract {field}")
        for field in ("method", "recipe"):
            if contract.get(field) != original[field]:
                errors.append(f"{identifier}: API {field} differs from frozen inventory")
        if original["surface"] == "CDI" and contract.get("exposure") != "private-authenticated":
            errors.append(f"{identifier}: CDI private authenticated boundary unqualified")
        if original["semantic_class"] == "vendor-control-requires-explicit-non-equivalence":
            if row.get("compatibility") != "explicit-non-equivalence" or not row.get("non_equivalence"):
                errors.append(f"{identifier}: vendor control needs explicit non-equivalence")
        elif row.get("compatibility") != "business-compatible":
            errors.append(f"{identifier}: required business API compatibility unqualified")
    if group in ("sdks", "plugins", "integrations"):
        qualification = row.get("qualification", {})
        for field in ("version", "runtime_os", "supported_feature_matrix", "transport_storage", "build_evidence", "restrictions"):
            if not present(qualification.get(field)):
                errors.append(f"{identifier}: missing profile qualification {field}")
        try:
            checked_artifact(root, qualification.get("build_evidence"))
        except (OSError, ValueError, TypeError) as exc:
            errors.append(f"{identifier}: profile build evidence: {exc}")
        if group == "sdks" and original.get("name") in ("iOS", "Android", "React Native") and "native" not in profiles:
            errors.append(f"{identifier}: native platform execution missing")
        if group == "integrations" and not qualification.get("live_provider_status") == "qualified":
            errors.append(f"{identifier}: live integration provider qualification missing")
    return errors


def validate(root: Path, ledger: dict, *, completion=True):
    root = root.resolve()
    errors = integrity_errors(root, ledger)
    if errors:
        return errors
    originals = frozen_records(root)
    snapshot = source_snapshot(root)
    locks = ledger.get("dependency_lock_paths", [])
    dependencies = {}
    try:
        dependencies = {p: sha256(safe_path(root, p)) for p in locks}
        if not dependencies:
            errors.append("Release dependency pins/lockfiles are missing")
    except (OSError, ValueError, TypeError) as exc:
        errors.append(f"Dependency lockfile: {exc}")
    cache = {}
    all_rows = {}
    for group, records in originals.items():
        mapping = {r["id"]: r for r in records}
        for row in ledger[group]:
            all_rows[row["id"]] = row
            if row["status"] != "verified":
                if completion:
                    errors.append(f"{row['id']}: status {row['status']} prevents COMPLETE")
                continue
            errors.extend(check_verified_row(root, group, row, mapping[row["id"]], snapshot, dependencies, cache))
    for row in ledger.get("additional_requirements", []):
        if row["status"] != "verified":
            if completion:
                errors.append(f"{row['id']}: added requirement remains {row['status']}")
        else:
            errors.extend(check_verified_row(root, "additional_requirements", row, row, snapshot, dependencies, cache))
    for group in ("milestones", "work_packages"):
        for original in originals[group]:
            if all_rows[original["id"]]["status"] == "verified":
                for dependency in original.get("depends_on", []):
                    if all_rows[dependency]["status"] != "verified":
                        errors.append(f"{original['id']}: dependency {dependency} unverified")
                if group == "milestones":
                    for contained_group in ("requirements", "work_packages"):
                        for contained in originals[contained_group]:
                            if contained.get("milestone") == original["id"] and all_rows[contained["id"]]["status"] != "verified":
                                errors.append(f"{original['id']}: contained item {contained['id']} unverified")
    if not completion:
        return errors
    for qualification in QUALIFICATIONS:
        ref = ledger.get("qualification_artifacts", {}).get(qualification)
        try:
            report = read_json(checked_artifact(root, ref))
            if report.get("status") != "qualified" or report.get("source_tree_sha256") != object_hash(snapshot):
                raise ValueError("qualification missing, incomplete or stale")
            if report.get("blockers") or not report.get("runs"):
                raise ValueError("qualification has blockers or no executed evidence")
            for run in report["runs"]:
                check_run(root, run, snapshot, dependencies)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"{qualification}: {exc}")
    try:
        review = read_json(checked_artifact(root, ledger.get("independent_security_review")))
        if review.get("reviewer_type") != "human" or review.get("independent") is not True:
            raise ValueError("independent human security review missing")
        reviewer = review.get("reviewer")
        authors = review.get("security_code_authors")
        if not reviewer or not authors or reviewer in authors:
            raise ValueError("reviewer must be independent of security-code authors")
        if review.get("disposition") != "accepted" or review.get("source_tree_sha256") != object_hash(snapshot):
            raise ValueError("review rejected or stale")
        if review.get("ledger_claims_sha256") != claims_hash(ledger):
            raise ValueError("review does not cover current ledger claims and evidence references")
        if not {"code", "configuration", "threat_model", "evidence"}.issubset(review.get("scope", [])):
            raise ValueError("independent review scope incomplete")
        findings = review.get("findings")
        if not isinstance(findings, list):
            raise ValueError("review findings inventory missing")
        if any(f.get("severity") in ("critical", "high") and f.get("status") != "remediated-verified" for f in findings):
            raise ValueError("unresolved critical/high security findings")
        checked_artifact(root, review.get("report"))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"independent_security_review: {exc}")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--claims-only", action="store_true", help="Validate current verified claims; never approve release")
    parser.add_argument("--output", help="Optional JSON report path relative to repository")
    args = parser.parse_args(argv)
    try:
        ledger = read_json(args.root / "ledger/implementation.json")
        errors = validate(args.root, ledger, completion=not args.claims_only)
        report = {"mode": "claims-only" if args.claims_only else "full-release", "counts": COUNTS,
                  "requirement_status_counts": dict(collections.Counter(r["status"] for r in ledger["requirements"])),
                  "passed": not errors, "complete": not args.claims_only and not errors,
                  "errors": errors,
                  "limitation": "Artifact validation cannot establish reviewer identity or detect fabricated tests. Independent review remains mandatory."}
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        report = {"passed": False, "complete": False, "errors": [str(exc)]}
    if args.output:
        from ledger import write_json
        write_json(safe_path(args.root.resolve(), args.output), report)
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
