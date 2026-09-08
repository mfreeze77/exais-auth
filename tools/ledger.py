"""Frozen-baseline traceability and stdlib test recording; never an auth certificate."""
from __future__ import annotations

import argparse
import collections
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "baseline/expert-auth-full-parity-plan-v1.0"
# Trust anchor from the supplied, independently verified package, not an editable ledger.
MANIFEST_SHA256 = "68026295a81a02d1b7598ba5935981169b1b8f455863335bde045745c1a32255"
STATUSES = ("planned", "implemented-unverified", "verified", "failed", "blocked")
COUNTS = {"requirements": 265, "apis": 205, "sdks": 8, "plugins": 14,
          "integrations": 10, "milestones": 11, "work_packages": 36}
REGISTRIES = {"requirements": "requirements", "apis": "api-operations",
              "sdks": "sdk-and-plugins", "plugins": "sdk-and-plugins",
              "integrations": "sdk-and-plugins", "milestones": "milestones",
              "work_packages": "work-packages"}
EXCLUDED = {".git", ".cache", ".runtime", "node_modules", ".venv", "venv", "__pycache__",
            ".pytest_cache", ".mypy_cache", ".ruff_cache"}
ROOT_EXCLUDED = {"baseline", "evidence", "ledger", "dist", ".runtime", "artifacts"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def object_hash(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def safe_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        raise ValueError("A nonempty relative path is required")
    candidate = root / relative
    if any(part == ".." for part in Path(relative).parts):
        raise ValueError(f"Path escapes repository: {relative}")
    # Symlinks are excluded: a changing external target must not enter a release.
    if candidate.is_symlink() or any(p.is_symlink() for p in candidate.parents if p != root.parent):
        raise ValueError(f"Symlink evidence is not accepted: {relative}")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError(f"Path escapes repository: {relative}")
    return resolved


def read_json(path: Path):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON field: {key}")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_pairs)


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def frozen_records(root: Path):
    baseline = safe_path(root, BASELINE)
    manifest_path = baseline / "PACKAGE_MANIFEST.json"
    if sha256(manifest_path) != MANIFEST_SHA256:
        raise ValueError("Frozen package manifest changed")
    manifest = read_json(manifest_path)
    for entry in manifest["files"]:
        path = safe_path(baseline, entry["path"])
        if not path.is_file() or sha256(path) != entry["sha256"]:
            raise ValueError(f"Frozen baseline changed: {entry['path']}")
    groups = {}
    for group, registry in REGISTRIES.items():
        path = baseline / "registry" / f"{registry}.json"
        data = read_json(path)
        if isinstance(data, dict):
            data = data[group]
        if len(data) != COUNTS[group] or len({r["id"] for r in data}) != COUNTS[group]:
            raise ValueError(f"Original {group} coverage changed")
        groups[group] = data
    if collections.Counter(r["surface"] for r in groups["apis"]) != {"FDI": 49, "CDI": 156}:
        raise ValueError("Original FDI/CDI denominator changed")
    if len({r["family"] for r in groups["requirements"]}) != 29:
        raise ValueError("Original requirement families changed")
    if {r["id"] for r in groups["milestones"]} != {f"M{i}" for i in range(11)}:
        raise ValueError("Original M0-M10 milestone IDs changed")
    return groups


def reference(root: Path, group: str, original: dict):
    path = f"{BASELINE}/registry/{REGISTRIES[group]}.json"
    return {"registry": path, "registry_sha256": sha256(root / path),
            "record_sha256": object_hash(original)}


def new_ledger(root: Path):
    originals = frozen_records(root)
    ledger = {"schema_version": 1, "purpose": "implementation-traceability-not-auth-certification",
              "baseline_manifest_sha256": MANIFEST_SHA256, "dependency_lock_paths": [],
              "independent_security_review": None, "qualification_artifacts": {},
              "additional_requirements": []}
    for group, records in originals.items():
        ledger[group] = [{"id": r["id"], "baseline": reference(root, group, r),
                          "status": "planned", "implementation": [],
                          "positive_test_ids": [], "negative_test_ids": [],
                          "runs": [], "environment": {}, "review": {}, "blockers": []}
                         for r in records]
    return ledger


def integrity_errors(root: Path, ledger: dict):
    errors = []
    try:
        originals = frozen_records(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return [f"baseline: {exc}"]
    if ledger.get("schema_version") != 1 or ledger.get("baseline_manifest_sha256") != MANIFEST_SHA256:
        errors.append("Ledger schema or baseline trust anchor changed")
    all_ids = set()
    for group, records in originals.items():
        rows = ledger.get(group)
        if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
            errors.append(f"{group}: expected ledger row list")
            continue
        ids = [r.get("id") for r in rows]
        required_ids = {r["id"] for r in records}
        if len(ids) != len(required_ids) or set(ids) != required_ids:
            errors.append(f"{group}: original IDs missing, duplicated or substituted")
        mapping = {r["id"]: r for r in records}
        for row in rows:
            identifier = row.get("id")
            if identifier not in mapping:
                continue
            all_ids.add(identifier)
            if row.get("baseline") != reference(root, group, mapping[identifier]):
                errors.append(f"{identifier}: original wording/provenance reference changed")
            if row.get("status") not in STATUSES:
                errors.append(f"{identifier}: invalid status")
            for field in ("implementation", "positive_test_ids", "negative_test_ids", "runs", "blockers"):
                if not isinstance(row.get(field), list):
                    errors.append(f"{identifier}: {field} must be a list")
            if row.get("status") in ("failed", "blocked") and not row.get("blockers"):
                errors.append(f"{identifier}: failed/blocked state requires concrete blockers")
    additions = ledger.get("additional_requirements", [])
    if not isinstance(additions, list):
        errors.append("additional_requirements must be a list")
    else:
        for row in additions:
            if not isinstance(row, dict) or not row.get("id") or row["id"] in all_ids:
                errors.append("Additional requirement lacks a unique non-baseline ID")
            else:
                all_ids.add(row["id"])
                if not row.get("acceptance") or not row.get("source_provenance") or row.get("status") not in STATUSES:
                    errors.append(f"{row['id']}: additional requirement lacks acceptance/provenance/status")
    return errors


def source_snapshot(root: Path):
    files = {}
    for current, directories, names in os.walk(root):
        current = Path(current)
        directories[:] = sorted(d for d in directories if d not in EXCLUDED
                                 and not (current == root and d in ROOT_EXCLUDED))
        for directory in directories:
            safe_path(root, (current / directory).relative_to(root).as_posix())
        for name in sorted(names):
            if name.endswith((".pyc", ".pyo")):
                continue
            if (name == '.env' or name.startswith('.env.')) and name != '.env.example':
                continue
            path = current / name
            relative = path.relative_to(root).as_posix()
            safe_path(root, relative)
            files[relative] = sha256(path)
    return files


def artifact(root: Path, path: Path):
    return {"path": path.resolve().relative_to(root.resolve()).as_posix(), "sha256": sha256(path)}


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []

    def record(self, test, status):
        self.records.append({"id": test.id(), "status": status})

    def addSuccess(self, test):
        super().addSuccess(test)
        self.record(test, "passed")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.record(test, "failed")

    def addError(self, test, err):
        super().addError(test, err)
        self.record(test, "error")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.record(test, "skipped")

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.record(test, "expected-failure")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.record(test, "unexpected-success")

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.record(subtest, "failed")


def record_tests(root: Path, discover: str, output: str, profile="integrity", dependency_paths=()):
    """Execute real unittest cases, persisting exact outcomes and source/dependency hashes."""
    root = root.resolve()
    output_path = safe_path(root, output)
    if output_path.exists():
        raise ValueError("Evidence is append-only; use a new output name")
    before = source_snapshot(root)
    dependencies = {p: sha256(safe_path(root, p)) for p in dependency_paths}
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    stream = io.StringIO()
    previous_cwd = Path.cwd()
    try:
        os.chdir(root)
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            suite = unittest.TestLoader().discover(str(safe_path(root, discover)))
            result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=RecordingResult).run(suite)
    finally:
        os.chdir(previous_cwd)
    changed = before != source_snapshot(root)
    passed = result.testsRun > 0 and result.wasSuccessful() and not changed and all(
        r["status"] == "passed" for r in result.records)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    log_path = output_path.with_suffix(".log")
    if log_path.exists():
        raise ValueError("Evidence log already exists; use a new output name")
    log_path.write_text(stream.getvalue(), encoding="utf-8")
    report = {"schema": "test-execution-v1", "runner": "stdlib-unittest", "profile": profile,
              "command": [sys.executable, "tools/ledger.py", "run-tests", "--discover", discover,
                          "--output", output, "--profile", profile] +
                         [arg for p in dependency_paths for arg in ("--dependency-lock", p)],
              "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "exit_code": 0 if passed else 1, "source_snapshot": before,
              "source_tree_sha256": object_hash(before), "source_changed_during_run": changed,
              "dependency_hashes": dependencies,
              "environment": {"python": platform.python_version(), "platform": platform.platform(),
                              "executable": sys.executable},
              "test_count": result.testsRun, "tests": result.records,
              "output": artifact(root, log_path)}
    write_json(output_path, report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    sub.add_parser("check")
    run = sub.add_parser("run-tests")
    run.add_argument("--discover", required=True)
    run.add_argument("--output", required=True)
    run.add_argument("--profile", choices=("integrity", "integration", "security", "native", "browser", "migration", "operational"), default="integrity")
    run.add_argument("--dependency-lock", action="append", default=[])
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        path = root / "ledger/implementation.json"
        if args.command == "init":
            if path.exists():
                raise ValueError("Refusing to overwrite existing implementation ledger")
            write_json(path, new_ledger(root))
            print(json.dumps({"created": str(path), "counts": COUNTS, "authentication_completion": False}))
            return 0
        if args.command == "run-tests":
            report = record_tests(root, args.discover, args.output, args.profile, args.dependency_lock)
            print(json.dumps({"output": args.output, "tests": report["test_count"], "exit_code": report["exit_code"]}))
            return report["exit_code"]
        ledger = read_json(path)
        errors = integrity_errors(root, ledger)
        print(json.dumps({"integrity_passed": not errors, "authentication_completion": False,
                          "counts": COUNTS, "requirement_status_counts": dict(collections.Counter(
                              r["status"] for r in ledger["requirements"])), "errors": errors}, indent=2))
        return 1 if errors else 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"error": str(exc), "authentication_completion": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
