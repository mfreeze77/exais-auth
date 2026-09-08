#!/usr/bin/env python3
"""Validate planning inventory integrity, not authentication implementation/security.

Run from any working directory. Uses only the Python standard library.
All planned test IDs in this package are specifications, not executable auth tests.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import sys
from typing import Any


def load(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    root = args.root.resolve()
    errors: list[str] = []

    def check(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    def unique(rows: list[dict[str, Any]], label: str, field: str = "id") -> set[str]:
        ids = [row[field] for row in rows]
        check(len(ids) == len(set(ids)), f"Duplicate {label} {field}")
        return set(ids)

    def dag(rows: list[dict[str, Any]], label: str) -> None:
        mapping = {r["id"]: r["depends_on"] for r in rows}
        seen: set[str] = set()
        active: set[str] = set()

        def visit(node: str) -> None:
            if node in active:
                errors.append(f"Cycle in {label} involving {node}")
                return
            if node in seen:
                return
            active.add(node)
            for dep in mapping.get(node, []):
                if dep not in mapping:
                    errors.append(f"Unknown {label} dependency {dep} in {node}")
                else:
                    visit(dep)
            active.remove(node)
            seen.add(node)

        for key in mapping:
            visit(key)

    try:
        reqs = load(root / "registry/requirements.json")
        fams = load(root / "registry/families.json")
        sources = load(root / "registry/sources.json")
        milestones = load(root / "registry/milestones.json")
        work = load(root / "registry/work-packages.json")
        ops = load(root / "registry/api-operations.json")
        profiles = load(root / "registry/sdk-and-plugins.json")
        lock = load(root / "registry/baseline-lock.template.json")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Cannot read planning inventory: {exc}", file=sys.stderr)
        return 2

    source_ids = unique(sources, "source")
    family_ids = unique(fams, "family", "code")
    milestone_ids = unique(milestones, "milestone")
    unique(reqs, "requirement")
    unique(work, "work package")
    unique(ops, "operation")
    dag(milestones, "milestone")
    dag(work, "work package")
    counts = Counter(r["family"] for r in reqs)
    tests: list[str] = []
    for r in reqs:
        check(r["family"] in family_ids, f"Unknown family: {r['id']}")
        check(r["milestone"] in milestone_ids, f"Unknown milestone: {r['id']}")
        check(r["required"] is True, f"Scope reduction: {r['id']} is not required")
        check(bool(r["acceptance"].strip()), f"Missing acceptance: {r['id']}")
        check(bool(r["test_ids"]), f"Missing planned tests: {r['id']}")
        check(set(r["source_ids"]) <= source_ids, f"Unknown source: {r['id']}")
        if r["status"] == "verified":
            check(bool(r["implementation_paths"]) and bool(r["evidence"]),
                  f"Unsupported implementation claim: {r['id']}")
        tests.extend(r["test_ids"])
    for f in fams:
        check(counts[f["code"]] == f["requirement_count"], f"Family count mismatch: {f['code']}")
    assigned = [f for m in milestones for f in m["families"]]
    check(Counter(assigned) == Counter({f: 1 for f in family_ids}), "Each family must have exactly one closing milestone")
    for w in work:
        check(w["milestone"] in milestone_ids, f"Unknown work milestone: {w['id']}")
        check(bool(w["deliverables"]) and bool(w["exit_gate"]), f"Missing work output/gate: {w['id']}")
    for o in ops:
        check(o["source_id"] in source_ids, f"Unknown operation source: {o['id']}")
        check(o["method"] in {"GET", "POST", "PUT", "DELETE", "PATCH"}, f"Invalid method: {o['id']}")
        if o["capture_status"] == "method-and-operation-name-only":
            check(o["path"] is None and o["request_schema"] is None and o["response_schema"] is None,
                  f"Unverified contract fields in {o['id']}")
        if o["implementation_status"] == "verified":
            check(bool(o["evidence"]) and o["path"] is not None, f"Unsupported API claim: {o['id']}")
        tests.extend(o["test_ids"])
    check(len(tests) == len(set(tests)), "Duplicate planned test identifiers")
    surface_counts = dict(Counter(o["surface"] for o in ops))
    check(surface_counts == {"FDI": 49, "CDI": 156}, "API baseline counts differ")
    check(len(reqs) == 265 and len(fams) == 29, "Requirement baseline counts differ")
    check(len(work) == 36 and len(milestones) == 11, "Backlog baseline counts differ")
    check(len(profiles["sdks"]) == 8 and len(profiles["plugins"]) == 14, "SDK/plugin baseline counts differ")
    check(len(profiles["integrations"]) == 10, "Integration baseline count differs")
    check(lock["state"] == "unfrozen-template-not-a-build-lock", "Version template misrepresented")
    check(lock["selected_engine"] is None, "Engine selection requires actual feasibility evidence")
    report = {
        "validation_scope": "planning-inventory-integrity-only",
        "result": "passed" if not errors else "failed",
        "baseline_date": "2026-09-08",
        "counts": {"required_requirements": len(reqs), "families": len(fams),
                   "milestones": len(milestones), "work_packages": len(work),
                   "api_operations": len(ops), "api_by_surface": surface_counts,
                   "sdk_profiles": len(profiles["sdks"]), "plugin_packages": len(profiles["plugins"]),
                   "integration_profiles": len(profiles["integrations"]),
                   "planned_acceptance_and_contract_test_ids": len(tests),
                   "verified_implementation_requirements": sum(r["status"] == "verified" for r in reqs),
                   "schema_complete_operations": sum(o["path"] is not None and o["request_schema"] is not None and o["response_schema"] is not None for o in ops)},
        "errors": errors,
        "limitations": ["No authentication implementation is supplied or tested.",
                        "No source build or immutable baseline pin has been validated.",
                        "API paths and schemas remain capture tasks; names and methods alone are not an OpenAPI contract.",
                        "Test IDs describe planned checks, not executable authentication tests."]
    }
    output = args.output or root / "validation-report.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
