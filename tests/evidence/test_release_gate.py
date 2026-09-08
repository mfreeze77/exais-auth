"""Adversarial tests of the evidence gate, not tests of authentication behavior."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import uuid

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "tools"))
import ledger as ledger_tool
import validate_release as gate


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="expert-auth-gate-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(PROJECT / "baseline", self.root / "baseline")
        (self.root / "src").mkdir()
        (self.root / "src/behavior.py").write_text("def operation(value):\n    return value > 0\n", encoding="utf-8")
        (self.root / "deps.lock").write_text('{"python":"3.13","dependencies":[]}', encoding="utf-8")
        self.ledger = ledger_tool.new_ledger(self.root)
        self.ledger["dependency_lock_paths"] = ["deps.lock"]

    def execute_fixture(self, profile="integration", skipped=False):
        # Synthetic fixture validates the gate mechanics only. It is never shipped as auth evidence.
        tests = self.root / "tests"
        tests.mkdir(exist_ok=True)
        module = f"test_synthetic_{uuid.uuid4().hex}"
        skip = "    @unittest.skip('injected missing platform')\n" if skipped else ""
        (tests / f"{module}.py").write_text(
            "import unittest\nclass EvidenceFixture(unittest.TestCase):\n"
            "    def test_positive(self):\n        self.assertGreater(2, 1)\n" + skip +
            "    def test_negative(self):\n        self.assertFalse(0 > 1)\n", encoding="utf-8")
        report = ledger_tool.record_tests(self.root, "tests", "evidence/fixture.json", profile, ["deps.lock"])
        return module, report

    def verified_fixture(self, group="requirements", index=0, profile="integration"):
        module, run = self.execute_fixture(profile)
        row = self.ledger[group][index]
        row.update({"status": "verified", "implementation": [ledger_tool.artifact(self.root, self.root / "src/behavior.py")],
                    "positive_test_ids": [f"{module}.EvidenceFixture.test_positive"],
                    "negative_test_ids": [f"{module}.EvidenceFixture.test_negative"],
                    "runs": [ledger_tool.artifact(self.root, self.root / "evidence/fixture.json")],
                    "environment": run["environment"], "review": {"reviewer": "gate-test-fixture", "disposition": "accepted"}})
        original = ledger_tool.frozen_records(self.root)[group][index]
        row["baseline_test_mapping"] = {identifier: row["positive_test_ids"] + row["negative_test_ids"]
                                        for identifier in original.get("test_ids", [])}
        return row

    def errors(self, completion=False):
        return gate.validate(self.root, self.ledger, completion=completion)

    def test_original_inventory_and_wording_are_anchored(self):
        self.assertEqual([], ledger_tool.integrity_errors(self.root, self.ledger))
        self.assertEqual({group: len(self.ledger[group]) for group in ledger_tool.COUNTS}, ledger_tool.COUNTS)
        self.assertTrue(all(row["status"] == "planned" for group in ledger_tool.COUNTS for row in self.ledger[group]))
        records = ledger_tool.frozen_records(self.root)
        self.assertEqual(29, len({row["family"] for row in records["requirements"]}))
        self.assertEqual(49, sum(row["surface"] == "FDI" for row in records["apis"]))
        self.assertEqual(156, sum(row["surface"] == "CDI" for row in records["apis"]))

    def test_planned_inventory_cannot_pass_release(self):
        errors = self.errors(completion=True)
        self.assertEqual(265, sum(error.startswith(tuple(r["id"] + ":" for r in self.ledger["requirements"])) for error in errors))
        self.assertTrue(any("independent_security_review" in error for error in errors))

    def test_runtime_secret_and_output_files_do_not_enter_source_evidence(self):
        for name in ('.runtime/local.env','src/.runtime/generated-fixture.json','artifacts/checkpoint.zip','src/.env','src/.env.production'):
            path = self.root/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('synthetic-test-secret')
        (self.root/'src/.env.example').write_text('API_KEY=replace-me')
        snapshot = ledger_tool.source_snapshot(self.root)
        self.assertIn('src/behavior.py',snapshot)
        self.assertIn('src/.env.example',snapshot)
        self.assertFalse(any('.runtime' in Path(name).parts or name.startswith('artifacts/') or name in ('src/.env','src/.env.production') for name in snapshot))

    def test_missing_substituted_and_duplicated_ids_fail(self):
        for group in ledger_tool.COUNTS:
            with self.subTest(group=group):
                changed = copy.deepcopy(self.ledger)
                changed[group].pop()
                self.assertTrue(ledger_tool.integrity_errors(self.root, changed))
                changed = copy.deepcopy(self.ledger)
                changed[group][-1] = copy.deepcopy(changed[group][0])
                self.assertTrue(ledger_tool.integrity_errors(self.root, changed))

    def test_baseline_wording_tamper_fails_even_with_rehashed_ledger_reference(self):
        path = self.root / ledger_tool.BASELINE / "registry/requirements.json"
        data = ledger_tool.read_json(path)
        data[0]["acceptance"] = "Weakened requirement"
        ledger_tool.write_json(path, data)
        self.ledger["requirements"][0]["baseline"] = ledger_tool.reference(self.root, "requirements", data[0])
        self.assertIn("Frozen baseline changed", "\n".join(self.errors()))

    def test_modified_manifest_cannot_rebaseline_scope(self):
        path = self.root / ledger_tool.BASELINE / "PACKAGE_MANIFEST.json"
        data = ledger_tool.read_json(path)
        data["files"] = []
        ledger_tool.write_json(path, data)
        self.assertIn("Frozen package manifest changed", "\n".join(self.errors()))

    def test_original_wording_reference_cannot_be_substituted(self):
        self.ledger["requirements"][0]["baseline"]["record_sha256"] = "0" * 64
        self.assertIn("wording/provenance", "\n".join(self.errors()))

    def test_status_schema_and_blocker_details_are_enforced(self):
        self.ledger["requirements"][0]["status"] = "complete"
        self.assertIn("invalid status", "\n".join(self.errors()))
        self.ledger["requirements"][0]["status"] = "blocked"
        self.assertIn("concrete blockers", "\n".join(self.errors()))

    def test_unsupported_verified_claim_is_rejected(self):
        self.ledger["requirements"][0]["status"] = "verified"
        errors = "\n".join(self.errors())
        for required in ("no implementation", "no test-run", "positive and negative", "reviewer", "mapping for AT-BAS-001"):
            self.assertIn(required, errors)

    def test_executed_positive_and_negative_fixture_can_support_claim_validation_only(self):
        self.verified_fixture()
        self.assertEqual([], self.errors())
        self.assertTrue(self.errors(completion=True))

    def test_integrity_test_profile_cannot_qualify_authentication(self):
        self.verified_fixture(profile="integrity")
        self.assertIn("cannot qualify authentication", "\n".join(self.errors()))

    def test_unexecuted_or_same_positive_negative_ids_fail(self):
        row = self.verified_fixture()
        row["negative_test_ids"] = ["fabricated.test_name"]
        self.assertIn("were not executed", "\n".join(self.errors()))
        row["negative_test_ids"] = row["positive_test_ids"]
        self.assertIn("distinct positive and negative", "\n".join(self.errors()))

    def test_changed_implementation_and_new_source_file_invalidate_evidence(self):
        self.verified_fixture()
        (self.root / "src/behavior.py").write_text("# modified\n", encoding="utf-8")
        errors = "\n".join(self.errors())
        self.assertIn("hash changed", errors)
        self.assertIn("Stale source", errors)
        (self.root / "src/new_behavior.py").write_text("# untested new code\n", encoding="utf-8")
        self.assertIn("Stale source", "\n".join(self.errors()))

    def test_changed_dependency_lock_invalidates_run(self):
        self.verified_fixture()
        (self.root / "deps.lock").write_text('{"python":"changed"}', encoding="utf-8")
        self.assertIn("Stale source", "\n".join(self.errors()))

    def test_changed_logs_and_report_hashes_are_rejected(self):
        self.verified_fixture()
        (self.root / "evidence/fixture.log").write_text("invented success", encoding="utf-8")
        self.assertIn("Artifact missing or hash changed", "\n".join(self.errors()))

    def test_skipped_tests_fail_runner_and_release_even_if_exit_is_forged(self):
        _, report = self.execute_fixture(skipped=True)
        self.assertEqual(1, report["exit_code"])
        self.assertTrue(any(t["status"] == "skipped" for t in report["tests"]))
        report["exit_code"] = 0
        path = self.root / "evidence/fixture.json"
        ledger_tool.write_json(path, report)
        with self.assertRaisesRegex(ValueError, "Skipped"):
            gate.check_run(self.root, ledger_tool.artifact(self.root, path), ledger_tool.source_snapshot(self.root),
                           {"deps.lock": ledger_tool.sha256(self.root / "deps.lock")})

    def test_run_with_missing_tests_or_duplicate_ids_fails(self):
        self.execute_fixture()
        path = self.root / "evidence/fixture.json"
        report = ledger_tool.read_json(path)
        report["tests"] = []
        ledger_tool.write_json(path, report)
        with self.assertRaisesRegex(ValueError, "Missing executed"):
            gate.check_run(self.root, ledger_tool.artifact(self.root, path), ledger_tool.source_snapshot(self.root),
                           {"deps.lock": ledger_tool.sha256(self.root / "deps.lock")})

    def test_api_route_presence_without_complete_contract_fails(self):
        row = self.verified_fixture("apis")
        row["contract"] = {"method": "GET", "path": "/auth/test", "recipe": "App"}
        errors = "\n".join(self.errors())
        self.assertIn("unfilled API contract request_schema", errors)
        self.assertIn("business API compatibility", errors)

    def test_deprecated_business_api_cannot_be_excused_as_vendor_licensing(self):
        row = self.verified_fixture("apis", index=2)
        row["compatibility"] = "explicit-non-equivalence"
        row["non_equivalence"] = "deprecated"
        self.assertIn("business API compatibility", "\n".join(self.errors()))

    def test_private_core_exposure_is_required(self):
        row = self.verified_fixture("apis", index=49)
        row["contract"] = {"exposure": "public"}
        self.assertIn("CDI private authenticated boundary", "\n".join(self.errors()))

    def test_native_source_without_build_and_execution_is_unqualified(self):
        self.verified_fixture("sdks", index=6)
        errors = "\n".join(self.errors())
        self.assertIn("native platform execution missing", errors)
        self.assertIn("profile build evidence", errors)

    def test_verified_milestone_with_unverified_dependency_fails(self):
        self.verified_fixture("milestones", index=1)
        self.assertIn("dependency M0 unverified", "\n".join(self.errors()))

    def test_verified_milestone_cannot_ignore_its_required_items(self):
        self.verified_fixture("milestones", index=0)
        self.assertIn("contained item BAS-001 unverified", "\n".join(self.errors()))
        self.assertIn("contained item WP-001 unverified", "\n".join(self.errors()))

    def test_api_placeholder_values_are_unfilled(self):
        row = self.verified_fixture("apis")
        row["contract"] = {"path": "TODO", "request_schema": "pending"}
        errors = "\n".join(self.errors())
        self.assertIn("unfilled API contract path", errors)
        self.assertIn("unfilled API contract request_schema", errors)

    def test_api_contract_must_be_current_hashed_source(self):
        row = self.verified_fixture("apis")
        row["contract"] = {"method": "GET", "path": "/changed-after-test"}
        row["contract_artifact"] = ledger_tool.artifact(self.root, self.root / "deps.lock")
        self.assertIn("must match a hashed release source", "\n".join(self.errors()))

    def test_changed_dependency_evidence_fails_even_when_source_hash_is_corrected(self):
        self.execute_fixture()
        path = self.root / "evidence/fixture.json"
        report = ledger_tool.read_json(path)
        report["dependency_hashes"]["deps.lock"] = "0" * 64
        ledger_tool.write_json(path, report)
        with self.assertRaisesRegex(ValueError, "dependency evidence"):
            gate.check_run(self.root, ledger_tool.artifact(self.root, path), ledger_tool.source_snapshot(self.root),
                           {"deps.lock": ledger_tool.sha256(self.root / "deps.lock")})

    def test_critical_security_findings_block_review(self):
        report_path = self.root / "evidence/independent.txt"
        report_path.parent.mkdir()
        report_path.write_text("Synthetic gate fixture, not actual security review.", encoding="utf-8")
        review = {"reviewer_type": "human", "independent": True, "reviewer": "fixture-reviewer",
                  "security_code_authors": ["fixture-author"], "disposition": "accepted",
                  "source_tree_sha256": ledger_tool.object_hash(ledger_tool.source_snapshot(self.root)),
                  "ledger_claims_sha256": gate.claims_hash(self.ledger),
                  "scope": ["code", "configuration", "threat_model", "evidence"],
                  "findings": [{"severity": "critical", "status": "open"}],
                  "report": ledger_tool.artifact(self.root, report_path)}
        path = self.root / "evidence/security-review.json"
        ledger_tool.write_json(path, review)
        self.ledger["independent_security_review"] = ledger_tool.artifact(self.root, path)
        self.assertIn("unresolved critical/high", "\n".join(self.errors(completion=True)))

    def test_review_hash_changes_when_evidence_claims_change(self):
        original_hash = gate.claims_hash(self.ledger)
        self.ledger["requirements"][0]["status"] = "implemented-unverified"
        self.assertNotEqual(original_hash, gate.claims_hash(self.ledger))
        changed_hash = gate.claims_hash(self.ledger)
        self.ledger["independent_security_review"] = {"path": "evidence/review.json", "sha256": "a" * 64}
        self.assertEqual(changed_hash, gate.claims_hash(self.ledger))

    def test_ai_security_review_does_not_satisfy_independent_review(self):
        review = {"reviewer_type": "AI", "independent": True, "reviewer": "agent"}
        path = self.root / "evidence/security-review.json"
        ledger_tool.write_json(path, review)
        self.ledger["independent_security_review"] = ledger_tool.artifact(self.root, path)
        self.assertIn("independent human security review", "\n".join(self.errors(completion=True)))

    def test_path_traversal_cannot_read_external_evidence(self):
        for path in ("../secret", str(self.root.parent / "secret")):
            with self.subTest(path=path), self.assertRaises(ValueError):
                gate.checked_artifact(self.root, {"path": path, "sha256": "0" * 64})

    def test_duplicate_json_keys_are_rejected(self):
        path = self.root / "duplicate.json"
        path.write_text('{"status":"failed","status":"verified"}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            ledger_tool.read_json(path)

    def test_evidence_recorder_refuses_overwrite(self):
        self.execute_fixture()
        with self.assertRaisesRegex(ValueError, "append-only"):
            ledger_tool.record_tests(self.root, "tests", "evidence/fixture.json")


if __name__ == "__main__":
    unittest.main()
