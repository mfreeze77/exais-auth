"""Tests of real pinned-source capture and failures that must block completion.

Synthetic documents below test only extractor behavior; they are never presented
as authentication/SDK integration evidence. Integration checks inspect the actual
205-entry artifact produced from pinned upstream sources.
"""
import copy
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("capture_contracts", ROOT / "tools/capture_contracts.py")
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


class ArtifactContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = capture.baseline_operations()
        cls.artifact = capture.read_json(ROOT / "contracts/api-contracts.json")
        cls.by_id = {record["id"]: record for record in cls.artifact["operations"]}

    def tampered(self):
        return copy.deepcopy(self.artifact)

    def test_all_205_original_ids_are_preserved(self):
        result = capture.validate_capture(self.artifact, self.baseline)
        self.assertEqual(result["accounted_operations"], 205)
        self.assertEqual(result["FDI"], 49)
        self.assertEqual(result["CDI"], 156)
        self.assertEqual(result["fully_captured_and_behavior_verified"], 0)

    def test_missing_id_is_rejected(self):
        artifact = self.tampered()
        artifact["operations"].pop()
        with self.assertRaisesRegex(ValueError, "205 IDs"):
            capture.validate_capture(artifact, self.baseline)

    def test_duplicate_id_cannot_replace_a_missing_id(self):
        artifact = self.tampered()
        artifact["operations"][-1] = artifact["operations"][0]
        with self.assertRaisesRegex(ValueError, "205 IDs"):
            capture.validate_capture(artifact, self.baseline)

    def test_original_wording_cannot_be_weakened(self):
        artifact = self.tampered()
        artifact["operations"][0]["baseline"]["documented_name"] = "Optional route"
        with self.assertRaisesRegex(ValueError, "inventory fields changed"):
            capture.validate_capture(artifact, self.baseline)

    def test_fabricated_capture_complete_is_rejected(self):
        artifact = self.tampered()
        artifact["operations"][0]["capture_status"] = "complete"
        with self.assertRaisesRegex(ValueError, "Fabricated"):
            capture.validate_capture(artifact, self.baseline)

    def test_fabricated_implementation_verified_is_rejected(self):
        artifact = self.tampered()
        artifact["operations"][0]["implementation_status"] = "verified"
        with self.assertRaisesRegex(ValueError, "Fabricated"):
            capture.validate_capture(artifact, self.baseline)

    def test_top_level_completion_is_rejected(self):
        artifact = self.tampered()
        artifact["complete"] = True
        with self.assertRaisesRegex(ValueError, "cannot claim completion"):
            capture.validate_capture(artifact, self.baseline)

    def test_blockers_cannot_be_removed(self):
        artifact = self.tampered()
        artifact["operations"][0]["unknown_fields"].remove("side-effects")
        with self.assertRaisesRegex(ValueError, "cannot clear"):
            capture.validate_capture(artifact, self.baseline)

    def test_required_header_field_cannot_disappear(self):
        artifact = self.tampered()
        del artifact["operations"][0]["variants"][0]["request_headers"]
        with self.assertRaisesRegex(ValueError, "required capture field"):
            capture.validate_capture(artifact, self.baseline)

    def test_source_revision_tampering_is_rejected(self):
        artifact = self.tampered()
        artifact["sources"][0]["revision"] = "f" * 40
        with self.assertRaisesRegex(ValueError, "immutable pin"):
            capture.validate_capture(artifact, self.baseline)

    def test_fake_schema_license_permission_is_rejected(self):
        artifact = self.tampered()
        artifact["sources"][0]["license_audit"]["redistribution_authorized"] = True
        with self.assertRaisesRegex(ValueError, "licensing boundary"):
            capture.validate_capture(artifact, self.baseline)

    def test_misleading_oauth_start_continue_swap_is_rejected(self):
        self.assertEqual(self.by_id["FDI-014"]["variants"][0]["upstream_operation_id"], "oauthLoginGET")
        self.assertEqual(self.by_id["FDI-023"]["variants"][0]["upstream_operation_id"], "oauthAuthGET")
        artifact = self.tampered()
        artifact["operations"][13]["variants"][0]["upstream_operation_id"] = "oauthAuthGET"
        with self.assertRaisesRegex(ValueError, "Wrong operation mapping"):
            capture.validate_capture(artifact, self.baseline)

    def test_webauthn_recovery_get_is_preserved_and_uncharacterized(self):
        variant = self.by_id["CDI-150"]["variants"][0]
        self.assertEqual(variant["method"], "GET")
        self.assertEqual(variant["side_effects"]["status"], "uncharacterized")
        self.assertIn("RECOVER_ACCOUNT_TOKEN_INVALID_ERROR", variant["error_variants"]["application_status_enum_values"])

    def test_unicode_route_artifacts_are_preserved_and_blocked(self):
        ids = [record["id"] for record in self.artifact["operations"] if any("\u2800" in variant["path_as_published"] for variant in record["variants"])]
        self.assertEqual(ids, ["FDI-026", "CDI-099", "CDI-104", "CDI-116"])
        for ident in ids:
            self.assertIn("non-ascii-path-artifact-needs-sdk-runtime-resolution", self.by_id[ident]["unknown_fields"])

    def test_session_tenant_and_app_variants_are_both_preserved(self):
        for ident in ("CDI-106", "CDI-110"):
            self.assertEqual(len(self.by_id[ident]["variants"]), 2)
            self.assertEqual({variant["tenancy"]["tenant_id_in_published_path"] for variant in self.by_id[ident]["variants"]}, {True, False})

    def test_bulk_entries_have_explicit_supplemental_branch_blocker(self):
        for ident in ("CDI-028", "CDI-030"):
            self.assertEqual(self.by_id[ident]["source_id"], "CDI-5.3.0-bulk-fix")
            self.assertIn("supplemental-fix-branch-not-proven-in-supported-release", self.by_id[ident]["unknown_fields"])

    def test_refresh_header_and_cookie_names_are_captured_without_false_attributes(self):
        variant = self.by_id["FDI-032"]["variants"][0]
        self.assertIn("Set-Cookie", variant["response_headers_and_cookies"]["header_names"])
        self.assertIn("st-refresh-token", variant["response_headers_and_cookies"]["header_names"])
        self.assertIn("sRefreshToken", variant["response_headers_and_cookies"]["request_cookie_names"])
        self.assertIsNone(variant["response_headers_and_cookies"]["response_cookie_attribute_contract"])

    def test_only_five_vendor_control_entries_are_non_equivalences(self):
        ids = [record["id"] for record in self.artifact["operations"] if record["compatibility_disposition"].startswith("explicit-vendor")]
        self.assertEqual(ids, ["CDI-002", "CDI-007", "CDI-010", "CDI-013", "CDI-021"])

    def test_upstream_additions_do_not_expand_or_remove_frozen_ids(self):
        self.assertEqual(len(self.artifact["upstream_additions_outside_frozen_inventory"]), 5)
        self.assertEqual(len(self.artifact["operations"]), 205)

    def test_raw_specs_descriptions_and_examples_are_not_persisted(self):
        text = (ROOT / "contracts/api-contracts.json").read_text(encoding="utf-8")
        self.assertNotIn('"description":', text)
        self.assertNotIn('"example":', text)
        self.assertNotIn('"examples":', text)
        self.assertFalse(list((ROOT / "contracts").glob("**/api_spec.yaml")))


class ExtractorSecurityTests(unittest.TestCase):
    def test_missing_and_nullable_are_distinct(self):
        fields = capture.schema_facts({}, {"type": "object", "required": ["mandatory"], "properties": {"mandatory": {"type": "string"}, "nullable": {"type": "string", "nullable": True}, "optional": {"type": "string"}}})
        by_field = {field["field"]: field for field in fields}
        self.assertTrue(by_field["$.mandatory"]["required_by_parent"])
        self.assertFalse(by_field["$.optional"]["required_by_parent"])
        self.assertFalse(by_field["$.optional"]["nullable_declared"])
        self.assertTrue(by_field["$.nullable"]["nullable"])

    def test_local_reference_resolves_constraints(self):
        doc = {"components": {"schemas": {"state": {"type": "string", "enum": ["OK", "ERROR"]}}}}
        facts = capture.schema_facts(doc, {"$ref": "#/components/schemas/state"})
        self.assertEqual(facts[0]["enum"], ["OK", "ERROR"])

    def test_external_reference_cannot_trigger_network_access(self):
        with self.assertRaisesRegex(ValueError, "external schema reference"):
            capture.resolve({}, {"$ref": "http://169.254.169.254/metadata"})

    def test_reference_cycles_fail_explicitly(self):
        with self.assertRaisesRegex(ValueError, "Circular direct"):
            capture.resolve({"cycle": {"$ref": "#/cycle"}}, {"$ref": "#/cycle"})

    def test_recursive_object_schema_is_bounded_and_retains_reference(self):
        doc = {"components": {"schemas": {"node": {"type": "object", "properties": {"next": {"$ref": "#/components/schemas/node"}}}}}}
        facts = capture.schema_facts(doc, {"$ref": "#/components/schemas/node"})
        self.assertEqual(len(facts), 2)
        self.assertEqual(facts[1]["recursive_reference"], "#/components/schemas/node")

    def test_yaml_numeric_http_keys_normalize_without_overwrite(self):
        doc = capture.parse_yaml(b"openapi: 3.0.0\nresponses:\n  404: {description: missing}\n")
        self.assertIn("404", doc["responses"])
        with self.assertRaisesRegex(ValueError, "Duplicate YAML"):
            capture.parse_yaml(b"openapi: 3.0.0\nresponses:\n  404: {description: one}\n  '404': {description: two}\n")

    def test_yaml_object_constructors_are_not_executed(self):
        import yaml
        with self.assertRaises(yaml.constructor.ConstructorError):
            capture.parse_yaml(b"openapi: 3.0.0\nvalue: !!python/object/apply:os.system ['echo unsafe']\n")

    def test_source_digest_mismatch_fails_before_parsing(self):
        pin = {"id": "synthetic", "revision": "a" * 40, "repository": "example/test", "path": "api_spec.yaml", "sha256": "0" * 64}
        with self.assertRaisesRegex(ValueError, "content mismatch"):
            capture.audit_source(pin, lambda url: b"untrusted replacement")

    def test_mutable_revision_is_rejected_before_network_access(self):
        with self.assertRaisesRegex(ValueError, "immutable"):
            capture.audit_source({"revision": "main"}, lambda url: self.fail("network fetch must not run"))


if __name__ == "__main__":
    unittest.main()
