#!/usr/bin/env python3
"""Reproducibly account for the frozen API inventory without copying unlicensed specs.

Network capture reads pinned public source into memory, checks its digest, audits
the immutable repository tree and emits independently normalized protocol facts.
Exact schemas remain immutable references; this tool never proves API behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "baseline/expert-auth-full-parity-plan-v1.0/registry/api-operations.json"
BASELINE_SHA256 = "d99a8f09a3825ec3c24fb6eddb1f82b17900729f1a22b28253d136fdf7dbfc10"
METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
EXPECTED_IDS = [f"{surface}-{i:03d}" for surface, count in (("FDI", 49), ("CDI", 156)) for i in range(1, count + 1)]
BASELINE_FIELDS = ("id", "surface", "recipe", "method", "documented_name", "deprecated", "source_id", "semantic_class", "test_ids")
UNRESOLVED = ["exact-schema-redistribution-rights", "runtime-schema-conformance", "missing-versus-null-runtime-behavior", "side-effects", "idempotency", "concurrency", "cookie-attribute-runtime-behavior", "tenant-enforcement", "claim-runtime-behavior", "pagination-runtime-behavior", "deprecation-runtime-compatibility"]


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def baseline_operations() -> list[dict]:
    raw = BASELINE.read_bytes()
    if digest(raw) != BASELINE_SHA256:
        raise ValueError("Immutable API baseline digest mismatch")
    result = json.loads(raw)
    assert_ids(result, "baseline")
    return result


def assert_ids(records: list[dict], label: str) -> None:
    actual = [record.get("id") for record in records]
    if len(actual) != 205 or Counter(actual) != Counter(EXPECTED_IDS):
        raise ValueError(f"{label}: require each of the original 205 IDs exactly once; missing={sorted(set(EXPECTED_IDS) - set(actual))}, extra={sorted(set(actual) - set(EXPECTED_IDS))}")


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "ExpertAuth-contract-capture/1.0", "Accept": "application/vnd.github+json" if "api.github.com" in url else "text/plain"})
    with urllib.request.urlopen(request, timeout=45) as response:
        return response.read()


def parse_yaml(raw: bytes) -> dict:
    import yaml

    class NoDuplicateLoader(yaml.SafeLoader):
        pass

    def mapping(loader: Any, node: Any, deep: bool = False) -> dict:
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            # YAML allows unquoted integer HTTP response keys; OpenAPI's JSON
            # object representation makes those keys strings. Detect collisions
            # after this conversion so 404 and '404' cannot overwrite each other.
            if isinstance(key, int) and not isinstance(key, bool):
                key = str(key)
            if key in result:
                raise ValueError(f"Duplicate YAML key {key!r} at line {key_node.start_mark.line + 1}")
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    NoDuplicateLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    document = yaml.load(raw, Loader=NoDuplicateLoader)
    if not isinstance(document, dict) or document.get("openapi") != "3.0.0":
        raise ValueError("Only the audited OpenAPI 3.0.0 source dialect is supported")
    return document


def pointer_part(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def resolve(document: dict, value: Any, seen: frozenset[str] = frozenset()) -> Any:
    """Resolve only local refs, rejecting remote fetches and ambiguous ref siblings."""
    if not isinstance(value, dict) or "$ref" not in value:
        return value
    ref = value["$ref"]
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise ValueError(f"Unapproved external schema reference: {ref!r}")
    if ref in seen:
        raise ValueError(f"Circular direct reference: {ref}")
    target: Any = document
    for part in ref[2:].split("/"):
        target = target[part.replace("~1", "/").replace("~0", "~")]
    return resolve(document, target, seen | {ref})


def schema_facts(document: dict, schema: Any, path: str = "$", visited: frozenset[str] = frozenset()) -> list[dict]:
    """Extract field/type/enum/presence facts, never descriptions or whole schemas."""
    if not isinstance(schema, dict):
        return []
    reference = schema.get("$ref")
    if reference in visited:
        return [{"field": path, "recursive_reference": reference}]
    node = resolve(document, schema)
    visited = visited | ({reference} if reference else set())
    fact: dict[str, Any] = {"field": path}
    # These are protocol constraints, not prose, samples, or copied schema documents.
    for key in ("type", "format", "nullable", "enum", "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems", "uniqueItems", "pattern"):
        if key in node:
            fact[key] = node[key]
    if reference:
        fact["source_reference"] = reference
    if "properties" in node:
        fact["required_property_names"] = node.get("required", [])
        fact["required_keyword_declared"] = "required" in node
    if "additionalProperties" in node:
        fact["additional_properties_rule"] = node["additionalProperties"] if isinstance(node["additionalProperties"], bool) else "schema-reference"
    output = [fact]
    for name, value in node.get("properties", {}).items():
        fields = schema_facts(document, value, path + "." + name, visited)
        if fields:
            fields[0]["required_by_parent"] = name in node.get("required", [])
            fields[0]["nullable_declared"] = "nullable" in resolve(document, value)
        output.extend(fields)
    if "items" in node:
        output.extend(schema_facts(document, node["items"], path + "[]", visited))
    if isinstance(node.get("additionalProperties"), dict):
        output.extend(schema_facts(document, node["additionalProperties"], path + ".*", visited))
    for combinator in ("oneOf", "anyOf", "allOf"):
        for index, value in enumerate(node.get(combinator, [])):
            output.extend(schema_facts(document, value, f"{path}[{combinator}:{index}]", visited))
    return output


def reference(source: dict, pointer: str, value: Any) -> dict:
    return {"source_id": source["id"], "url": source["raw_url"] + pointer, "json_pointer": pointer, "canonical_json_sha256": digest(canonical(value)), "exact_schema_status": "reference-only-redistribution-rights-unresolved"}


def content_facts(document: dict, source: dict, content: dict, pointer: str) -> list[dict]:
    result = []
    for media_type, entry in content.items():
        schema = entry.get("schema")
        result.append({"media_type": media_type, "schema_reference": reference(source, pointer + "/" + pointer_part(media_type) + "/schema", schema), "field_facts": schema_facts(document, schema), "schema_declared": schema is not None})
    return result


def parameter_facts(document: dict, parameter: dict) -> dict:
    value = resolve(document, parameter)
    result = {key: value[key] for key in ("name", "in", "required", "deprecated", "allowEmptyValue", "style", "explode") if key in value}
    result["required_by_openapi"] = value.get("required", value.get("in") == "path")
    result["field_facts"] = schema_facts(document, value.get("schema"))
    if "$ref" in parameter:
        result["source_reference"] = parameter["$ref"]
    return result


def all_operations(document: dict) -> list[tuple[str, str, dict, dict]]:
    return [(method.upper(), path, operation, path_item) for path, path_item in document["paths"].items() for method, operation in path_item.items() if method in METHODS]


def audit_source(pin: dict, fetcher: Any = fetch) -> tuple[dict, dict]:
    if not re.fullmatch(r"[a-f0-9]{40}", pin["revision"]):
        raise ValueError("Source revision must be an immutable 40-character commit")
    raw_url = f"https://raw.githubusercontent.com/{pin['repository']}/{pin['revision']}/{pin['path']}"
    raw = fetcher(raw_url)
    if digest(raw) != pin["sha256"]:
        raise ValueError(f"Pinned source content mismatch: {pin['id']}")
    document = parse_yaml(raw)
    if str(document["info"]["version"]) != pin["protocol_version"]:
        raise ValueError(f"Pinned protocol version mismatch: {pin['id']}")
    tree_url = f"https://api.github.com/repos/{pin['repository']}/git/trees/{pin['revision']}?recursive=1"
    tree_raw = fetcher(tree_url)
    tree = json.loads(tree_raw)
    if tree.get("truncated"):
        raise ValueError("Truncated repository tree cannot establish license-file audit")
    paths = sorted(item["path"] for item in tree["tree"])
    candidates = [path for path in paths if re.search(r"(^|/)(licen[cs]e|copying|notice|copyright)([./_-]|$)", path, re.I)]
    checked_text_files = []
    for name in ("README.md", "CONTRIBUTING.md"):
        if name in paths:
            text_url = f"https://raw.githubusercontent.com/{pin['repository']}/{pin['revision']}/{name}"
            text_raw = fetcher(text_url)
            checked_text_files.append({"path": name, "url": text_url, "sha256": digest(text_raw), "licensing_keyword_present": bool(re.search(r"licen[sc]|copyright|permission|Apache|\bMIT\b", text_raw.decode("utf-8"), re.I)), "source_retained": False})
    metadata = {**pin, "raw_url": raw_url, "openapi_version": document["openapi"], "source_operation_count": len(all_operations(document)), "license_audit": {"repository_tree_url": tree_url, "repository_tree_sha": tree["sha"], "repository_paths": paths, "candidate_license_paths": candidates, "other_text_files_checked": checked_text_files, "openapi_license_field_present": "license" in document["info"], "redistribution_authorized": False, "decision": "reference-only; no redistribution grant established by this audit", "raw_source_persisted": False}, "capture_scope": "published-specification-facts; no implementation or behavior proof"}
    return metadata, document


def operation_facts(baseline: dict, method: str, path: str, operation: dict, path_item: dict, source: dict, document: dict) -> dict:
    pointer = "#/paths/" + pointer_part(path) + "/" + method.lower()
    parameters = [parameter_facts(document, value) for value in path_item.get("parameters", []) + operation.get("parameters", [])]
    request_body_ref = operation.get("requestBody", {})
    request_body = resolve(document, request_body_ref)
    request_body_pointer = request_body_ref.get("$ref", pointer + "/requestBody")
    request = {"body_declared": "requestBody" in operation, "body_required_by_openapi": request_body.get("required", False), "parameters": parameters, "content": content_facts(document, source, request_body.get("content", {}), request_body_pointer + "/content")}
    responses = []
    for status, response_ref in operation.get("responses", {}).items():
        response = resolve(document, response_ref)
        response_pointer = response_ref.get("$ref", pointer + "/responses/" + str(status))
        headers = [{"name": name, "field_facts": schema_facts(document, resolve(document, value).get("schema"))} for name, value in response.get("headers", {}).items()]
        responses.append({"http_status": str(status), "headers": headers, "content": content_facts(document, source, response.get("content", {}), response_pointer + "/content")})
    security = []
    for requirement in operation.get("security", document.get("security", [])):
        alternatives = []
        for name, scopes in requirement.items():
            scheme = resolve(document, document.get("components", {}).get("securitySchemes", {}).get(name, {}))
            alternatives.append({"scheme_id": name, "scopes": scopes, **{key: scheme[key] for key in ("type", "in", "name", "scheme", "bearerFormat") if key in scheme}})
        security.append(alternatives)
    response_fields = [field for response in responses for content in response["content"] for field in content["field_facts"]]
    status_values = sorted({str(value) for field in response_fields if field["field"].endswith(".status") for value in field.get("enum", [])})
    anomaly = bool(re.search(r"[^\x20-\x7e]", path))
    return {"method": method, "path_as_published": path, "path_unicode_escape": path.encode("unicode_escape").decode("ascii"), "path_resolution_status": "blocked-non-ascii-path-artifact" if anomaly else "published-path-only-not-runtime-confirmed", "upstream_operation_id": operation.get("operationId"), "deprecated_as_published": operation.get("deprecated", False), "source_reference": reference(source, pointer, operation), "protocol_version": source["protocol_version"], "request": request, "request_headers": [parameter for parameter in parameters if parameter.get("in") == "header"], "responses": responses, "security_alternatives": security, "response_headers_and_cookies": {"header_names": sorted({header["name"] for response in responses for header in response["headers"]}), "request_cookie_names": sorted({scheme["name"] for alternative in security for scheme in alternative if scheme.get("in") == "cookie"}), "response_cookie_attribute_contract": None, "status": "names-captured-attributes-and-clearing-uncharacterized"}, "error_variants": {"http_statuses": [response["http_status"] for response in responses], "application_status_enum_values": status_values, "exhaustive_runtime_errors": False}, "tenancy": {"app_id_in_published_path": "<appId>" in path, "tenant_id_in_published_path": "<tenantId>" in path, "scope_reference": source["raw_url"] + "#/info/description", "runtime_enforcement": "unverified", "session_derived_tenant_or_public_only": None}, "side_effects": {"status": "uncharacterized", "description_reference": source["raw_url"] + pointer + "/description", "mutations": None}, "idempotency": {"status": "uncharacterized", "key_header": None}, "pagination": {"parameter_names": [parameter.get("name") for parameter in parameters if re.search(r"page|limit|cursor", parameter.get("name", ""), re.I)], "runtime_boundaries": "unverified"}, "claims": {"status": "schema-facts-only-runtime-unverified"}}


def capture(baseline: list[dict], mappings: list[dict], sources: dict[str, tuple[dict, dict]]) -> dict:
    assert_ids(baseline, "baseline")
    assert_ids(mappings, "operation map")
    mapping_by_id = {entry["id"]: entry for entry in mappings}
    records = []
    used: dict[str, set[tuple[str, str]]] = {key: set() for key in sources}
    for original in baseline:
        mapping = mapping_by_id[original["id"]]
        source, document = sources[mapping["source_id"]]
        matches = [(method, path, operation, path_item) for method, path, operation, path_item in all_operations(document) if (operation.get("operationId") == mapping["upstream_operation_id"] if mapping.get("upstream_operation_id") is not None else path == mapping.get("upstream_path")) and method == original["method"]]
        if not matches:
            raise ValueError(f"Unresolved operation mapping: {original['id']}")
        variants = []
        for method, path, operation, path_item in matches:
            if bool(operation.get("deprecated", False)) != original["deprecated"]:
                raise ValueError(f"Deprecation mismatch: {original['id']}")
            normalized_recipe = re.sub(r"[^a-z0-9]", "", original["recipe"].lower())
            normalized_tags = [re.sub(r"[^a-z0-9]", "", re.sub(r"\s+(Recipe|API)$", "", tag).lower()) for tag in operation.get("tags", [])]
            if normalized_recipe not in normalized_tags:
                raise ValueError(f"Recipe mapping mismatch: {original['id']}")
            variants.append(operation_facts(original, method, path, operation, path_item, source, document))
            used[source["id"]].add((method, path))
        blockers = list(UNRESOLVED)
        if any(variant["path_resolution_status"].startswith("blocked") for variant in variants):
            blockers.append("non-ascii-path-artifact-needs-sdk-runtime-resolution")
        if source["id"].endswith("bulk-fix"):
            blockers.append("supplemental-fix-branch-not-proven-in-supported-release")
        records.append({"id": original["id"], "baseline": {key: original[key] for key in BASELINE_FIELDS}, "capture_status": "captured-reference-only", "implementation_status": "unverified-by-contract-capture", "source_id": source["id"], "variants": variants, "unknown_fields": blockers, "behavioral_test_evidence": [], "compatibility_disposition": "explicit-vendor-control-non-equivalence-required" if original["semantic_class"].startswith("vendor-control") else "business-compatibility-unverified"})
    extra = []
    for source_id, (source, document) in sources.items():
        if source_id.endswith("bulk-fix"):
            continue  # Supplemental source is explicitly limited to its two mapped entries.
        for method, path, operation, _ in all_operations(document):
            if (method, path) not in used[source_id]:
                extra.append({"source_id": source_id, "method": method, "path_as_published": path, "upstream_operation_id": operation.get("operationId"), "disposition": "outside-frozen-api-inventory; related baseline feature obligations still apply"})
    return {"format_version": 1, "baseline_sha256": BASELINE_SHA256, "capture_kind": "normalized-facts-and-immutable-references", "complete": False, "sources": [source for source, _ in sources.values()], "operations": records, "upstream_additions_outside_frozen_inventory": extra}


def validate_capture(result: dict, baseline: list[dict]) -> dict:
    assert_ids(result.get("operations", []), "capture")
    if result.get("baseline_sha256") != BASELINE_SHA256 or result.get("complete") is not False:
        raise ValueError("Capture must preserve baseline and cannot claim completion")
    originals = {entry["id"]: entry for entry in baseline}
    source_by_id = {source["id"]: source for source in result.get("sources", [])}
    expected_pins = read_json(ROOT / "contracts/source-pins.json")["sources"]
    if len(source_by_id) != len(expected_pins) or len(result["sources"]) != len(expected_pins):
        raise ValueError("Source pins missing or duplicated")
    for pin in expected_pins:
        if pin["id"] not in source_by_id or any(source_by_id[pin["id"]].get(key) != value for key, value in pin.items()):
            raise ValueError(f"Captured source does not match immutable pin: {pin['id']}")
    mappings = read_json(ROOT / "contracts/operation-map.json")["operations"]
    assert_ids(mappings, "operation map")
    mapping_by_id = {entry["id"]: entry for entry in mappings}
    for record in result["operations"]:
        original = originals[record["id"]]
        if record.get("baseline") != {key: original[key] for key in BASELINE_FIELDS}:
            raise ValueError(f"Original inventory fields changed: {record['id']}")
        if record.get("capture_status") != "captured-reference-only" or record.get("implementation_status") != "unverified-by-contract-capture":
            raise ValueError(f"Fabricated complete or implementation status: {record['id']}")
        if not set(UNRESOLVED).issubset(record.get("unknown_fields", [])) or record.get("behavioral_test_evidence") != []:
            raise ValueError(f"Reference capture cannot clear runtime/schema blockers: {record['id']}")
        if not record.get("variants") or record["source_id"] not in source_by_id:
            raise ValueError(f"Missing source or variant: {record['id']}")
        source = source_by_id[record["source_id"]]
        mapping = mapping_by_id[record["id"]]
        if record["source_id"] != mapping["source_id"]:
            raise ValueError(f"Wrong mapped source: {record['id']}")
        if not re.fullmatch(r"[a-f0-9]{40}", source.get("revision", "")) or source["license_audit"].get("redistribution_authorized") is not False or source["license_audit"].get("raw_source_persisted") is not False:
            raise ValueError("Source pin or reference-only licensing boundary invalid")
        for variant in record["variants"]:
            if variant.get("method") != original["method"] or not variant.get("path_as_published") or variant.get("protocol_version") != source["protocol_version"]:
                raise ValueError(f"Method/path/version missing or altered: {record['id']}")
            if variant.get("upstream_operation_id") != mapping.get("upstream_operation_id") or (mapping.get("upstream_path") and variant["path_as_published"] != mapping["upstream_path"]):
                raise ValueError(f"Wrong operation mapping: {record['id']}")
            for field in ("request", "request_headers", "responses", "response_headers_and_cookies", "error_variants", "tenancy", "side_effects", "idempotency", "pagination", "claims", "source_reference", "security_alternatives"):
                if field not in variant:
                    raise ValueError(f"Missing required capture field {field}: {record['id']}")
            if variant["source_reference"].get("exact_schema_status") != "reference-only-redistribution-rights-unresolved":
                raise ValueError("Exact-schema capture cannot claim license or behavior completion")
            if not variant["responses"] or not re.fullmatch(r"[a-f0-9]{64}", variant["source_reference"].get("canonical_json_sha256", "")):
                raise ValueError(f"Responses or source fragment digest missing: {record['id']}")
    return {"accounted_operations": len(result["operations"]), "FDI": 49, "CDI": 156, "operation_variants": sum(len(record["variants"]) for record in result["operations"]), "captured_reference_only": len(result["operations"]), "fully_captured_and_behavior_verified": 0, "exact_schema_redistribution_blocked": 205, "vendor_control_non_equivalences_required": sum(original["semantic_class"].startswith("vendor-control") for original in baseline), "operations_with_path_artifacts": [record["id"] for record in result["operations"] if any(variant["path_resolution_status"].startswith("blocked") for variant in record["variants"])], "upstream_additions_outside_frozen_inventory": len(result.get("upstream_additions_outside_frozen_inventory", [])), "complete": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true", help="Offline validation of the stored capture; no network or writes")
    parser.add_argument("--check", action="store_true", help="Refetch pinned source and compare without rewriting generated output")
    parser.add_argument("--require-complete", action="store_true", help="Fail if any exact schema or behavioral contract remains unresolved")
    args = parser.parse_args()
    baseline = baseline_operations()
    target = ROOT / "contracts/api-contracts.json"
    if args.validate:
        result = read_json(target)
    else:
        pins = read_json(ROOT / "contracts/source-pins.json")["sources"]
        source_data = {pin["id"]: audit_source(pin) for pin in pins}
        result = capture(baseline, read_json(ROOT / "contracts/operation-map.json")["operations"], source_data)
        if args.check:
            if canonical(result) != canonical(read_json(target)):
                raise ValueError("Stored capture differs from fresh pinned source extraction")
        else:
            # Validate before persisting any newly generated artifact.
            validate_capture(result, baseline)
            write_json(target, result)
    summary = validate_capture(result, baseline)
    print(json.dumps(summary, indent=2))
    if not args.validate and not args.check:
        import yaml
        evidence = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "command": "python tools/capture_contracts.py", "python_version": sys.version, "pyyaml_version": yaml.__version__, "exit_code": 0, "source_files_retained": False, "input_and_output_sha256": {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in (Path(__file__), BASELINE, ROOT / "contracts/source-pins.json", ROOT / "contracts/operation-map.json", target)}, "result": summary, "evidence_type": "source-contract-accounting-not-runtime-implementation"}
        write_json(ROOT / "evidence/contracts/capture-report.json", evidence)
    return 1 if args.require_complete and not summary["complete"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, OSError) as error:
        print(f"Contract capture failed: {error}", file=sys.stderr)
        raise SystemExit(2)
