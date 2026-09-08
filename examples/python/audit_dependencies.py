"""Audit installed wheel versions/source hashes against the pinned source registry.

Run in the built SDK image with /work mounted read-only and evidence output scoped.
The report records declarations and advisories; it is not independent legal/security review.
"""
import hashlib
import importlib.metadata
import json
import pathlib
import sys
import urllib.request
from datetime import datetime, timezone

ROOT = pathlib.Path("/work")
EXPECTED_COMMIT = "b498da1a6d09ca84ca204ac881df76900df19175"
manifest_path = ROOT / "reuse/files/supertokens__supertokens-python.json"
manifest = json.loads(manifest_path.read_text())
assert manifest["commit"] == EXPECTED_COMMIT
source_hashes = {entry["source_path"]: entry["sha256"] for entry in manifest["files"]}
dist = importlib.metadata.distribution("supertokens-python")
sdk_files = []
for entry in dist.files:
    name = str(entry)
    if name.startswith("supertokens_python/") and name.endswith(".py"):
        actual = hashlib.sha256(dist.locate_file(entry).read_bytes()).hexdigest()
        sdk_files.append({"path": name, "sha256": actual, "audited_source_sha256": source_hashes.get(name), "matches_audited_source": actual == source_hashes.get(name)})
assert sdk_files, "No SDK source files found in installed package"
mismatches = [entry for entry in sdk_files if not entry["matches_audited_source"]]
resolution = json.loads((ROOT / "examples/python/dependency-resolution.json").read_text())
dependencies = []
for entry in resolution["install"]:
    name, version = entry["metadata"]["name"], entry["metadata"]["version"]
    installed = importlib.metadata.distribution(name)
    assert installed.version == version, f"Installed dependency mismatch: {name}"
    license_files = []
    for path in installed.files or []:
        lower = str(path).lower()
        if (".dist-info/" in lower or ".egg-info/" in lower) and any(word in pathlib.Path(lower).name for word in ("license", "copying", "notice")):
            license_files.append({"installed_path": str(path), "sha256": hashlib.sha256(installed.locate_file(path).read_bytes()).hexdigest()})
    metadata = installed.metadata
    dependencies.append({"name": name, "version": version, "wheel_url": entry["download_info"]["url"], "wheel_sha256": entry["download_info"]["archive_info"]["hashes"]["sha256"], "declared_license": metadata.get("License-Expression") or metadata.get("License"), "license_classifiers": [value for value in metadata.get_all("Classifier", []) if value.startswith("License ::")], "installed_license_files": license_files, "modifications": [], "boundary": "unmodified installed wheel dependency"})
queries = [{"package": {"ecosystem": "PyPI", "name": entry["name"]}, "version": entry["version"]} for entry in dependencies]
osv_request = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=json.dumps({"queries": queries}).encode(), headers={"Content-Type": "application/json"}, method="POST")
try:
    with urllib.request.urlopen(osv_request, timeout=30) as response:
        advisory_raw = response.read()
    osv = json.loads(advisory_raw)["results"]
    assert len(osv) == len(dependencies)
    advisories = [{"name": dependency["name"], "version": dependency["version"], "vulnerability_ids": [vulnerability["id"] for vulnerability in result.get("vulns", [])]} for dependency, result in zip(dependencies, osv)]
    advisory_status = "queried-OSV-exact-versions; absence-of-matches-is-not-independent-review"
except Exception as error:
    advisories = []
    advisory_status = "blocked-OSV-query-" + type(error).__name__
report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "python": sys.version, "source_repository": "supertokens/supertokens-python", "source_commit": EXPECTED_COMMIT, "audited_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(), "sdk_package": "supertokens-python", "sdk_version": dist.version, "sdk_source_files_checked": len(sdk_files), "sdk_source_mismatches": mismatches, "sdk_source_files": sdk_files, "dependencies": dependencies, "advisory_status": advisory_status, "advisories": advisories, "independent_review": "blocked-not-performed", "license_review": "installed notices and declarations recorded; substantive per-file exceptions remain separate audit obligations", "input_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in (pathlib.Path(__file__), ROOT / "examples/python/dependency-resolution.json", ROOT / "examples/python/requirements.lock", ROOT / "examples/python/LICENSES/supertokens-python-LICENSE.md")}, "exit_code": 1 if mismatches else 0}
destination = ROOT / "evidence/clients/python/dependency-audit.json"
destination.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"source_files": len(sdk_files), "source_mismatches": len(mismatches), "dependencies": len(dependencies), "advisory_status": advisory_status, "advisory_matches": [entry for entry in advisories if entry["vulnerability_ids"]]}, indent=2))
raise SystemExit(report["exit_code"])
