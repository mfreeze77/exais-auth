"""Verify the parent's bounded SQLite text acquisition, without network/native use."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import re

OUT = Path(__file__).resolve().parent.parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def main():
    request_path = OUT / "acquisition-request.json"
    acquisition_path = OUT / "acquired/acquisition.json"
    container_path = OUT / "acquired/container.json"
    request = json.loads(request_path.read_text())
    acquisition = json.loads(acquisition_path.read_text())
    container = json.loads(container_path.read_text())
    metadata = {row["path"]: row for row in json.loads((OUT / "manifest.json").read_text())["files"]}
    recorded = {row["path"]: row for row in acquisition["records"]}
    assert len(request["files"]) == len(recorded) == len(acquisition["records"]) == 26
    assert set(recorded) == {row["path"] for row in request["files"]}
    result = {"scope": "Independent exact-text acquisition verification; no license approval, native rebuild or native-platform qualification",
              "timestamp_utc": datetime.now(timezone.utc).isoformat(), "request_sha256": sha(request_path.read_bytes()),
              "acquisition_report_sha256": sha(acquisition_path.read_bytes()), "container_report_sha256": sha(container_path.read_bytes()),
              "manifest_sha256": sha((OUT / "manifest.json").read_bytes()), "script_sha256": sha(Path(__file__).read_bytes()),
              "license_approved": False, "native_rebuild_verified": False, "native_platform_tests_passed": False,
              "parent_recorded_container_absent": container.get("container_absent"), "files": [], "toolchain_references": []}
    for row in request["files"]:
        path = row["path"]
        assert not path.startswith("lib/") and path != "src/main/ext/extension-functions.c", "Excluded permission-gap source was fetched"
        raw = (OUT / "acquired" / path).read_bytes()
        fact = metadata[path]
        observed = recorded[path]
        assert row["expected_git_blob_sha1"] == fact["git_blob_sha1"] == blob(raw)
        assert row["expected_bytes"] == fact["git_tree_bytes"] == observed["bytes"] == len(raw)
        assert observed["sha256"] == sha(raw) and observed["http_status"] == 200
        assert observed["url"] == observed["final_url"] == row["url"]
        text = raw.decode("utf-8")
        references = []
        for number, line in enumerate(text.splitlines(), 1):
            if line.startswith("DEFAULT_DOCKCROSS_IMAGE=") or line.startswith("FROM ") or "cargo install --git" in line:
                references.append({"line": number, "text": line, "historical_toolchain_digest_established": False})
        if references:
            result["toolchain_references"].append({"path": path, "references": references})
        result["files"].append({"path": path, "bytes": len(raw), "sha256": sha(raw), "git_blob_sha1": blob(raw),
                                 "exact_immutable_source_object_match": True,
                                 "file_permission_header_matches": [{"line": number, "text": line.strip()} for number, line in enumerate(text.splitlines(), 1) if re.search(r"copyright|licensed under|SPDX-License-Identifier|proprietary", line, re.I)],
                                 "license_context": "Apache-2.0 repository context; separate toolchain/dependency/generated-origin obligations remain unqualified"})
    allowed = {row["path"] for row in request["files"]} | {"acquisition.json", "container.json"}
    actual = {path.relative_to(OUT / "acquired").as_posix() for path in (OUT / "acquired").rglob("*") if path.is_file()}
    assert actual == allowed, "Unexpected acquired file set"
    result["files_verified"] = len(result["files"])
    result["total_verified_bytes"] = sum(row["bytes"] for row in result["files"])
    result["acquired_set_exact"] = True
    result["passed"] = result["files_verified"] == 26 and result["total_verified_bytes"] == 134402 and container.get("passed") is True and container.get("container_absent") is True
    target = OUT / "research/acquired-verification.json"
    assert not target.exists(), "Preserve prior acquisition verification"
    target.write_bytes((json.dumps(result, indent=2) + "\n").encode())
    print(json.dumps({"files_verified": result["files_verified"], "bytes": result["total_verified_bytes"], "passed": result["passed"], "report_sha256": sha(target.read_bytes())}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
