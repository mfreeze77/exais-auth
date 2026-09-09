"""Verify parent's bounded JNA text acquisition and retain notice observations.

Read-only for upstream inputs; writes only acquired-review.json beside this file.
No network, native execution, images, or license approvals.
"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def blob_hash(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def observe(path, data):
    text = data.decode("utf-8")
    lines = data.splitlines(keepends=True)
    observation = "No standalone file license grant identified; enclosing project terms require applicability review."
    family = "ENCLOSING_TERMS_REVIEW_REQUIRED"
    end = min(35, len(lines))
    if "dual-licensed under 2" in text:
        family = "Apache-2.0 OR LGPL-2.1-or-later (explicit file header)"
        observation = "Preserve file copyright lines and chosen license terms; no choice or approval is made here."
        end = next((i + 1 for i, line in enumerate(lines[:40]) if b" */" in line), min(27, len(lines)))
    elif path == "native/libffi/msvcc.sh":
        family = "MPL-1.1 OR GPL-2.0-or-later OR LGPL-2.1-or-later (explicit file header)"
        observation = "LICENSE-BUILDTOOLS separately summarizes GPL v2; preserve both texts and record chosen route before source distribution."
        end = 38
    elif path in ("native/libffi/config.guess", "native/libffi/config.sub"):
        family = "GPL-3.0-or-later WITH file-specific Autoconf-program distribution exception"
        observation = "Exception permits stated program-distribution terms only when its conditions apply; retain exact notice."
        end = 25
    elif path.startswith("native/libffi/m4/") and "General Public License" in text:
        assert "version 3" in text and "configure" in text and "special exception" in text
        family = "GPL-3.0-or-later WITH file-specific configure-output exception"
        observation = "Output configure scripts have an exception; the macro source remains governed by its GPL terms. Preserve the macro notice and GPL v3 text for the selected source-distribution route."
        end = next(i for i, line in enumerate(lines) if line.startswith(b"#serial"))
    elif path.startswith("native/libffi/m4/") and "permitted in any medium without royalty" in text:
        family = "Permissive notice-preservation grant (explicit file text)"
        observation = "Copying/modification/distribution allowed by file text subject to preserving copyright and notice; preserve exact text."
        end = next(i for i, line in enumerate(lines) if line.startswith(b"#serial"))
    elif path == "native/libffi/libtool-ldflags":
        family = "GPL-2.0-or-later (explicit file header)"
        observation = "Build-only script carries GPL terms; no output exception was identified in this file's header."
        end = 22
    elif path == "native/libffi/src/dlmalloc.c":
        family = "Public-domain statement (Doug Lea dlmalloc 2.8.3)"
        observation = "Retain the exact declaration and allocator version; actual inclusion per native build remains unverified."
        end = 7
    elif path == "native/libffi/include/ffi.h.in":
        family = "MIT-style permission grant (explicit file header)"
        observation = "Preserve the Anthony Green / Red Hat copyright and permission notice in generated/source distribution where applicable."
        end = 25
    elif path == "native/libffi/LICENSE-BUILDTOOLS":
        family = "Build/test scope statement and complete GPL v2 text"
        observation = "Lists msvcc.sh, make_sunver.pl and bhaible tests as build/test tools; explicitly assigns GPL v2 to msvcc.sh and bhaible, without an explicit individual grant for make_sunver.pl."
        end = len(lines)
    elif path in ("native/libffi/include/ffi_common.h", "native/libffi/include/ffi_cfi.h"):
        family = "File copyright notice; enclosing libffi terms need applicability review"
        observation = ("Preserve additional file copyright owners; ffi_common.h includes Free Software Foundation alongside Anthony Green/Red Hat. Root MIT notice alone does not enumerate every file copyright.")
        end = 8 if path.endswith("ffi_common.h") else 5
    elif path == "native/libffi/make_sunver.pl":
        observation = "No file license/copyright grant found. LICENSE-BUILDTOOLS mentions this tool but does not explicitly assign its terms in the following GPL-v2 sentence; enclosing-term/provenance review remains open."
    if family == "ENCLOSING_TERMS_REVIEW_REQUIRED" and "<licenses>" in text:
        family = "POM license declaration (not file-specific native closure)"
        observation = "Retained Maven declaration does not resolve every native, tool, macro or runtime component."
    witness = b"".join(lines[:end])
    return {"declared_or_observed_terms": family, "observation": observation,
            "license_approved": False, "full_file_review_complete": False,
            "witness": {"line_start": 1, "line_end": end,
                        "byte_start": 0, "byte_end_exclusive": len(witness),
                        "sha256": sha256(witness)}}


def main():
    request_path = HERE / "acquisition-request.json"
    request = read_json(request_path)
    capture_path = HERE / "acquired/acquisition.json"
    capture = read_json(capture_path)
    captured = {r["path"]: r for r in capture["records"]}
    assert len(captured) == len(request["files"]) == 47
    assert capture["errors"] == [] and capture["passed"] is True
    records = []
    for wanted in request["files"]:
        path = wanted["path"]
        data = (HERE / "acquired" / path).read_bytes()
        record = captured[path]
        assert record["url"] == wanted["url"] == record["final_url"], path
        assert record["http_status"] == 200
        assert wanted["expected_bytes"] == record["bytes"] == len(data), path
        assert wanted["expected_git_blob_sha1"] == record["expected_git_blob_sha1"] == blob_hash(data), path
        assert record["sha256"] == sha256(data), path
        records.append({"path": path, "local_path": "acquired/" + path,
                        "repo": wanted["repo"], "commit": wanted["commit"],
                        "url": wanted["url"], "bytes": len(data), "sha256": sha256(data),
                        "git_blob_sha1": blob_hash(data), "integrity_verified": True,
                        "notice_observation": observe(path, data)})
    container = read_json(HERE / "acquired/container.json")
    assert container["container_absent"] is True and container["exit_code"] == 0
    result = {
        "schema": "expertauth-jna-acquired-source-review-v1",
        "coordinate": request["coordinate"], "work_package": "WP-002",
        "status": "PARTIAL_NATIVE_SOURCE_BUILD_AND_LICENSE_CLOSURE_UNPROVEN",
        "request_sha256": sha256(request_path.read_bytes()),
        "acquisition_manifest_sha256": sha256(capture_path.read_bytes()),
        "source_files_verified": len(records),
        "source_bytes_verified": sum(r["bytes"] for r in records),
        "files": records,
        "native_builds_performed": 0, "native_platform_tests_passed": 0,
        "license_approved": False, "engine_or_foundation_status_changed": False,
        "remaining": [
            "455 additional files in the 508-file conservative inventory are not acquired by this text request or its six existing inputs.",
            "All architecture C/assembly, generated JNI/configure/header inputs, build dependencies and platform toolchains require complete correspondence proof.",
            "Full GPL-v3 source-distribution text/route for GPL-v3 macro sources is not supplied by this JNA tree's LICENSE-BUILDTOOLS (GPL v2).",
            "make_sunver.pl, header-only notices and files without independent grants require enclosing-license/provenance review; do not blanket classify the subtree as MIT.",
            "Static compiler runtimes, CRTs, JNI-header supplier terms and generated-tool license exceptions remain unverified.",
        ],
        "resource_record": {"owner": "parent consolidated source-acquisition lane",
                            "container_name": container["container_name"],
                            "container_id": container["container_id"],
                            "container_absent_recorded": True,
                            "record_path": "acquired/container.json",
                            "independent_live_docker_inspection_performed": False},
        "reviewer_resources_created": {"containers": [], "images": [], "networks": [], "volumes": []},
    }
    assert result["source_bytes_verified"] == 699788
    (HERE / "acquired-review.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"source_files_verified": len(records), "source_bytes_verified": result["source_bytes_verified"],
                      "native_builds": 0, "native_platform_tests": 0, "license_approval": False}))


if __name__ == "__main__":
    main()
