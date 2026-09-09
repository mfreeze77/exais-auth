"""Retain bounded make_sunver.pl provenance findings; no upstream changes/fetches."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
JNA = HERE.parent
ROOT = JNA.parents[3]
JNA_COMMIT = "cc4ce71d511a9aa17219cc36e2338dd1b0f52770"
LIBFFI_ADD = "ca112537df7b9cdbccad7541aa3cb43b2a2dac9a"
GCC_REVISION = "d809887a669e7c2c709d1ca37d2f0e44ecfdb341"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def record(path):
    data = path.read_bytes()
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": len(data),
            "sha256": digest(data),
            "git_blob_sha1": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}


def main():
    script = record(JNA / "acquired/native/libffi/make_sunver.pl")
    assert script["sha256"] == "ca40d3458893e03a90807be87d720a59e921ee6bf678c6696779d635004a261f"
    assert script["git_blob_sha1"] == "8a90b1fea0d366f7a9ec0857d5304a67ee34f389"
    assert script["bytes"] == 9021
    assert script["git_blob_sha1"].startswith("8a90b1fea0d36")
    inventory = json.loads((JNA / "fetch-manifest.json").read_text())
    entry = next(x for x in inventory["files"] if x["path"] == "native/libffi/make_sunver.pl")
    assert entry["expected_git_blob_sha1"] == script["git_blob_sha1"]
    assert entry["expected_bytes"] == script["bytes"]
    sources = [
        {"id": "jna-import", "url": "https://github.com/java-native-access/jna/commit/ffb7e0e7ed963d88eec3ed93fe9a47efccecd557",
         "finding": "JNA import says libffi v3.3 plus 64 commits and links 5c63b463b87d3c06102a4a7f05f395929d9ea79b; make_sunver.pl added in the diff.", "immutable": True},
        {"id": "libffi-add", "url": f"https://github.com/libffi/libffi/commit/{LIBFFI_ADD}.patch",
         "finding": "2019-10-26 Anthony Green import adds 333-line script with target blob prefix 8a90b1fea. Changes source location from ../contrib/make_sunver.pl. Adds script name to tooling-scope paragraph but not the following GPL-v2 assignment sentence.", "immutable": True,
         "observed_git_blob_prefix": "8a90b1fea", "local_blob_prefix_matches": True},
        {"id": "gcc-matching-edit", "url": f"https://github.com/gcc-mirror/gcc/commit/{GCC_REVISION}.patch",
         "finding": "2013-02-27 Rainer Orth change enforces C locale; resulting contrib/make_sunver.pl blob prefix 8a90b1fea0d36 matches the local pinned file. SVN r196309.", "immutable": True,
         "observed_git_blob_prefix": "8a90b1fea0d36", "local_blob_prefix_matches": True},
        {"id": "gcc-original-add", "url": "https://github.com/gcc-mirror/gcc/commit/1e0859a29e0b7ca2f70e156aafdac7b4db30663b",
         "finding": "2010-07-02 Rainer Orth adds contrib/make_sunver.pl without a file license header. SVN r161701. This establishes an earlier source-history witness, not every author's grant.", "immutable": True},
        {"id": "gcc-readme", "url": f"https://raw.githubusercontent.com/gcc-mirror/gcc/{GCC_REVISION}/README",
         "finding": "General GCC permission points to COPYING* files and notes differing terms for manuals and some runtime libraries. It does not assign this script a specific SPDX expression.", "immutable": True},
        {"id": "gcc-copying2", "url": f"https://raw.githubusercontent.com/gcc-mirror/gcc/{GCC_REVISION}/COPYING",
         "finding": "GPL version 2 text is present at the same GCC revision.", "immutable": True},
        {"id": "gcc-copying3", "url": f"https://raw.githubusercontent.com/gcc-mirror/gcc/{GCC_REVISION}/COPYING3",
         "finding": "GPL version 3 text is present at the same GCC revision. License-text availability alone does not supply the missing file-specific application evidence.", "immutable": True},
        {"id": "ffmpeg-import", "url": "https://github.com/FFmpeg/FFmpeg/commit/c1aac39eaccd32dc3b74ccfcce701d3d888fbc6b",
         "finding": "2015 import explicitly says script comes from GCC; FFmpeg copy adds FSF 2010-2013/GPL-3.0-or-later header. This is primary evidence for FFmpeg's downstream treatment, not proof the original rightsholders authorized the exact JNA bytes under those terms.", "immutable": True},
    ]
    for source in sources:
        source["inspection_method"] = "web primary-source view"
        source["raw_response_bytes_retained"] = False
        source["upstream_sha256_verified"] = False
    result = {
        "schema": "expertauth-jna-make-sunver-grant-review-v1",
        "scope": "Bounded upstream provenance and grant research only; WP-002",
        "status": "BLOCKED_EXACT_GRANT_UNRESOLVED",
        "script": {**script, "repo": "java-native-access/jna", "commit": JNA_COMMIT,
                   "source_path": "native/libffi/make_sunver.pl", "lines": 333},
        "original_evidence_integrity_verified": True,
        "enclosing_notice_files": [
            record(JNA / "acquired/native/libffi/LICENSE-BUILDTOOLS"),
            record(ROOT / "evidence/reuse/runtime-distribution-review/upstream/jna__native__libffi__LICENSE"),
            record(ROOT / "evidence/reuse/runtime-distribution-review/upstream/jna__LICENSE"),
        ],
        "primary_sources": sources,
        "conclusion": {
            "provenance": "Strong GCC-to-libffi-to-JNA evidence, with matching 13/9-hex blob prefixes; upstream full-blob byte identity not independently re-acquired in this research lane.",
            "candidate_terms": "GPL-3.0-or-later is suggested by downstream FFmpeg's explicit classification and GCC provenance; it remains unqualified for the exact JNA file.",
            "established_grant": None,
            "root_MIT_blanket_assignment_supported": False,
            "automatic_GPL2_from_LICENSE_BUILDTOOLS_supported": False,
            "license_approved": False,
            "existing_exclusion_changed": False,
        },
        "blocker": "No unambiguous originating/enclosing grant was established that selects terms for this exact script and all relevant contributions. Do not infer a grant from public repository access, neighboring notices, or a downstream-added header.",
        "resume_inputs": [
            {"repo": "gcc-mirror/gcc", "commit": GCC_REVISION, "path": "contrib/make_sunver.pl",
             "url": f"https://raw.githubusercontent.com/gcc-mirror/gcc/{GCC_REVISION}/contrib/make_sunver.pl",
             "expected_candidate_git_blob_sha1": script["git_blob_sha1"], "expected_candidate_bytes": 9021,
             "purpose": "Acquire exact source or full Git blob metadata and verify candidate identity; not license approval."},
            {"repo": "libffi/libffi", "commit": LIBFFI_ADD, "path": "make_sunver.pl",
             "url": f"https://raw.githubusercontent.com/libffi/libffi/{LIBFFI_ADD}/make_sunver.pl",
             "expected_candidate_git_blob_sha1": script["git_blob_sha1"], "expected_candidate_bytes": 9021,
             "purpose": "Verify exact import identity, retaining immutable provenance and SHA-256."},
            {"purpose": "Find an originating GCC/FSF license declaration or maintainer clarification explicitly applicable to this script/revision; no message to upstream has been sent."},
        ],
        "access_limit": "Web API/Gitiles metadata endpoints were unavailable. Failed endpoints were not retried; no host-network retry, Docker, binary or archive acquisition occurred.",
        "resources_created": {"containers": [], "images": [], "networks": [], "volumes": []},
        "runtime_code_changes": [], "native_tests_passed": 0,
    }
    (HERE / "findings.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "local_source_sha256": script["sha256"],
                      "primary_sources": len(sources), "original_evidence_changed": False}))


if __name__ == "__main__":
    main()
