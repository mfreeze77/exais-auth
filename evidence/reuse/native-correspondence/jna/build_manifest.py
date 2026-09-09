"""Offline JNA source/provenance inventory. Does not fetch, build, or execute JNA.

Optional --tree is the complete immutable GitHub recursive tree response. Its
response provenance is retained by the parent's consolidated acquisition lane.
Outputs stay in this script's directory. No original audit files are modified.
"""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
REVIEW = ROOT / "evidence/reuse/runtime-distribution-review"
REPO = "java-native-access/jna"
COMMIT = "cc4ce71d511a9aa17219cc36e2338dd1b0f52770"
RAW = f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/"
TREE_URL = f"https://api.github.com/repos/{REPO}/git/trees/{COMMIT}?recursive=1"
ROOT_INPUTS = {
    "LICENSE", "AL2.0", "LGPL2.1", "build.xml", "build-ant-tools.xml",
    "pom-jna.xml", "pom-jna-platform.xml", "pom-jna-jpms.xml",
    "pom-jna-platform-jpms.xml", ".travis.yml", "appveyor.yml",
}
DIRECT_NATIVE = {
    "Makefile", "README.libffi", "build.xml", "callback.c", "cc.sh",
    "dispatch.c", "dispatch.h", "dll-callback.c", "jnidispatch.rc", "ld.sh",
    "pom.xml", "protect.h", "snprintf.h", "testlib.c", "testlib2.c",
}
LIBFFI_WITNESSES = {
    "LICENSE", "LICENSE-BUILDTOOLS", "configure.ac", "configure.host",
    "Makefile.am", "autogen.sh", "msvcc.sh", "make_sunver.pl",
    "libtool-ldflags", "libtool-version", "libffi.map.in",
    "generate-darwin-source-and-headers.py", "libffi.xcodeproj/project.pbxproj",
    "src/prep_cif.c", "src/types.c", "src/raw_api.c", "src/java_raw_api.c",
    "src/closures.c", "src/debug.c", "src/dlmalloc.c",
}
BUILD_BINARY_INPUTS = {
    "lib/ant.jar", "lib/asm-8.0.1.jar", "lib/animal-sniffer-ant-tasks-1.17.jar",
    "lib/maven-ant-tasks-2.1.3.jar",
}
BINARY_SUFFIXES = {".jar", ".zip", ".gz", ".xz", ".bz2", ".dll", ".so",
                   ".dylib", ".jnilib", ".a", ".o", ".obj", ".lib", ".exe",
                   ".class", ".pdf", ".png", ".jpg", ".gif", ".ico"}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def blob_hash(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def record_role(path):
    if path.startswith("native/libffi/"):
        return "vendored_libffi_source_build_test_and_notices"
    if path.startswith("native/"):
        return "dispatch_native_source_and_build"
    if path.startswith("src/"):
        return "java_sources_for_generated_jni_headers"
    if path.startswith("ant-tools-src/"):
        return "custom_ant_build_tools_source"
    return "root_build_license_or_ci_context"


def source_selected(path):
    return (path in ROOT_INPUTS or path.startswith("native/") or
            path.startswith("ant-tools-src/") or
            (path.startswith("src/") and path.endswith(".java")))


def file_record(path, metadata=None, cached=None):
    result = {
        "repo": REPO, "commit": COMMIT, "path": path, "url": RAW + path,
        "role": record_role(path), "expected_git_blob_sha1": None,
        "expected_bytes": None, "sha256": None,
        "verification": "pinned_path_observed_in_primary_source; blob_metadata_pending",
        "source_downloaded_in_this_task": False,
    }
    if metadata:
        result.update(expected_git_blob_sha1=metadata["sha"],
                      expected_bytes=metadata["size"], git_mode=metadata["mode"],
                      verification="immutable_recursive_tree_metadata")
    if cached:
        data = (REVIEW / cached["path"]).read_bytes()
        assert len(data) == cached["bytes"] and sha256(data) == cached["sha256"]
        digest = blob_hash(data)
        if metadata:
            assert digest == metadata["sha"] and len(data) == metadata["size"], path
        result.update(expected_git_blob_sha1=digest, expected_bytes=len(data),
                      sha256=sha256(data), cached_source=cached["path"],
                      verification=("cached_immutable_source_matches_tree" if metadata
                                    else "cached_immutable_source_bytes; tree_comparison_pending"))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=Path)
    args = parser.parse_args()
    if args.tree is None:
        recorded_tree = ROOT / "evidence/reuse/native-correspondence/metadata/run-01/jna/tree.json"
        if recorded_tree.is_file():
            args.tree = recorded_tree.relative_to(ROOT)
    inv = read_json(REVIEW / "archive-inventory.json")
    artifact = next(x for x in inv["artifacts"]
                    if x["coordinate"] == "net.java.dev.jna:jna:5.8.0")
    jar = ROOT / artifact["binary"]["path"]
    jar_bytes = jar.read_bytes()
    assert sha256(jar_bytes) == artifact["binary"]["sha256"]
    upstream_jar = read_json(REVIEW / "upstream/jna-dist-jar-metadata.json")
    assert blob_hash(jar_bytes) == upstream_jar["sha"]
    assert len(jar_bytes) == upstream_jar["size"]
    tag = read_json(REVIEW / "upstream/jna-tag.json")
    assert tag["object"] == {"sha": COMMIT, "type": "commit",
                             "url": f"https://api.github.com/repos/{REPO}/git/commits/{COMMIT}"}
    natives, notices, embedded_texts = [], [], {}
    with zipfile.ZipFile(jar) as archive:
        for old in artifact["binary"]["native_members"]:
            data = archive.read(old["member"])
            assert sha256(data) == old["sha256"] and len(data) == old["bytes"]
            platform = old["member"].split("/")[-2]
            natives.append({**old, "platform": platform, "git_blob_sha1": blob_hash(data),
                            "upstream_packaging_input": f"lib/native/{platform}.jar",
                            "source_rebuild_performed": False,
                            "native_platform_tests_passed": False,
                            "source_to_native_binary_correspondence": "UNPROVEN"})
        for member in ("META-INF/MANIFEST.MF", "META-INF/AL2.0",
                       "META-INF/LGPL2.1", "META-INF/LICENSE"):
            data = archive.read(member)
            notices.append({"member": member, "bytes": len(data), "sha256": sha256(data)})
            if member != "META-INF/MANIFEST.MF":
                embedded_texts[member.split("/")[-1]] = (member, data)
    assert len(natives) == 25
    cached = {}
    for entry in read_json(REVIEW / "supplemental-fetch.json")["records"]:
        if entry["repo"] == REPO and entry["kind"] == "source":
            assert entry["url"].startswith(RAW)
            cached[entry["url"][len(RAW):]] = entry

    tree_index, tree_evidence, excluded = {}, None, []
    if args.tree:
        tree_bytes = args.tree.read_bytes()
        tree = json.loads(tree_bytes)
        assert tree.get("truncated") is False, "Refuse truncated or unspecified tree"
        assert isinstance(tree.get("tree"), list)
        commit_path = args.tree.parent / "commit.json"
        commit_bytes = commit_path.read_bytes()
        commit = json.loads(commit_bytes)
        assert commit["sha"] == COMMIT and commit["tree"]["sha"] == tree["sha"]
        acquisition_path = args.tree.parent.parent / "acquisition.json"
        acquisition = read_json(acquisition_path)
        bindings = []
        for source_path, data, expected_url in (
            (commit_path, commit_bytes, f"https://api.github.com/repos/{REPO}/git/commits/{COMMIT}"),
            (args.tree, tree_bytes, f"https://api.github.com/repos/{REPO}/git/trees/{tree['sha']}?recursive=1"),
        ):
            relative = source_path.relative_to(acquisition_path.parent).as_posix()
            record = next(r for r in acquisition["records"] if r["path"] == relative)
            assert record["url"] == expected_url and record["final_url"] == expected_url
            assert record["http_status"] == 200 and record["bytes"] == len(data)
            assert record["sha256"] == sha256(data)
            bindings.append({"path": source_path.as_posix(), "url": expected_url,
                             "sha256": sha256(data), "bytes": len(data)})
        for entry in tree["tree"]:
            path = entry["path"]
            assert not path.startswith("/") and ".." not in Path(path).parts
            if entry["type"] == "blob":
                assert len(entry["sha"]) == 40 and isinstance(entry.get("size"), int)
                tree_index[path] = entry
            elif entry["type"] == "commit" and source_selected(path):
                raise ValueError(f"Submodule input requires separate pinned manifest: {path}")
        assert tree_index["dist/jna.jar"]["sha"] == upstream_jar["sha"]
        tree_evidence = {"path": args.tree.as_posix(), "url": bindings[1]["url"],
                         "response_sha256": sha256(tree_bytes), "bytes": len(tree_bytes),
                         "root_tree_sha1": tree.get("sha"), "truncated": False,
                         "commit_to_tree_verified": True,
                         "acquisition_manifest": acquisition_path.as_posix(),
                         "acquisition_manifest_sha256": sha256(acquisition_path.read_bytes()),
                         "verified_response_bindings": bindings}
        paths = set()
        for path, entry in tree_index.items():
            if source_selected(path):
                if Path(path).suffix.lower() in BINARY_SUFFIXES:
                    excluded.append({"path": path, "git_blob_sha1": entry["sha"],
                                     "bytes": entry["size"], "reason": "binary_or_archive_not_fetched"})
                else:
                    assert entry["mode"] in ("100644", "100755"), (path, entry["mode"])
                    paths.add(path)
    else:
        paths = (ROOT_INPUTS | {"native/" + p for p in DIRECT_NATIVE} |
                 {"native/libffi/" + p for p in LIBFFI_WITNESSES} |
                 {"src/com/sun/jna/Function.java", "src/com/sun/jna/Native.java",
                  "src/com/sun/jna/win32/DLLCallback.java"})
    files = [file_record(p, tree_index.get(p), cached.get(p)) for p in sorted(paths)]
    for record in files:
        if record["path"] in embedded_texts and tree_index:
            member, data = embedded_texts[record["path"]]
            assert blob_hash(data) == record["expected_git_blob_sha1"]
            assert len(data) == record["expected_bytes"]
            record.update(cached_archive_member={"archive": artifact["binary"]["path"],
                                                 "member": member},
                          sha256=sha256(data), verification="cached_archive_text_matches_tree")
    known = [f for f in files if f["expected_bytes"] is not None]
    packaging = []
    for path in sorted(BUILD_BINARY_INPUTS | {n["upstream_packaging_input"] for n in natives}):
        meta = tree_index.get(path)
        packaging.append({"repo": REPO, "commit": COMMIT, "path": path,
                          "fetch": False, "kind": "prebuilt_native_packaging_input" if path.startswith("lib/native/") else "build_tool_binary_requires_separate_source_license_audit",
                          "git_blob_sha1": meta["sha"] if meta else None,
                          "bytes": meta["size"] if meta else None})
    manifest = {
        "schema": "expertauth-jna-native-source-fetch-manifest-v1",
        "work_package": "WP-002", "coordinate": artifact["coordinate"],
        "repo": REPO, "commit": COMMIT, "release_tag": "5.8.0",
        "status": "PARTIAL_SOURCE_CORRESPONDENCE_UNPROVEN",
        "foundation_status_changed": False, "license_approval": False,
        "source_inventory_expanded_from_complete_tree": bool(args.tree),
        "tree_evidence": tree_evidence,
        "metadata_request": {"url": TREE_URL, "reject_truncated": True},
        "selection": {"entire_subtrees": ["native/", "ant-tools-src/"],
                      "patterns": ["src/**/*.java"], "root_files": sorted(ROOT_INPUTS),
                      "reason": "Conservative complete vendored libffi source/build/test closure; Java JNI generation and custom Ant tools; root licenses/build context. Platform toolchain closure is separate.",
                      "excluded": excluded},
        "acquisition_limits": {"max_files": 2000, "max_total_bytes": 20000000,
                               "max_file_bytes": 1000000, "archives_and_binaries": "forbidden",
                               "action_if_bound_exceeded": "Stop before fetching and report; do not silently shrink the source set.",
                               "executor": "Parent consolidated bounded acquisition; this script performs no network or build."},
        "files": files, "file_count": len(files), "metadata_verified_file_count": len(known),
        "known_total_source_bytes": sum(f["expected_bytes"] for f in known),
        "missing_blob_metadata_paths": [f["path"] for f in files if f["expected_bytes"] is None],
        "release_binary": {"path": artifact["binary"]["path"],
                           "bytes": len(jar_bytes), "sha256": sha256(jar_bytes),
                           "git_blob_sha1": blob_hash(jar_bytes), "upstream_path": "dist/jna.jar",
                           "release_byte_identity_verified": True,
                           "reproducible_source_build_verified": False},
        "native_members": natives, "exact_embedded_notice_members": notices,
        "binary_metadata_only_do_not_fetch": packaging,
        "source_jar": {"path": artifact["source"]["path"],
                       "sha256": artifact["source"]["sha256"],
                       "native_source_members": 0,
                       "limit": "Java source JAR does not provide native source/build closure."},
        "blockers": [
            "Generated JNI inputs and root Ant release transformation have not been reproduced.",
            "Exact historical compiler, linker, JDK/JNI headers, OS SDK/sysroot, autotools and build-tool dependencies are not locked.",
            "None of the 25 native artifacts has been rebuilt or tested in this work package.",
            "Static libffi/compiler-runtime inclusion and per-platform licensing exceptions require file-specific closure.",
            "Recorded source URLs/blob identities establish acquisition inputs, not native build correspondence or license approval.",
        ],
        "resources_created": {"containers": [], "images": [], "networks": [], "volumes": [], "runtime_changes": []},
    }
    if args.tree:
        assert len(files) <= manifest["acquisition_limits"]["max_files"]
        assert sum(f["expected_bytes"] for f in files) <= manifest["acquisition_limits"]["max_total_bytes"]
        assert max(f["expected_bytes"] for f in files) <= manifest["acquisition_limits"]["max_file_bytes"]
    (HERE / "fetch-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    if args.tree:
        minimal_paths = (ROOT_INPUTS | {"native/" + p for p in DIRECT_NATIVE if not p.startswith("testlib")} |
                         {"native/libffi/" + p for p in (
                             "LICENSE", "LICENSE-BUILDTOOLS", "configure.ac", "configure.host",
                             "Makefile.am", "autogen.sh", "acinclude.m4", "config.guess", "config.sub",
                             "msvcc.sh", "make_sunver.pl", "libtool-ldflags", "libtool-version",
                             "src/dlmalloc.c", "include/Makefile.am", "include/ffi.h.in",
                             "include/ffi_common.h", "include/ffi_cfi.h")})
        minimal_paths |= {p for p in paths if p.startswith("native/libffi/m4/")}
        candidate = [f for f in files if f["path"] in minimal_paths]
        pending = [f for f in candidate if not f.get("cached_source") and not f.get("cached_archive_member")]
        assert len(candidate) == len(minimal_paths), sorted(minimal_paths - {f["path"] for f in candidate})
        request = {"schema": "expertauth-jna-source-acquisition-request-v1",
                   "coordinate": artifact["coordinate"], "repo": REPO, "commit": COMMIT,
                   "status": "BOUNDED_TEXT_RESEARCH_INPUTS_ONLY",
                   "files": pending, "total_files": len(pending),
                   "total_bytes": sum(f["expected_bytes"] for f in pending),
                   "available_without_fetch": [f for f in candidate if f not in pending],
                   "full_source_inventory": "fetch-manifest.json",
                   "constraints": ["No binaries or archives; preserve exact bytes and verify size/Git blob SHA1.",
                                   "These build and exception witnesses do not discharge all source/build/license obligations.",
                                   "Do not fetch the entire vendored libffi tree in this bounded follow-up."]}
        assert request["total_bytes"] < 1000000
        (HERE / "acquisition-request.json").write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"files": len(files), "known_blob_metadata": len(known),
                      "known_source_bytes": manifest["known_total_source_bytes"],
                      "native_members_verified": len(natives), "source_rebuilds": 0,
                      "source_inventory_expanded_from_complete_tree": bool(args.tree),
                      "bounded_request_files": request["total_files"] if args.tree else None,
                      "bounded_request_bytes": request["total_bytes"] if args.tree else None}))


if __name__ == "__main__":
    main()
