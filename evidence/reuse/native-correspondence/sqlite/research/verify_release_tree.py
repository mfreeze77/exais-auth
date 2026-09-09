"""Bind retained SQLite members to a retained primary immutable Git commit/tree."""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import hashlib
import json

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent.parent
COMMIT = "5ac6b0d4bf42244f1d48b39af74e87ce7621cac6"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit-metadata", type=Path, required=True)
    parser.add_argument("--tree", type=Path, required=True)
    args = parser.parse_args()
    commit = json.loads(args.commit_metadata.read_text())
    tree = json.loads(args.tree.read_text())
    assert commit["sha"] == COMMIT, "Different immutable release commit"
    assert tree["sha"] == commit["tree"]["sha"] and tree["truncated"] is False, "Incomplete/unbound Git tree"
    nodes = {row["path"]: row for row in tree["tree"]}
    assert len(nodes) == len(tree["tree"]), "Duplicate Git paths"
    manifest_path = OUT / "manifest.json"
    before = manifest_path.read_bytes()
    manifest = json.loads(before)
    assert manifest["commit"] == COMMIT
    report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "scope": "Release Git-object identity, not compiled-source correspondence",
              "commit": COMMIT, "tree_sha1": tree["sha"], "commit_metadata_sha256": sha(args.commit_metadata),
              "tree_metadata_sha256": sha(args.tree), "inspection_script_sha256": sha(Path(__file__)),
              "native_rebuild_verified": False, "native_platform_tests_passed": False, "license_approved": False,
              "native_bindings": [], "cached_source_bindings": [], "notice_and_pom_bindings": []}
    cached = json.loads((OUT / "research/cached-members.json").read_text())
    for item in cached["archives"]["binary"]["members"]:
        if item["kind"] != "native_members":
            continue
        path = "src/main/resources/" + item["member"]
        obj = nodes.get(path)
        same = bool(obj and obj["type"] == "blob" and obj["sha"] == item["git_blob_sha1"] and obj["size"] == item["bytes"])
        report["native_bindings"].append({"member": item["member"], "member_sha256": item["sha256"], "member_bytes": item["bytes"],
                                          "calculated_git_blob_sha1": item["git_blob_sha1"], "release_git_path": path,
                                          "release_git_blob_sha1": obj.get("sha") if obj else None,
                                          "release_git_blob_bytes": obj.get("size") if obj else None,
                                          "exact_release_object_match": same,
                                          "embedded_sqlite_source_id_strings": item["embedded_sqlite_source_id_strings"]})
    for row in manifest["files"]:
        obj = nodes.get(row["path"])
        if obj and obj["type"] == "blob":
            row["git_blob_sha1"] = obj["sha"]
            row["git_tree_bytes"] = obj["size"]
            row["git_object_verification"] = "immutable-commit-tree-metadata-verified"
        else:
            row["git_object_verification"] = "path-not-present-as-blob-in-release-tree"
        if row["cached_source"]:
            local = row["cached_source"]
            same = bool(obj and obj["type"] == "blob" and obj["sha"] == local["git_blob_sha1_calculated"] and obj["size"] == local["bytes"])
            row["cached_source"]["exact_release_object_match"] = same
            report["cached_source_bindings"].append({"path": row["path"], "exact_release_object_match": same})
    for item in cached["archives"]["source"]["members"]:
        if item["kind"] not in ("notice_members", "build_members"):
            continue
        path = item["member"].rsplit("/", 1)[1]
        obj = nodes.get(path)
        report["notice_and_pom_bindings"].append({"member": item["member"], "path": path,
                                                "cached_git_blob_sha1": item["git_blob_sha1"],
                                                "release_git_blob_sha1": obj.get("sha") if obj else None,
                                                "exact_release_object_match": bool(obj and obj["sha"] == item["git_blob_sha1"] and obj["size"] == item["bytes"])})
    # Include any additional tracked JNI header facts, without copying headers or
    # treating an outer repository license as permission for third-party bytes.
    existing = {row["path"] for row in manifest["files"]}
    for path, obj in sorted(nodes.items()):
        if obj["type"] == "blob" and path.startswith("lib/inc_") and path not in existing:
            manifest["files"].append({"repository": "xerial/sqlite-jdbc", "commit": COMMIT, "path": path,
                                      "url": f"https://raw.githubusercontent.com/xerial/sqlite-jdbc/{COMMIT}/{path}",
                                      "purpose": "Additional tracked JNI input; precise terms and actual include selection require review",
                                      "git_blob_sha1": obj["sha"], "git_tree_bytes": obj["size"],
                                      "git_object_verification": "immutable-commit-tree-metadata-verified", "cached_source": None,
                                      "acquisition": "reference-and-research-only-pending-terms", "redistribution_approved": False})
    manifest["files"].sort(key=lambda row: row["path"])
    manifest["primary_git_tree_metadata"] = {"commit_sha1": COMMIT, "tree_sha1": tree["sha"],
                                              "commit_metadata_sha256": report["commit_metadata_sha256"],
                                              "tree_metadata_sha256": report["tree_metadata_sha256"],
                                              "commit_metadata_path": args.commit_metadata.resolve().relative_to(ROOT).as_posix(),
                                              "tree_metadata_path": args.tree.resolve().relative_to(ROOT).as_posix()}
    report["native_member_count"] = len(report["native_bindings"])
    report["native_release_object_bindings_verified"] = sum(row["exact_release_object_match"] for row in report["native_bindings"])
    report["cached_sources_verified"] = sum(row["exact_release_object_match"] for row in report["cached_source_bindings"])
    report["notice_and_pom_verified"] = sum(row["exact_release_object_match"] for row in report["notice_and_pom_bindings"])
    report["all23_native_release_objects_match"] = report["native_member_count"] == report["native_release_object_bindings_verified"] == 23
    report["all57_cached_sources_match"] = len(report["cached_source_bindings"]) == report["cached_sources_verified"] == 57
    previous = OUT / "research/manifest-before-git-verification.json"
    assert not previous.exists() and not (OUT / "research/release-bindings.json").exists(), "Preserve prior qualification evidence"
    previous.write_bytes(before)
    manifest_path.write_bytes((json.dumps(manifest, indent=2) + "\n").encode())
    report["resulting_manifest_sha256"] = sha(manifest_path)
    (OUT / "research/release-bindings.json").write_bytes((json.dumps(report, indent=2) + "\n").encode())
    print(json.dumps({key: report[key] for key in ("native_member_count", "native_release_object_bindings_verified", "cached_sources_verified", "notice_and_pom_verified", "all23_native_release_objects_match", "all57_cached_sources_match")}))
    return 0 if report["all23_native_release_objects_match"] and report["all57_cached_sources_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
