"""Author SQLite source acquisition facts from retained metadata; no network or Docker."""
from pathlib import Path
import hashlib
import json
import zipfile

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent.parent
COMMIT = "5ac6b0d4bf42244f1d48b39af74e87ce7621cac6"
REPO = "xerial/sqlite-jdbc"
SOURCE = ROOT / ".cache/runtime-source-jars/org.xerial.sqlite-jdbc-3.45.1.0-sources.jar"


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def main():
    paths = {
        "Makefile": "amalgamation changes, compiler flags and per-platform build recipes",
        "Makefile.common": "JNI include selection, compiler/linker/strip flags and source filename encoding",
        "VERSION": "SQLite source version",
        "amalgamation_version.sh": "SQLite amalgamation filename generator",
        "pom.xml": "JVM compilation, packaging, build-time dependencies and notices",
        "LICENSE": "wrapper root Apache notice",
        "LICENSE.zentus": "Zentus BSD-style notice",
        ".github/workflows/build-native.yml": "native target matrix and build artifact workflow",
        ".github/workflows/ci.yml": "release and JVM/native test workflow context",
        "src/main/ext/extension-functions.c": "appended extension implementation and origin comments; permission chain unresolved",
        "src/main/java/org/sqlite/core/NativeDB.c": "JNI glue with its distinct ISC-style permission notice",
        "lib/inc_linux/jni_md.h": "JNI machine types; exact provenance/terms require review",
        "lib/inc_mac/jni_md.h": "JNI machine types with Sun proprietary marking; no redistribution approval",
        "lib/inc_win/jni.h": "JNI interface with Sun proprietary marking and Netscape origin; no redistribution approval",
        "lib/inc_win/jni_md.h": "JNI machine types with Sun proprietary marking; no redistribution approval",
    }
    for suffix in ("linux_x86", "linux_x86_64", "alpine-linux_x86", "alpine-linux_x86_64", "rcodesign"):
        paths["docker/Dockerfile." + suffix] = "native build/signing image recipe; image/toolchain digest not pinned by recipe"
    for suffix in ("android-arm", "android-arm64", "android-x86", "android-x86_64", "arm64-lts", "armv5", "armv6-lts", "armv7a-lts", "musl-arm64", "ppc64", "windows-arm64", "windows-armv7", "windows-x64", "windows-x86"):
        paths["docker/dockcross-" + suffix] = "platform cross-compiler wrapper; resolve exact historical OCI/toolchain source separately"
    paths["docker/updatescripts.sh"] = "origin/update controls for generated dockcross wrappers"
    cached = {}
    with zipfile.ZipFile(SOURCE) as archive:
        for name in archive.namelist():
            if name.endswith(".java") or name == "org/sqlite/core/NativeDB.c":
                path = "src/main/java/" + name
                paths.setdefault(path, "Java source used by JNI/header generation; retain full source closure already cached")
                raw = archive.read(name)
                cached[path] = {"archive": SOURCE.relative_to(ROOT).as_posix(), "member": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "git_blob_sha1_calculated": blob(raw)}
    files = []
    for path, role in sorted(paths.items()):
        files.append({"repository": REPO, "commit": COMMIT, "path": path,
                      "url": f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/{path}",
                      "purpose": role, "git_blob_sha1": None, "git_tree_bytes": None,
                      "git_object_verification": "awaiting-retained-primary-git-tree-metadata",
                      "cached_source": cached.get(path),
                      "acquisition": "reuse-cached-member-after-Git-object-comparison" if path in cached else "reference-and-research-only-pending-terms" if path.startswith("lib/") or path == "src/main/ext/extension-functions.c" else "bounded-text-fetch",
                      "redistribution_approved": False})
    report = {
        "schema": "expertauth-sqlite-native-source-correspondence-v1",
        "coordinate": "org.xerial:sqlite-jdbc:3.45.1.0",
        "repository": REPO, "release_tag": "3.45.1.0", "commit": COMMIT,
        "release_reference": "https://github.com/xerial/sqlite-jdbc/releases/tag/3.45.1.0",
        "commit_reference": f"https://github.com/{REPO}/commit/{COMMIT}",
        "primary_git_tree_metadata": None,
        "source_acquisition_complete": False, "native_rebuild_verified": False,
        "native_platform_tests_passed": False, "license_approved": False, "foundation_passed": False,
        "scope": "Bounded missing source/build identification and retained-byte release binding; no new archive/native binary download or native execution",
        "amalgamation": {
            "version": "3.45.1", "encoded_filename": "sqlite-amalgamation-3450100.zip",
            "url": "https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip",
            "sqlite_source_id": "2024-01-30 16:01:20 e876e51a0ed5c5b3126f52e532044363a014bc594cfefa87ffb5b82257cc467a",
            "sqlite_fossil_revision": "e876e51a0ed5c5b3126f52e532044363a014bc594cfefa87ffb5b82257cc467a",
            "published_sqlite3_c_sha3_256": "0474604df9e1b69a5544295dd046aad954749279780d557da80f44b958100295",
            "release_reference": "https://www.sqlite.org/releaselog/3_45_1.html",
            "archive_sha256": None, "archive_hash_status": "not-downloaded-or-hashed; pinned-Makefile-has-no-digest",
            "sqlite3_c_hash_verified_against_acquired_bytes": False,
            "required_archive_members": ["sqlite-amalgamation-3450100/sqlite3.c", "sqlite-amalgamation-3450100/sqlite3.h", "sqlite-amalgamation-3450100/sqlite3ext.h"],
            "shell_c_needed_for_this_JNI_recipe": False,
            "modifications_reference": f"https://github.com/{REPO}/blob/{COMMIT}/Makefile#L60-L104",
            "modifications": ["initialize sqlite3_api in generated sqlite3ext.h", "register appended extension functions during successful database open", "append JDBC_EXTENSIONS compile-option marker", "append all src/main/ext C sources before compilation"],
        },
        "files": files,
        "blocked": [
            "Exact ZIP SHA256 not yet measured; published sqlite3.c SHA3 is not an archive hash",
            "Sun-marked JNI headers and extension-function permission/origin chain require resolution before approved source distribution",
            "Historical per-platform compiler, linker, sysroot, OCI and code-signing identities are not fully pinned",
            "Static libgcc/compiler runtime inclusion, exact source and applicable notices/exceptions remain unverified",
            "All23 native recompilation/binary correspondence and native-platform execution tests remain unperformed",
        ],
    }
    (OUT / "manifest.json").write_bytes((json.dumps(report, indent=2) + "\n").encode())
    print(json.dumps({"manifest": "evidence/reuse/native-correspondence/sqlite/manifest.json", "files": len(files), "cached_sources": len(cached), "bounded_fetch_candidates": sum(row["acquisition"] == "bounded-text-fetch" for row in files)}))


if __name__ == "__main__":
    main()
