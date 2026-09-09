"""Bounded, nonexecuting source correspondence audit for Nodemailer 9.1.1."""
from __future__ import annotations

import argparse
import base64
import datetime
import gzip
import hashlib
import io
import json
import pathlib
import subprocess
import tarfile
import urllib.request

IMAGE = "python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36"
NAME = "expertauth-nodemailer-source-20260909-01"
LIMIT = 1024 * 1024
URL = "https://registry.npmjs.org/nodemailer/-/nodemailer-9.1.1.tgz"
META = ".cache/reuse-audit/80083bf5cac75c928c63c9d850912b88a106cfec6583d472192899e79ad9b372"


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def save(path, data):
    with path.open("xb") as stream:
        stream.write(data)


def save_json(path, data):
    save(path, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode())


def fetch(directory):
    request = strict_json((directory / "request.json").read_bytes())
    if request["url"] != URL or request["maximum_bytes"] != LIMIT:
        raise ValueError("unexpected acquisition request")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise ValueError("redirect refused")
    report = {"started_at": now(), "url": URL, "maximum_bytes": LIMIT, "passed": False}
    try:
        opener = urllib.request.build_opener(NoRedirect())
        req = urllib.request.Request(URL, headers={"Accept-Encoding": "identity"})
        with opener.open(req, timeout=20) as response:
            if response.status != 200 or response.geturl() != URL:
                raise ValueError("unexpected response")
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) > LIMIT:
                raise ValueError("declared size exceeds limit")
            data = response.read(LIMIT + 1)
            if len(data) > LIMIT:
                raise ValueError("body exceeds limit")
            if declared is not None and len(data) != int(declared):
                raise ValueError("truncated response")
            save(directory / "nodemailer-9.1.1.tgz", data)
            integrity = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
            if integrity != request["integrity"]:
                raise ValueError("locked integrity mismatch")
            report.update(passed=True, bytes=len(data), sha256=sha(data),
                          integrity=integrity, http_status=response.status,
                          final_url=response.geturl(), declared_content_length=declared)
    except Exception as exc:
        report["error_type"] = type(exc).__name__
        raise
    finally:
        report["finished_at"] = now()
        save_json(directory / "fetch.json", report)


def docker(args, timeout=20):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("Docker operation failed: " + args[0])
    return result.stdout.strip()


def acquire(root, output):
    script = pathlib.Path(__file__).resolve()
    before = docker(["ps", "-a", "--no-trunc", "--format", "{{.ID}} {{.Names}}"])
    if any(line.split()[-1] == NAME for line in before.splitlines()):
        raise ValueError("owned resource name already exists")
    image = strict_json(docker(["image", "inspect", IMAGE]))[0]
    acquisition = output / "acquisition"
    command = ["run", "--rm", "--pull=never", "--name", NAME,
               "--label", "org.expertauth.project=expert-auth",
               "--label", "org.expertauth.purpose=nodemailer-source-correspondence",
               "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
               "--memory=128m", "--cpus=0.5", "--pids-limit=64",
               "--cidfile", str(acquisition / "container.cid"),
               "--mount", f"type=bind,source={script},target=/audit.py,readonly",
               "--mount", f"type=bind,source={acquisition},target=/out",
               "--entrypoint", "python", IMAGE, "-B", "/audit.py", "--fetch", "/out"]
    lifecycle = {"name": NAME, "image": IMAGE, "image_id": image["Id"],
                 "image_bytes": image["Size"], "started_at": now(),
                 "command": ["docker", *command], "preexisting_container_count": len(before.splitlines()),
                 "new_images_networks_or_volumes": False}
    try:
        result = subprocess.run(["docker", *command], capture_output=True, text=True, timeout=50)
        lifecycle["exit_code"] = result.returncode
        lifecycle["stdout"] = result.stdout
        lifecycle["stderr"] = result.stderr
        if result.returncode:
            raise RuntimeError("acquisition container failed")
    except Exception as exc:
        lifecycle["error_type"] = type(exc).__name__
        raise
    finally:
        cid = acquisition / "container.cid"
        lifecycle["container_id"] = cid.read_text().strip() if cid.exists() else None
        remaining = docker(["ps", "-a", "--no-trunc", "--format", "{{.ID}} {{.Names}}"])
        owned = [line.split()[0] for line in remaining.splitlines() if line.split()[-1] == NAME]
        lifecycle["fallback_removal_required"] = bool(owned)
        for identifier in owned:
            info = strict_json(docker(["inspect", identifier]))[0]
            labels = info["Config"]["Labels"]
            if labels.get("org.expertauth.project") != "expert-auth" or labels.get("org.expertauth.purpose") != "nodemailer-source-correspondence":
                raise RuntimeError("cleanup ownership mismatch")
            docker(["rm", "-f", identifier])
        after = docker(["ps", "-a", "--no-trunc", "--format", "{{.ID}} {{.Names}}"])
        lifecycle["container_absent_after_cleanup"] = not any(line.split()[-1] == NAME for line in after.splitlines())
        lifecycle["finished_at"] = now()
        save_json(acquisition / "lifecycle.json", lifecycle)
        if not lifecycle["container_absent_after_cleanup"]:
            raise RuntimeError("owned container remains")


def audit(root, acquire_requested):
    output = root / "evidence/reuse/nodemailer-9.1.1-source-correspondence"
    destination = root / "reuse/nodemailer-9.1.1-source-correspondence.json"
    if destination.exists():
        raise ValueError("report already exists")
    output.mkdir(parents=True, exist_ok=True)
    acquisition = output / "acquisition"
    acquisition.mkdir(exist_ok=True)
    lock_path = root / "examples/node-react/package-lock.json"
    historical_path = root / "reuse/password-reset-components.json"
    lock_bytes = lock_path.read_bytes()
    historical_bytes = historical_path.read_bytes()
    lock = strict_json(lock_bytes)["packages"]["node_modules/nodemailer"]
    metadata_bytes = (root / (META + ".body")).read_bytes()
    provenance_bytes = (root / (META + ".json")).read_bytes()
    metadata = strict_json(metadata_bytes)
    provenance = strict_json(provenance_bytes)
    if sha(metadata_bytes) != provenance["sha256"] or provenance["url"] != "https://registry.npmjs.org/nodemailer/9.1.1":
        raise ValueError("cached primary metadata provenance mismatch")
    if lock["version"] != "9.1.1" or metadata["version"] != "9.1.1" or metadata["name"] != "nodemailer":
        raise ValueError("unexpected package version")
    if lock["resolved"] != URL or metadata["dist"]["tarball"] != URL or lock["integrity"] != metadata["dist"]["integrity"]:
        raise ValueError("primary metadata disagrees with current lock")
    if acquire_requested:
        save_json(acquisition / "request.json", {"url": URL, "integrity": lock["integrity"], "maximum_bytes": LIMIT})
        acquire(root, output)
    artifact = acquisition / "nodemailer-9.1.1.tgz"
    if artifact.stat().st_size > LIMIT:
        raise ValueError("cached archive exceeds bound")
    compressed = artifact.read_bytes()
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(compressed).digest()).decode()
    if integrity != lock["integrity"] or hashlib.sha1(compressed).hexdigest() != metadata["dist"]["shasum"]:
        raise ValueError("artifact digest mismatch")
    with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
        expanded = stream.read(2 * LIMIT + 1)
    if len(expanded) > 2 * LIMIT:
        raise ValueError("expanded archive exceeds bound")
    members = {}
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        seen = set()
        for member in archive:
            path = pathlib.PurePosixPath(member.name)
            if len(seen) >= 128 or member.name in seen or member.name != path.as_posix() or path.is_absolute() or ".." in path.parts or "\\" in member.name or path.parts[0] != "package":
                raise ValueError("unsafe or duplicate archive path")
            seen.add(member.name)
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("nonregular archive member")
            body = archive.extractfile(member).read()
            if len(body) != member.size:
                raise ValueError("truncated archive member")
            members[member.name] = body
    if len(members) != metadata["dist"]["fileCount"] or sum(map(len, members.values())) != metadata["dist"]["unpackedSize"]:
        raise ValueError("archive inventory disagrees with primary metadata")
    historical = strict_json(historical_bytes)
    component = next(item for item in historical["installed_reused_components"] if item["name"] == "nodemailer")
    if component["installed_version"] != "9.1.1" or len(component["files"]) != 6:
        raise ValueError("unexpected historical component scope")
    comparisons = []
    for record in component["files"]:
        path = root / record["path"]
        if path.is_symlink() or not path.is_file():
            raise ValueError("installed source not regular")
        installed = path.read_bytes()
        member = "package/" + record["package_relative_path"]
        original = members[member]
        if installed != original or sha(installed) != record["sha256"]:
            raise ValueError("installed or historical source mismatch")
        comparisons.append({"installed_path": record["path"], "archive_member": member,
                            "bytes": len(installed), "sha256": sha(installed),
                            "original_member_sha256": sha(original), "exact_bytes_match": True,
                            "historical_report_hash_matches": True, "role": record["role"]})
    package_root = root / "examples/node-react/node_modules/nodemailer"
    for path in ["LICENSE", "package.json"]:
        installed_path = package_root / path
        if installed_path.is_symlink() or installed_path.read_bytes() != members["package/" + path]:
            raise ValueError("installed metadata or notice mismatch")
    package = strict_json(members["package/package.json"])
    if package["version"] != "9.1.1" or package["license"] != "MIT-0" or metadata["license"] != "MIT-0":
        raise ValueError("unexpected license declaration")
    inventory = [{"archive_member": name, "bytes": len(body), "sha256": sha(body)} for name, body in sorted(members.items())]
    save_json(output / "archive-members.json", inventory)
    save(output / "LICENSE", members["package/LICENSE"])
    save(output / "package.json", members["package/package.json"])
    save(output / "registry-metadata.json", metadata_bytes)
    save(output / "registry-provenance.json", provenance_bytes)
    if lock_path.read_bytes() != lock_bytes or historical_path.read_bytes() != historical_bytes:
        raise ValueError("input changed during audit")
    def descriptor(path):
        data = path.read_bytes()
        return {"path": path.relative_to(root).as_posix(), "bytes": len(data), "sha256": sha(data)}
    report = {
        "schema": "expertauth.nodemailer-source-correspondence.v1",
        "created_at": now(), "status": "SIX_INSTALLED_SOURCE_FILES_MATCH_LOCKED_ORIGINAL_NPM_ARTIFACT",
        "passed": True, "package": "nodemailer", "version": "9.1.1",
        "scope": "Six files from the historical password reset component report, plus package metadata and MIT-0 notice; all archive members inventoried without executing or installing package code",
        "lock": descriptor(lock_path), "historical_report_unchanged": descriptor(historical_path),
        "artifact": {**descriptor(artifact), "url": URL, "integrity": integrity,
                     "sha1": hashlib.sha1(compressed).hexdigest(), "maximum_download_bytes": LIMIT,
                     "archive_file_count": len(members), "unpacked_file_bytes": sum(map(len, members.values()))},
        "primary_metadata": descriptor(output / "registry-metadata.json"),
        "primary_metadata_provenance": descriptor(output / "registry-provenance.json"),
        "registry_reported_git_head": metadata["gitHead"],
        "git_head_source_tree_or_signature_verified": False,
        "archive_inventory": descriptor(output / "archive-members.json"),
        "files": comparisons,
        "license": {**descriptor(output / "LICENSE"), "declared_spdx": "MIT-0",
                    "archive_member": "package/LICENSE", "installed_path": "examples/node-react/node_modules/nodemailer/LICENSE",
                    "installed_bytes_match_original": True},
        "package_metadata": {**descriptor(output / "package.json"), "archive_member": "package/package.json",
                             "installed_bytes_match_original": True},
        "acquisition": descriptor(acquisition / "fetch.json"),
        "resource_lifecycle": descriptor(acquisition / "lifecycle.json"),
        "tool": descriptor(pathlib.Path(__file__).resolve()),
        "limits": ["Only the six selected installed source files and LICENSE/package.json were compared; full installed package correspondence is separate",
                   "Parent must bind rebuilt runtime image bytes to this artifact; no new runtime image qualification here",
                   "Nodemailer 9.1.1 remains an explicit override outside the original SDK declared ^8.0.2 range",
                   "No new vulnerability scan, complete transitive license audit, or legal approval",
                   "Full 265 requirements, 205 API entries, foundation selection, native/provider tests and independent security review remain unqualified"],
        "source_changes": [], "installed_dependency_changes": [], "license_approval": False,
        "runtime_image_correspondence_qualified": False,
    }
    save_json(destination, report)
    print(json.dumps({"passed": True, "report": destination.relative_to(root).as_posix(),
                      "report_sha256": sha(destination.read_bytes()), "matched_source_files": len(comparisons),
                      "archive_bytes": len(compressed), "container_absent": strict_json((acquisition / "lifecycle.json").read_bytes())["container_absent_after_cleanup"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", type=pathlib.Path)
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument("--acquire", action="store_true")
    args = parser.parse_args()
    if args.fetch:
        fetch(args.fetch)
    else:
        audit(args.repo.resolve(), args.acquire)


if __name__ == "__main__":
    main()
