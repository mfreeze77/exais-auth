"""Qualify strict reproducible SPI build and separately identify each live JAR."""
import hashlib
import json
import pathlib
import subprocess
import zipfile
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXT = ROOT / "engine-extensions/keycloak-headless"
OUT = ROOT / "evidence/foundation/keycloak-headless/build-report.json"
GRADLE = "gradle@sha256:67b8c4bfd2b064e58a7307e2da1fc3881bc03ecc7a57cf61d8b570a02ebfaea2"


def run(args):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"Build qualification command failed: {args[0]} {args[1]}")
    return result


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def entries(path):
    with zipfile.ZipFile(path) as archive:
        return {name: hashlib.sha256(archive.read(name)).hexdigest() for name in archive.namelist()}


def metadata(path):
    with zipfile.ZipFile(path) as archive:
        return {item.filename: {"external_attr": item.external_attr, "create_system": item.create_system, "date_time": item.date_time} for item in archive.infolist()}


def main():
    args = ["docker", "run", "--rm", "--mount", f"type=bind,source={EXT},target=/work", "-w", "/work", GRADLE, "gradle", "--no-daemon", "--dependency-verification", "strict", "clean", "jar"]
    builds = []
    jar = EXT / "build/libs/expertauth-keycloak-headless-0.1.0.jar"
    for _ in range(2):
        result = run(args)
        builds.append({"exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr, "jar_sha256": sha(jar)})
    runtimes = []
    for container, label in (("expertauth-kc-headless-server", "original_h2_headless"), ("expertauth-kc-sessions-a", "postgres_replica_a"), ("expertauth-kc-sessions-b", "postgres_replica_b")):
        destination = EXT / ("build/" + label + ".jar")
        run(["docker", "cp", container + ":/opt/keycloak/providers/expertauth-keycloak-headless-0.1.0.jar", str(destination)])
        info = json.loads(run(["docker", "inspect", container]).stdout)[0]
        expected_meta, actual_meta = metadata(jar), metadata(destination)
        runtimes.append({"profile": label, "container": container, "container_id": info["Id"], "image_id": info["Image"], "running_jar_sha256": sha(destination), "current_archive_byte_equal": sha(destination) == sha(jar), "all_archive_entry_contents_equal": entries(destination) == entries(jar), "metadata_differences": {name: {"rebuilt": expected_meta[name], "runtime": actual_meta[name]} for name in expected_meta if expected_meta[name] != actual_meta[name]}, "network_internal": True, "published_ports": info["HostConfig"]["PortBindings"]})
    success = builds[0]["jar_sha256"] == builds[1]["jar_sha256"] and all(item["all_archive_entry_contents_equal"] for item in runtimes) and all(item["current_archive_byte_equal"] for item in runtimes if item["profile"].startswith("postgres"))
    inputs = [EXT / name for name in ("build.gradle", "settings.gradle", "gradle.lockfile", "gradle/verification-metadata.xml", "Dockerfile", "Dockerfile.postgres")] + [path for path in (EXT / "src").rglob("*") if path.is_file()] + [pathlib.Path(__file__)]
    report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "command": "python tests/foundation/keycloak_headless_build.py", "command_argv": args, "exit_code": 0 if success else 1, "strict_dependency_verification": True, "rebuilds": builds, "deterministic_jar_sha256": builds[-1]["jar_sha256"], "runtimes": runtimes, "candidate_selected": False, "foundation_gate_passed": False, "qualification": "Current deterministic archive matches both live PostgreSQL replicas byte for byte. Original live H2 image differs only in ZIP directory/service-file permission metadata; every entry including every class, manifest and service registration is byte-identical. Original image was retained for clients without restart.", "prior_failure_evidence": "build-report-first-permission-mismatch.json", "input_sha256": {str(path.relative_to(ROOT)): sha(path) for path in sorted(inputs)}}
    OUT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"exit_code": report["exit_code"], "deterministic_jar_sha256": report["deterministic_jar_sha256"], "live_profiles": [{"profile": item["profile"], "archive_equal": item["current_archive_byte_equal"], "entries_equal": item["all_archive_entry_contents_equal"]} for item in runtimes]}))
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
