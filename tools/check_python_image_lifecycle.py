"""Exercise the actual image helper's source-drift rollback in an isolated copy.

Uses a distinct config-only image derived from the pinned existing image, the
private Core/PostgreSQL and the real 19-case HTTP probe. This proves image-tag
and source-stability rollback, not a complete source/dependency rebuild.
No download, database restart, production change or global prune. Run only in
the coordinated exclusive Python-image lifecycle slot.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
TAG = "expertauth-python-app:0.1.0"
PROTECTED = "sha256:7a4bb6dcfd634a98f603d65bc2c1219fef5b3a46a00be705631201c4f78802f1"
INPUTS = ["tools/refresh_python_image.py", "tools/run_sdk_session_faults.py", "examples/python/app.py",
          "examples/python/Dockerfile", "examples/python/.dockerignore", "examples/python/requirements.lock",
          "tests/clients/python_probe.py"]
PRESERVED_CONTAINERS = ("expertauth-oss-core-a", "expertauth-oss-postgres")
NETWORK = "expertauth-oss-proof"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def docker(*args, check=True):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8", timeout=40)
    if check and result.returncode:
        raise RuntimeError("Docker operation failed: " + " ".join(args[:2]))
    return result


def inspect(kind, name, required=True):
    result = docker(kind, "inspect", name, check=False)
    if result.returncode:
        require(not required, "Required Docker object absent: " + name)
        return None
    return json.loads(result.stdout)[0]


def inventory():
    return {kind: sorted(set(docker(*args).stdout.splitlines())) for kind, args in {
        "containers": ("ps", "-aq", "--no-trunc"), "images": ("image", "ls", "-q", "--no-trunc"),
        "volumes": ("volume", "ls", "-q"), "networks": ("network", "ls", "-q", "--no-trunc")}.items()}


def preserved_state():
    result = {}
    for name in PRESERVED_CONTAINERS:
        value = inspect("container", name)
        require(value["State"]["Running"], "Preserved private service is not running")
        require(not value["HostConfig"]["PortBindings"], "Preserved service unexpectedly publishes ports")
        result[name] = {"id": value["Id"], "image": value["Image"], "started_at": value["State"]["StartedAt"],
                        "mounts": [{key: mount.get(key) for key in ("Type", "Name", "Source", "Destination", "RW")} for mount in value["Mounts"]]}
    return result


def json_bytes(value):
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True, help="New evidence run name; requires an exclusive coordinated execution slot")
    args = parser.parse_args()
    require(args.name.isascii() and args.name and all(char.isalnum() or char in "-_" for char in args.name), "Invalid evidence name")
    output = ROOT / "evidence/operations/python-image-lifecycle" / args.name
    require(not output.exists(), "Preserve existing lifecycle evidence")
    protected = inspect("image", TAG)
    require(protected["Id"] == PROTECTED, "Protected Python tag differs; do not build or retire anything")
    require(inspect("network", NETWORK)["Internal"], "Expected existing private internal network")
    busy = docker("ps", "-aq", "--filter", "label=org.expertauth.purpose=python-image-proof").stdout.strip()
    require(not busy, "Another Python image qualification is active")
    before_state = preserved_state()
    before = inventory()
    original_hashes = {name: sha(ROOT / name) for name in INPUTS}
    output.mkdir(parents=True)
    run_id = uuid.uuid4().hex
    anchor = "expertauth-python-lifecycle-rollback:" + run_id
    scratch_base = (ROOT / ".runtime/python-image-lifecycle").resolve()
    scratch_base.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="source-drift-", dir=scratch_base)).resolve()
    require(scratch.parent == scratch_base and scratch.is_relative_to((ROOT / ".runtime").resolve()), "Scratch escaped ignored task directory")
    (scratch / ".ownership").write_text(run_id, encoding="utf-8")
    report = {"schema": "expertauth-real-python-image-source-drift-v1", "started": datetime.now(timezone.utc).isoformat(),
              "protected_tag": TAG, "protected_image": PROTECTED, "source_input_sha256": original_hashes,
              "tool_sha256": sha(Path(__file__)), "build_network": "none", "build_pull": False,
              "foundation_passed": False, "source_drift_isolated": True, "errors": [], "checks": {},
              "fallback_actions": [], "before_service_state": before_state, "mocked_helper": False,
              "mocked_core_or_http": False, "private_env_packaged": False,
              "fixture": "Config-only image with unique LABEL inheriting the exact protected image through an identity-checked local tag",
              "full_source_build_qualified": False}
    worker = None
    helper_report = None
    candidate = None
    app_cid = None
    secret_values = []
    anchored = False

    def redact(text):
        for value in secret_values:
            if value:
                text = text.replace(value, "[REDACTED]")
        return text

    def check(name, passed):
        report["checks"][name] = bool(passed)

    try:
        for name in INPUTS:
            target = scratch / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
            saved = output / "input-copy" / name
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(target, saved)
            require(sha(target) == original_hashes[name], "Input changed during isolated copy")
        changed = output / "changed-inputs"
        changed.mkdir()
        fixture = scratch / "examples/python/Dockerfile"
        fixture.write_bytes(("FROM " + anchor + "\nLABEL org.expertauth.lifecycle.fixture=\"" + run_id + "\"\n").encode())
        shutil.copyfile(fixture, changed / "Dockerfile")
        report["isolated_build_inputs"] = {name: sha(scratch / name) for name in INPUTS}
        require([name for name in INPUTS if report["isolated_build_inputs"][name] != original_hashes[name]] == ["examples/python/Dockerfile"], "Unexpected prebuild input mutation")
        private_env = scratch / ".runtime/oss-core/runtime.env"
        private_env.parent.mkdir(parents=True)
        env_raw = (ROOT / ".runtime/oss-core/runtime.env").read_bytes()
        values = dict(line.split("=", 1) for line in env_raw.decode().splitlines() if "=" in line)
        secret_values = [values.get("EXPERTAUTH_CORE_API_KEY", ""), values.get("POSTGRES_PASSWORD", "")]
        require(bool(secret_values[0]), "Private local Core key missing")
        private_env.write_bytes(env_raw)
        require(inspect("image", anchor, required=False) is None, "Protection tag already exists")
        docker("image", "tag", PROTECTED, anchor)
        anchored = True
        require(inspect("image", anchor)["Id"] == PROTECTED, "Protection tag points to another image")
        print("Lifecycle: exact helper copied; protected prior image; building isolated config-only LABEL fixture", flush=True)
        stdout_path = scratch / "helper-output.log"
        helper_name = "source-drift"
        helper_output = scratch / "evidence/operations/python-readiness" / helper_name
        with stdout_path.open("wb") as transcript:
            worker = subprocess.Popen([sys.executable, str(scratch / "tools/refresh_python_image.py"), "--name", helper_name],
                                      cwd=scratch, stdout=transcript, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 300
            injected = False
            while worker.poll() is None and time.monotonic() < deadline:
                if not injected:
                    paths = list((scratch / ".runtime/python-image-refresh").glob("run-*/app.cid"))
                    if paths:
                        require(len(paths) == 1 and paths[0].resolve().parent.parent == (scratch / ".runtime/python-image-refresh").resolve(), "Unexpected app CID path")
                        cid = paths[0].read_text().strip()
                        if len(cid) == 64 and all(char in "0123456789abcdef" for char in cid):
                            app_cid = cid
                            ignore = scratch / "examples/python/.dockerignore"
                            before_ignore = sha(ignore)
                            ignore.write_bytes(ignore.read_bytes() + ("\n# Isolated concurrent source drift " + run_id + "\n").encode())
                            shutil.copyfile(ignore, changed / "dockerignore-after-drift.txt")
                            report["injected_drift"] = {"after_app_cid_appeared": cid, "timestamp": datetime.now(timezone.utc).isoformat(),
                                                        "path": "examples/python/.dockerignore", "before_sha256": before_ignore, "after_sha256": sha(ignore)}
                            state = inspect("container", cid)
                            require(state["Config"].get("Labels", {}).get("org.expertauth.purpose") == "python-image-proof", "App CID ownership differs")
                            candidate = state["Image"]
                            require(candidate != PROTECTED, "Unique LABEL did not produce a distinct candidate image")
                            candidate_image = inspect("image", candidate)
                            report["candidate_rootfs_layers"] = candidate_image["RootFS"]["Layers"]
                            report["protected_rootfs_layers"] = protected["RootFS"]["Layers"]
                            require(candidate_image["RootFS"]["Layers"] == protected["RootFS"]["Layers"], "Config-only fixture changed filesystem layers")
                            require(candidate_image["Config"]["Cmd"] == protected["Config"]["Cmd"] and candidate_image["Config"]["User"] == protected["Config"]["User"], "Config-only fixture changed inherited runtime command/user")
                            report["observed_candidate_image"] = candidate
                            injected = True
                            print("Lifecycle: app CID observed after build; isolated .dockerignore changed; allowing real 19-case regression", flush=True)
                time.sleep(0.025)
            if worker.poll() is None:
                worker.terminate()
                worker.wait(timeout=15)
                raise RuntimeError("Bounded helper lifecycle timed out")
        report["helper_exit_code"] = worker.returncode
        (output / "helper-output.log").write_bytes(redact(stdout_path.read_text(encoding="utf-8", errors="replace")).encode())
        require(helper_output.is_dir(), "Helper did not preserve output")
        # Copy public output only; no .runtime, environment, cache or credentials.
        for path in helper_output.rglob("*"):
            if path.is_file():
                target = output / "helper-evidence" / path.relative_to(helper_output)
                target.parent.mkdir(parents=True, exist_ok=True)
                raw = path.read_bytes()
                require(all(value.encode() not in raw for value in secret_values if value), "Secret appeared in helper artifact")
                target.write_bytes(raw)
        helper_report = json.loads((helper_output / "report.json").read_text(encoding="utf-8"))
        candidate = helper_report.get("new_image", candidate)
        regression = json.loads((helper_output / "regression/probe-report.json").read_text(encoding="utf-8"))
        observed_tag = inspect("image", TAG)["Id"]
        observed_candidate = inspect("image", candidate, required=False) if candidate else None
        after_helper = inventory()
        report["observed_before_outer_fallback"] = {"tag_image": observed_tag, "candidate_image_absent": observed_candidate is None,
                                                    "helper_image_promoted": helper_report.get("image_promoted"),
                                                    "service_state": preserved_state()}
        check("source_drift_injected_after_actual_app_creation", injected and bool(app_cid))
        check("actual_helper_refused_with_exit_1", worker.returncode == 1)
        check("helper_detected_input_drift", helper_report.get("inputs_unchanged") is False and "Qualification inputs changed; preserving the prior image" in helper_report.get("errors", []))
        check("helper_did_not_promote", helper_report.get("image_promoted") is False)
        check("qualification_before_image_retirement", helper_report.get("promotion_checks_completed_before_image_retirement") is True)
        check("real_19_http_checks_passed", regression.get("executed") == regression.get("passed") == 19 and regression.get("failed") == regression.get("skipped") == regression.get("unexecuted") == regression.get("exit_code") == 0 and regression.get("harness_error") is None)
        check("two_synthetic_users_removed", regression.get("synthetic_cleanup", {}).get("created") == regression.get("synthetic_cleanup", {}).get("removed") == 2)
        check("dependency_layers_unchanged", helper_report.get("dependency_layers_unchanged") is True and report.get("candidate_rootfs_layers") == report.get("protected_rootfs_layers") and bool(report.get("candidate_rootfs_layers")))
        check("helper_restored_protected_tag", observed_tag == PROTECTED)
        check("helper_retired_ephemeral_image", candidate != PROTECTED and helper_report.get("retired_image") == candidate and observed_candidate is None)
        check("helper_retired_own_containers", helper_report.get("temporary_containers_retired") is True and all(row["id"] not in after_helper["containers"] for row in helper_report.get("created_containers", [])))
        check("core_and_postgres_unchanged_before_fallback", report["observed_before_outer_fallback"]["service_state"] == before_state)
        check("no_helper_created_volumes_or_networks", all(set(before[kind]) == set(after_helper[kind]) for kind in ("volumes", "networks")))
        check("only_intended_input_changed_after_build", [name for name in INPUTS if sha(scratch / name) != report["isolated_build_inputs"][name]] == ["examples/python/.dockerignore"])
    except Exception as error:
        report["errors"].append(redact(type(error).__name__ + ": " + str(error)))
    finally:
        if worker is not None and worker.poll() is None:
            worker.terminate()
            worker.wait(timeout=15)
            report["fallback_actions"].append("terminated-owned-helper-process")
        # Keep an interrupted helper's exact public output before private scratch
        # retirement too; an exception must not erase the failed run's evidence.
        try:
            transcript = scratch / "helper-output.log"
            if transcript.is_file() and not (output / "helper-output.log").exists():
                (output / "helper-output.log").write_bytes(redact(transcript.read_text(encoding="utf-8", errors="replace")).encode())
            partial_output = scratch / "evidence/operations/python-readiness/source-drift"
            for path in partial_output.rglob("*"):
                if path.is_file():
                    target = output / "helper-evidence" / path.relative_to(partial_output)
                    if not target.exists():
                        raw = path.read_bytes()
                        require(all(value.encode() not in raw for value in secret_values if value), "Secret appeared in partial helper artifact")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(raw)
        except Exception as error:
            report["errors"].append("Partial evidence: " + redact(type(error).__name__ + ": " + str(error)))
        # Fallback is safety recovery only and always prevents a passing result.
        try:
            if anchored:
                require(inspect("image", anchor)["Id"] == PROTECTED, "Protection image identity changed")
                if inspect("image", TAG, required=False) is None or inspect("image", TAG)["Id"] != PROTECTED:
                    docker("image", "tag", PROTECTED, TAG)
                    report["fallback_actions"].append("restored-protected-tag")
            owned_ids = {row["id"] for row in (helper_report or {}).get("created_containers", [])}
            for path in (scratch / ".runtime/python-image-refresh").glob("run-*/*.cid"):
                value = path.read_text().strip()
                if len(value) == 64 and all(char in "0123456789abcdef" for char in value):
                    owned_ids.add(value)
            for cid in owned_ids:
                state = inspect("container", cid, required=False)
                if state is None:
                    continue
                require(state["Id"] == cid and state["Config"].get("Labels", {}).get("org.expertauth.project") == "expert-auth" and state["Config"].get("Labels", {}).get("org.expertauth.purpose") == "python-image-proof", "Fallback container ownership differs")
                require(candidate is not None and state["Image"] == candidate and candidate != PROTECTED, "Fallback container image differs")
                docker("container", "rm", "-f", cid)
                report["fallback_actions"].append("removed-owned-container:" + cid)
            if candidate and candidate != PROTECTED:
                value = inspect("image", candidate, required=False)
                if value:
                    require(value.get("Config", {}).get("Labels", {}).get("org.expertauth.purpose") == "python-foundation", "Fallback image ownership differs")
                    require(not value.get("RepoTags") and not docker("ps", "-aq", "--filter", "ancestor=" + candidate).stdout.strip(), "Ephemeral image remains referenced; preserve it")
                    docker("image", "rm", candidate)
                    report["fallback_actions"].append("removed-owned-ephemeral-image:" + candidate)
            if anchored:
                require(inspect("image", TAG)["Id"] == PROTECTED and inspect("image", anchor)["Id"] == PROTECTED, "Do not untag the last protected image reference")
                docker("image", "rm", anchor)
                check("temporary_protection_tag_removed", inspect("image", anchor, required=False) is None)
            final_state = preserved_state()
            after = inventory()
            report["after_service_state"] = final_state
            report["resource_delta"] = {kind: {"added": sorted(set(after[kind]) - set(before[kind])), "removed": sorted(set(before[kind]) - set(after[kind]))} for kind in before}
            check("final_protected_tag_intact", inspect("image", TAG)["Id"] == PROTECTED)
            check("final_service_ids_start_times_mounts_unchanged", final_state == before_state)
            check("no_final_resource_inventory_delta", all(not row["added"] and not row["removed"] for row in report["resource_delta"].values()))
        except Exception as error:
            report["errors"].append("Safety cleanup: " + redact(type(error).__name__ + ": " + str(error)))
        try:
            resolved = scratch.resolve()
            require(resolved == scratch and resolved.parent == scratch_base and resolved.is_relative_to((ROOT / ".runtime").resolve()) and (resolved / ".ownership").read_text(encoding="utf-8") == run_id, "Refuse recursive cleanup outside exact owned temporary directory")
            shutil.rmtree(resolved)
            check("exact_private_scratch_removed", not resolved.exists())
        except Exception as error:
            report["errors"].append("Scratch cleanup: " + redact(type(error).__name__ + ": " + str(error)))
        check("original_workspace_inputs_unchanged", original_hashes == {name: sha(ROOT / name) for name in INPUTS})
        check("helper_rollback_needed_no_outer_fallback", not report["fallback_actions"])
        report["finished"] = datetime.now(timezone.utc).isoformat()
        report["expected_checks"] = 21
        report["passed"] = len(report["checks"]) == report["expected_checks"] and all(report["checks"].values()) and not report["errors"]
        report["exit_code"] = 0 if report["passed"] else 1
        report["artifacts"] = [{"path": path.relative_to(output).as_posix(), "sha256": sha(path)} for path in sorted(output.rglob("*")) if path.is_file()]
        encoded = json_bytes(report)
        require(all(value.encode() not in encoded for value in secret_values if value), "Refuse to persist private values")
        with (output / "report.json").open("xb") as stream:
            stream.write(encoded)
    print(json.dumps({"report": output.relative_to(ROOT).as_posix(), "passed": report["passed"], "exit_code": report["exit_code"], "checks": len(report["checks"]), "errors": report["errors"], "fallback_actions": report["fallback_actions"]}), flush=True)
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
