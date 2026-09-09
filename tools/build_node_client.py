"""Compile the current React client offline using one existing immutable image.

This writes only the generated public/app.js and fresh compilation evidence.
It does not qualify browser behavior, a full runtime image, or the foundation.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import uuid
from node_runtime_identity import TAG as NODE, require_owned_node


ROOT = Path(__file__).resolve().parents[1]
PURPOSE = "node-client-build"
SOURCE_FILES = ("examples/node-react/client.jsx", "examples/node-react/build.mjs", "examples/node-react/package-lock.json")
MAX_BUNDLE = 2 * 1024 * 1024
METADATA_PREFIX = "EXPERTAUTH_COMPILER_METADATA "


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_hashes():
    return {name: sha(ROOT / name) for name in SOURCE_FILES}


def preserved_public(public):
    result = {"directories": [], "files": {}}
    for path in sorted(public.rglob("*")):
        require(not path.is_symlink() and path.resolve().is_relative_to(public), "Public output contains an unsafe link")
        relative = path.relative_to(public).as_posix()
        if path.is_dir():
            result["directories"].append(relative)
        elif relative != "app.js":
            require(path.is_file(), "Public output contains a non-file entry")
            result["files"][relative] = sha(path)
    require("index.html" in result["files"], "Expected preserved public index")
    return result


def metadata_import(expected):
    # A read-only preload runs in the same Node process before /app/build.mjs.
    # Nothing here imports application/server configuration or reads credentials.
    script = """
import { readFileSync, openSync, readSync, closeSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
const require = createRequire('/app/build.mjs');
const hash = path => {
  const fd = openSync(path, 'r'), value = createHash('sha256'), buffer = Buffer.alloc(65536);
  try { let size; while ((size = readSync(fd, buffer, 0, buffer.length, null))) value.update(buffer.subarray(0, size)); }
  finally { closeSync(fd); }
  return value.digest('hex');
};
const esbuild = require('esbuild');
const modulePath = require.resolve('esbuild');
const lock = JSON.parse(readFileSync('/app/package-lock.json', 'utf8'));
const expected = EXPECTED_INPUTS;
const installed = Object.fromEntries(Object.keys(expected).map(path => [path, hash(path)]));
const metadata = {
  node: { version: process.version, platform: process.platform, architecture: process.arch,
    executable: process.execPath, executable_sha256: hash(process.execPath) },
  esbuild: { version: esbuild.version, module_path: modulePath, module_sha256: hash(modulePath),
    package_sha256: hash('/app/node_modules/esbuild/package.json') },
  installed_input_sha256: installed,
};
process.stdout.write('EXPERTAUTH_COMPILER_METADATA ' + JSON.stringify(metadata) + '\\n');
if (Object.keys(expected).some(path => installed[path] !== expected[path]) ||
    esbuild.version !== lock.packages?.['node_modules/esbuild']?.version) {
  throw new Error('Compiler inputs or installed locked esbuild version differ');
}
""".replace("EXPECTED_INPUTS", json.dumps(expected, separators=(",", ":")))
    return "data:text/javascript;base64," + base64.b64encode(script.encode()).decode(), hashlib.sha256(script.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.name), "Invalid build run name")
    output = ROOT / "evidence/operations/node-client-build" / args.name
    output.mkdir(parents=True, exist_ok=False)  # Existing successful/failed evidence is immutable.
    suffix = uuid.uuid4().hex[:12]
    name = "expertauth-node-client-build-" + suffix
    labels = {"org.expertauth.project": "expert-auth", "org.expertauth.purpose": PURPOSE, "org.expertauth.run": args.name,
              "org.expertauth.instance": suffix}
    cidfile = output / "container.cid"
    report = {"schema": "expertauth-offline-node-client-build-v1", "started": datetime.now(timezone.utc).isoformat(),
              "compiled": False, "browser_passed": False, "foundation_passed": False, "full_image_qualified": False,
              "scope": "Compilation of current React source against an existing immutable dependency image only",
              "image_reference": NODE, "image": None, "image_builds": 0, "image_downloads": 0, "new_networks": 0, "new_volumes": 0,
              "published_ports": [], "network": "none", "container_name": name, "container_id": None,
              "container_labels": labels, "container_retired": False, "inputs_unchanged": False, "preserved_public_unchanged": False,
              "compiler_tool_sha256": sha(Path(__file__)),
              "ownership_module_before_sha256": sha(ROOT/'tools/node_runtime_identity.py'), "commands": [], "errors": []}
    started = time.monotonic()
    launched = False
    image_id = None
    inputs = public_before = None
    public = (ROOT / "examples/node-react/public").resolve()

    def persist():
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    def command(label, argv, timeout=30):
        sequence = len(report["commands"]) + 1
        stdout, stderr = output / f"command-{sequence:02d}.stdout", output / f"command-{sequence:02d}.stderr"
        record = {"label": label, "argv": ["docker", *argv], "exit_code": None, "timed_out": False}
        report["commands"].append(record)
        try:
            with stdout.open("xb") as out, stderr.open("xb") as err:
                result = subprocess.run(["docker", *argv], stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=timeout)
            record["exit_code"] = result.returncode
        except subprocess.TimeoutExpired:
            record["timed_out"] = True
            raise RuntimeError("Docker command exceeded its bounded timeout") from None
        finally:
            for stream, path in (("stdout", stdout), ("stderr", stderr)):
                if path.exists():
                    record[stream] = {"path": path.name, "bytes": path.stat().st_size, "sha256": sha(path)}
            persist()
        require(stdout.stat().st_size <= MAX_BUNDLE, "Docker command output exceeded the bounded limit")
        return result.returncode, stdout.read_text(encoding="utf-8", errors="replace")

    # Restrict inspection logs to non-secret ownership and runtime fields.
    inspect_format = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
                      '"labels":{{json .Config.Labels}},"running":{{json .State.Running}}}')

    def inspect_container(reference, label):
        code, raw = command(label, ["container", "inspect", "--format", inspect_format, reference])
        return None if code else json.loads(raw)

    def assert_owned(state, cid):
        require(state["id"] == cid and state["name"] == "/" + name and state["image"] == image_id and
                all((state.get("labels") or {}).get(key) == value for key, value in labels.items()), "Container cleanup ownership differs")

    persist()
    try:
        require(public.is_relative_to(ROOT) and public.parent == (ROOT / "examples/node-react").resolve() and public.is_dir(), "Public output boundary differs")
        inputs = source_hashes()
        report["inputs_before"] = inputs
        public_before = preserved_public(public)
        report["preserved_public_before"] = public_before
        report["index_before_sha256"] = public_before["files"]["index.html"]
        require(not (public / "app.js").exists() or (public / "app.js").is_file(), "Generated bundle is not a regular file")
        code, raw = command("require-cached-image", ["image", "inspect", "--format", '{"id":{{json .Id}},"volumes":{{json (index .Config "Volumes")}},"labels":{{json (index .Config "Labels")}}}', NODE])
        require(code == 0, "Required immutable image inspection failed; no pull is permitted")
        image = json.loads(raw)
        require(re.fullmatch('sha256:[0-9a-f]{64}', image['id']) and not image["volumes"], "Owned image identity or anonymous-volume configuration differs")
        report['node_image_ownership'] = require_owned_node({'Id':image['id'],'Config':{'Labels':image.get('labels')}})
        image_id = report['image'] = image['id']
        code, raw = command("containers-before", ["ps", "-aq", "--no-trunc"])
        require(code == 0, "Could not inspect current container inventory")
        report["container_count_before"] = len(raw.splitlines())
        require(inspect_container(name, "name-collision-check") is None, "Container name already exists")
        expected = {"/app/" + Path(path).name: digest for path, digest in inputs.items()}
        preload, report["metadata_preload_sha256"] = metadata_import(expected)
        argv = ["run", "--rm", "--pull=never", "--name", name, "--cidfile", str(cidfile), "--network=none", "--read-only",
                "--user=0", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=512m", "--cpus=2", "--pids-limit=128",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m", "--workdir=/app"]
        for key, value in labels.items():
            argv += ["--label", key + "=" + value]
        argv += ["--mount", f"type=bind,source={ROOT / 'examples/node-react/client.jsx'},target=/app/client.jsx,readonly",
                 "--mount", f"type=bind,source={ROOT / 'examples/node-react/build.mjs'},target=/app/build.mjs,readonly",
                 "--mount", f"type=bind,source={public},target=/app/public",
                 "--entrypoint", "node", image_id, "--import", preload, "/app/build.mjs"]
        launched = True
        code, raw = command("compile-client", argv, timeout=60)
        metadata = [line[len(METADATA_PREFIX):] for line in raw.splitlines() if line.startswith(METADATA_PREFIX)]
        require(len(metadata) == 1, "Expected one actual installed compiler metadata record")
        report["installed_compiler"] = json.loads(metadata[0])
        require(report["installed_compiler"]["installed_input_sha256"] == expected, "Installed compiler inputs differ")
        require(code == 0, "Actual offline frontend compilation failed")
        bundle = public / "app.js"
        require(bundle.is_file() and 0 < bundle.stat().st_size <= MAX_BUNDLE, "Generated bundle is missing or exceeds two MiB")
        report["generated_bundle"] = {"path": "examples/node-react/public/app.js", "bytes": bundle.stat().st_size, "sha256": sha(bundle)}
        report["compiler_exit_code"] = code
    except Exception as error:
        report["errors"].append(str(error) if isinstance(error, RuntimeError) else "Compiler operation or evidence persistence failed")
    finally:
        try:
            cid = cidfile.read_text().strip() if cidfile.exists() else None
            require(cid is None or re.fullmatch(r"[0-9a-f]{64}", cid), "Malformed task container CID")
            if launched:
                state = inspect_container(cid or name, "cleanup-inspect")
                if state is not None:
                    # Recover a CID only from this generated name plus all unique
                    # ownership labels, then use that exact ID for every mutation.
                    cid = cid or state["id"]
                    require(re.fullmatch(r"[0-9a-f]{64}", cid), "Missing exact task container ID")
                    assert_owned(state, cid)
                    if state["running"]:
                        command("stop-owned-container", ["stop", "--time", "5", cid], timeout=15)
                    remaining = inspect_container(cid, "inspect-after-stop")
                    if remaining is not None:
                        assert_owned(remaining, cid)
                        command("remove-owned-container", ["rm", cid])
                report["container_id"] = cid
                require(report.get("compiler_exit_code") != 0 or cid is not None, "Successful compilation did not preserve its exact container ID")
            code, raw = command("containers-after", ["ps", "-aq", "--no-trunc"])
            require(code == 0 and (cid is None or cid not in raw.splitlines()), "Task container retirement could not be confirmed")
            report["container_count_after"] = len(raw.splitlines())
            code, raw = command("name-absent-after", ["ps", "-aq", "--filter", "name=^/" + name + "$"])
            require(code == 0 and not raw.strip(), "Task container name remains present")
            report["container_retired"] = True
        except Exception as error:
            report["errors"].append(str(error) if isinstance(error, RuntimeError) else "Exact container cleanup could not be confirmed")
        try:
            report["inputs_after"] = source_hashes()
            report['ownership_module_after_sha256'] = sha(ROOT/'tools/node_runtime_identity.py')
            require(report['ownership_module_after_sha256'] == report['ownership_module_before_sha256'], 'Image ownership helper changed during compilation')
            report["inputs_unchanged"] = inputs is not None and report["inputs_after"] == inputs
            report["preserved_public_after"] = preserved_public(public)
            report["index_after_sha256"] = report["preserved_public_after"]["files"]["index.html"]
            report["preserved_public_unchanged"] = public_before is not None and report["preserved_public_after"] == public_before
            require(report["inputs_unchanged"], "Source files changed during compilation")
            require(report["preserved_public_unchanged"], "A public file other than app.js changed during compilation")
            if "generated_bundle" in report:
                bundle = public / "app.js"
                require(bundle.is_file() and 0 < bundle.stat().st_size <= MAX_BUNDLE, "Generated bundle changed after compilation")
                report["generated_bundle_after"] = {"path": "examples/node-react/public/app.js", "bytes": bundle.stat().st_size, "sha256": sha(bundle)}
                require(report["generated_bundle_after"] == report["generated_bundle"], "Generated bundle changed after compilation")
        except Exception as error:
            report["errors"].append(str(error) if isinstance(error, RuntimeError) else "Final source/public preservation check failed")
        report["compiled"] = not report["errors"] and report.get("compiler_exit_code") == 0 and report["container_retired"] and report["inputs_unchanged"] and report["preserved_public_unchanged"]
        report["finished"] = datetime.now(timezone.utc).isoformat()
        report["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
        persist()
    print(json.dumps({"compiled": report["compiled"], "report": output.relative_to(ROOT).as_posix(), "container_retired": report["container_retired"], "errors": report["errors"]}))
    return 0 if report["compiled"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
