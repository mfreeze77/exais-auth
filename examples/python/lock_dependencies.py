"""Resolve exact Linux/Python wheel hashes; run only when intentionally updating."""
import json
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent
with tempfile.TemporaryDirectory() as temporary:
    report_path = pathlib.Path(temporary) / "pip-report.json"
    subprocess.run(["python", "-m", "pip", "install", "--dry-run", "--ignore-installed", "--only-binary=:all:", "--disable-pip-version-check", "--report", str(report_path), "-r", str(ROOT / "requirements.in")], check=True)
    report = json.loads(report_path.read_text())
lines = ["# Resolved for pinned Python 3.12 Linux x86_64 image; regenerate explicitly."]
for entry in sorted(report["install"], key=lambda item: item["metadata"]["name"].lower()):
    metadata = entry["metadata"]
    checksum = entry["download_info"]["archive_info"]["hashes"]["sha256"]
    lines.append(f"{metadata['name']}=={metadata['version']} --hash=sha256:{checksum}")
(ROOT / "requirements.lock").write_text("\n".join(lines) + "\n")
# Preserve resolver/environment and distribution facts without copying package
# README descriptions or embedding unrelated project documentation in delivery.
for entry in report["install"]:
    entry["metadata"] = {key: value for key, value in entry["metadata"].items() if key in {"name", "version", "license", "license_expression", "classifier", "requires_dist", "requires_python", "license_file", "metadata_version"}}
(ROOT / "dependency-resolution.json").write_text(json.dumps(report, indent=2) + "\n")
print(f"Locked {len(report['install'])} exact wheel distributions")
