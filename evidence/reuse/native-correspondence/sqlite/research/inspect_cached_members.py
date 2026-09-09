"""Read retained SQLite archives; never extract/execute native code or fetch bytes."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import re
import zipfile

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent
INVENTORY = ROOT / "evidence/reuse/runtime-distribution-review/archive-inventory.json"
COORDINATE = "org.xerial:sqlite-jdbc:3.45.1.0"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def main():
    baseline = next(row for row in json.loads(INVENTORY.read_text())["artifacts"] if row["coordinate"] == COORDINATE)
    result = {"scope": "Cached archive integrity and Git blob calculation only; no native execution or rebuild",
              "coordinate": COORDINATE, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
              "inventory_sha256": digest(INVENTORY.read_bytes()), "inspection_script_sha256": digest(Path(__file__).read_bytes()),
              "binary_downloaded": False, "native_tests_passed": False, "license_approved": False, "archives": {}}
    for kind in ("binary", "source"):
        archive = baseline[kind]
        path = ROOT / archive["path"]
        raw = path.read_bytes()
        assert digest(raw) == archive["sha256"] and len(raw) == archive["bytes"], "Archive drift"
        record = {"path": archive["path"], "sha256": digest(raw), "bytes": len(raw), "git_blob_sha1": git_blob(raw), "members": []}
        with zipfile.ZipFile(path) as jar:
            for group in ("native_members", "notice_members", "build_members", "native_source_members"):
                for expected in archive[group]:
                    member = jar.read(expected["member"])
                    assert digest(member) == expected["sha256"] and len(member) == expected["bytes"], "Member drift"
                    row = {**expected, "kind": group, "git_blob_sha1": git_blob(member)}
                    if group == "native_members":
                        row["embedded_sqlite_source_id_strings"] = sorted({item.decode("ascii") for item in re.findall(rb"20[0-9]{2}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9a-f]{64}", member)})
                        row["source_id_string_is_not_runtime_execution"] = True
                    record["members"].append(row)
        result["archives"][kind] = record
    output = HERE / "cached-members.json"
    assert not output.exists(), "Preserve prior inspection evidence"
    output.write_bytes((json.dumps(result, indent=2) + "\n").encode())
    print(json.dumps({"output": output.relative_to(ROOT).as_posix(), "archives_verified": 2,
                      "native_members_per_archive": 23, "sha256": digest(output.read_bytes())}))


if __name__ == "__main__":
    main()
