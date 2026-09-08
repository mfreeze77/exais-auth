"""Run contract-extractor tests and persist actual result with source hashes."""
import hashlib
import io
import json
import pathlib
import platform
import sys
import unittest
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
suite = unittest.defaultTestLoader.discover(str(ROOT / "tests/contracts"), pattern="test_*.py")
stream = io.StringIO()
result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
output = stream.getvalue()
print(output, end="")
exit_code = 0 if result.wasSuccessful() and not result.skipped else 1
paths = [ROOT / "tools/capture_contracts.py", *sorted((ROOT / "tests/contracts").glob("*.py")), *sorted((ROOT / "contracts").glob("*.json"))]
report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "command": "python tests/contracts/run.py", "environment": {"python": sys.version, "platform": platform.platform()}, "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped), "exit_code": exit_code, "input_sha256": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}, "output": output, "evidence_scope": "extractor-and-pinned-contract-accounting-only; no authentication or compatibility behavior pass"}
target = ROOT / "evidence/contracts/tests-report.json"
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
raise SystemExit(exit_code)
