"""Record a hashed ExpertAuth engine test run under evidence/engine/<name>/.

Runs the engine's typecheck and full node:test suite (TAP) against EXPERTAUTH_TEST_ADMIN_URL,
scrubs machine-local paths, and writes report.json with counts, test names, environment and the
SHA-256 of every engine source file. This is engine evidence, not the strict release run schema.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / 'engine'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,54}', args.name):
        raise SystemExit('Invalid evidence name')
    if not os.environ.get('EXPERTAUTH_TEST_ADMIN_URL'):
        raise SystemExit('EXPERTAUTH_TEST_ADMIN_URL is required')
    out = ROOT / 'evidence/engine' / args.name
    if out.exists():
        raise SystemExit('Evidence names must be new; previous runs are never overwritten')
    out.mkdir(parents=True)
    typecheck = subprocess.run(['npx', 'tsc', '--noEmit', '-p', '.'], cwd=ENGINE, capture_output=True, text=True)
    tests = sorted(str(p.relative_to(ENGINE)) for p in (ENGINE / 'test').glob('*.test.ts'))
    run = subprocess.run(['node', '--test', '--test-concurrency=1', '--test-reporter=tap', *tests],
                         cwd=ENGINE, capture_output=True, text=True, timeout=1800)
    scrub = lambda text: re.sub(r'file:///\S*?/engine/', 'file:///<repo>/engine/', text).replace(str(ROOT) + '/', '<repo>/')
    tap = scrub(run.stdout + run.stderr)
    (out / 'test-output.tap').write_text(tap)
    (out / 'typecheck.txt').write_text(scrub(typecheck.stdout + typecheck.stderr))
    counts = {k: int(m.group(1)) if (m := re.search(rf'^# {k} (\d+)$', tap, re.M)) else None
              for k in ('tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo')}
    files = sorted(p for p in ENGINE.rglob('*') if p.is_file() and 'node_modules' not in p.parts)
    package = json.loads((ENGINE / 'package.json').read_text())
    report = {
        'kind': 'expertauth-engine-test-run', 'name': args.name,
        'passed': run.returncode == 0 and typecheck.returncode == 0 and counts['fail'] == 0 and counts['cancelled'] == 0 and bool(counts['tests']),
        'exit_codes': {'tests': run.returncode, 'typecheck': typecheck.returncode},
        'counts': counts, 'test_names': re.findall(r'^\s*ok \d+ - (.+)$', tap, re.M),
        'environment': {'node': subprocess.run(['node', '--version'], capture_output=True, text=True).stdout.strip(),
                        'postgresql': os.environ.get('EXPERTAUTH_TEST_POSTGRES_LABEL', 'unrecorded'),
                        'dependencies': package.get('dependencies', {}), 'dev_dependencies': package.get('devDependencies', {})},
        'sources_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
        'recorded': datetime.now(timezone.utc).isoformat(),
        'scope': 'Independent ExpertAuth engine integration and unit tests against real PostgreSQL. Not the strict '
                 'release run schema, not load/HA/SDK/browser qualification, not independent review.',
    }
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'counts': counts}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
