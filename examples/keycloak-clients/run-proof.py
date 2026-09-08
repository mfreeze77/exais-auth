"""Rebuild own candidate backend and capture real HTTP/browser evidence on existing private lab."""
import hashlib
import json
import pathlib
import subprocess
import time
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
HERE = pathlib.Path(__file__).resolve().parent
OUTPUT = ROOT / 'evidence/foundation/keycloak-clients'
stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
commands = []


def run(arguments, *, required=True):
    completed = subprocess.run(arguments, cwd=ROOT, capture_output=True, text=True, timeout=180)
    index = len(commands) + 1
    log = OUTPUT / f'run-{stamp}-{index:02d}.log'
    log.write_text(completed.stdout + completed.stderr, encoding='utf8')
    commands.append({'argv': arguments, 'exit_code': completed.returncode,
                     'output': str(log.relative_to(ROOT)).replace('\\', '/'),
                     'output_sha256': hashlib.sha256(log.read_bytes()).hexdigest()})
    if required and completed.returncode:
        raise RuntimeError(f'Command {index} failed, exit {completed.returncode}; inspect redacted log')
    return completed


def snapshot():
    paths = [ROOT / 'tests/foundation/keycloak_clients.py']
    paths.extend(path for path in HERE.rglob('*') if not any(
        part in ('.runtime', 'node_modules', '__pycache__') for part in path.relative_to(HERE).parts) and path.name != 'app.js' and path.is_file())
    return {str(path.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


OUTPUT.mkdir(parents=True, exist_ok=True)
before = snapshot()
passed, error = False, None
try:
    run(['docker', 'inspect', 'expertauth-kc-clients-engine', '--format', '{{.Image}}'])
    run(['docker', 'build', '-t', 'expertauth-kc-clients-node:0.0.1', 'examples/keycloak-clients'])
    # Fixed owned disposable container; never affects the shared engine or production.
    run(['docker', 'rm', '-f', 'expertauth-kc-clients-node'])
    run(['docker', 'run', '-d', '--name', 'expertauth-kc-clients-node', '--network', 'expertauth-kc-clients-proof',
         '--network-alias', 'expertauth-kc-clients-node', '-e', 'EXPERTAUTH_LOCAL_PROOF=true', 'expertauth-kc-clients-node:0.0.1'])
    ready = False
    for _ in range(20):
        health = run(['docker', 'exec', 'expertauth-kc-clients-node', 'node', '-e',
                      "fetch('http://localhost:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"], required=False)
        if health.returncode == 0:
            ready = True
            break
        time.sleep(1)
    if not ready:
        raise RuntimeError('Candidate backend never became ready')
    mount = str(ROOT) + ':/workspace'
    common = ['docker', 'run', '--rm', '--network', 'expertauth-kc-clients-proof', '-v', mount]
    http = run(common + ['-w', '/workspace', '-e', 'PYTHONPATH=/workspace/examples/keycloak-clients/.runtime/testdeps',
                        'python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36',
                        'python', 'tests/foundation/keycloak_clients.py'], required=False)
    browser = run(common + ['-w', '/workspace/examples/keycloak-clients',
                           'mcr.microsoft.com/playwright@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e',
                           'node', 'browser-probe.mjs'], required=False)
    run(['docker', 'inspect', 'expertauth-kc-clients-node', '--format', '{{.Image}}'])
    passed = http.returncode == 0 and browser.returncode == 0
except Exception as exc:
    error = {'type': type(exc).__name__, 'detail': str(exc)}
after = snapshot()
report = {'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'commands': commands,
          'source_sha256_before': before, 'source_sha256_after': after, 'source_changed_during_run': before != after,
          'candidate_checks_passed': passed and before == after, 'auth_completion': False, 'foundation_passed': False,
          'harness_error': error, 'artifact_sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
              for path in OUTPUT.glob('*') if path.is_file() and path.name in ('http-results.json', 'browser-results.json',
                  'react-authenticated-mobile.png', 'react-signed-out-mobile.png')}}
text = json.dumps(report, indent=2) + '\n'
(OUTPUT / f'commands-{stamp}.json').write_text(text)
(OUTPUT / 'commands.json').write_text(text)
print(json.dumps({'candidate_checks_passed': report['candidate_checks_passed'], 'auth_completion': False,
                  'artifact': f'evidence/foundation/keycloak-clients/commands-{stamp}.json', 'harness_error': error}))
raise SystemExit(0 if report['candidate_checks_passed'] else 1)
