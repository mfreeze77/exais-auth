"""Launch a private, disposable Keycloak mapping experiment; never production."""
from __future__ import annotations
import hashlib
import json
import secrets
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'quay.io/keycloak/keycloak:26.7.3'
NETWORK = 'expertauth-foundation-kc'
CONTAINER = 'expertauth-foundation-kc'

def command(args, *, check=True):
    p = subprocess.run(args, capture_output=True, text=True, encoding='utf-8', errors='replace')
    if check and p.returncode:
        raise RuntimeError(f'{args[:3]} exited {p.returncode}: {p.stderr}')
    return p

def main():
    runtime = ROOT / '.runtime' / 'keycloak'
    runtime.mkdir(parents=True, exist_ok=True)
    evidence = ROOT / 'evidence' / 'foundation' / 'keycloak'
    evidence.mkdir(parents=True, exist_ok=True)
    if (evidence/'command.json').exists():
        previous = evidence/'attempts'/str(time.time_ns())
        previous.mkdir(parents=True)
        for file in evidence.glob('*'):
            if file.is_file():
                (previous/file.name).write_bytes(file.read_bytes())
    exists = command(['docker','container','inspect',CONTAINER], check=False)
    if exists.returncode == 0:
        raise SystemExit(f'{CONTAINER} exists; preserve it or remove this owned test container explicitly before rerunning.')
    secret = secrets.token_urlsafe(36)
    env = runtime / 'bootstrap.env'
    env.write_text(f'KC_BOOTSTRAP_ADMIN_CLIENT_ID=expertauth-probe\nKC_BOOTSTRAP_ADMIN_CLIENT_SECRET={secret}\n', encoding='utf-8')
    digest = json.loads(command(['docker','image','inspect',IMAGE]).stdout)[0]['RepoDigests'][0]
    python_digest = json.loads(command(['docker','image','inspect','python:3.12-slim']).stdout)[0]['RepoDigests'][0]
    command(['docker','network','create','--internal',NETWORK])
    command(['docker','run','-d','--name',CONTAINER,'--network',NETWORK,'--network-alias','keycloak',
             '--env-file',str(env), '--label','org.expertauth.purpose=foundation-probe', digest,
             'start-dev','--http-port=8080','--hostname-strict=false','--health-enabled=true'])
    start = time.monotonic()
    cmd = ['docker','run','--rm','--network',NETWORK,'--env-file',str(env),
           '-v',f'{ROOT}:/workspace','-w','/workspace',python_digest,
           'python','tests/foundation/keycloak_probe.py']
    run = command(cmd, check=False)
    record = {'command':cmd, 'exit_code':run.returncode,'elapsed_seconds':round(time.monotonic()-start,3),
              'stdout':run.stdout.replace(secret,'[REDACTED]'), 'stderr':run.stderr.replace(secret,'[REDACTED]'),
              'images':{'keycloak':digest,'python':python_digest},'network':{'internal':True,'published_ports':[]},
              'scope':'candidate mapping experiment; development storage; no foundation approval',
              'files':{p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in [Path(__file__), ROOT/'tests/foundation/keycloak_probe.py']}}
    (evidence/'command.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
    log = command(['docker','logs',CONTAINER],check=False)
    (evidence/'engine.log').write_text((log.stdout+log.stderr).replace(secret,'[REDACTED]'),encoding='utf-8')
    print(run.stdout)
    if run.stderr:
        print(run.stderr)
    print(f'Probe exit={run.returncode}; evidence={evidence}')
    raise SystemExit(run.returncode)

if __name__ == '__main__':
    main()
