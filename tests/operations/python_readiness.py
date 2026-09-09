"""Real Python application/database outage proof with host-controlled restoration.

The baseline image and current application share the real, owned Core/PostgreSQL.
All authentication uses the maintained SDK. Only synthetic test users are removed.
"""
from __future__ import annotations
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import uuid

import httpx

OUT = Path(os.environ['EVIDENCE_DIR'])
KEY = os.environ['EXPERTAUTH_CORE_API_KEY']
BASELINE = 'http://python-ready-baseline.example.test:8300'
CURRENT = 'http://python-ready-current.example.test:8300'
CORE = 'http://core-a:3567'
rows = []
users = []
client = httpx.Client(timeout=8, trust_env=False)
started = datetime.now(timezone.utc).isoformat()


def require(value, detail):
    if not value:
        raise AssertionError(detail)


def record(identifier, function):
    before = time.monotonic()
    try:
        detail = function() or {}
        row = {'id': identifier, 'status': 'passed', **detail}
    except Exception as error:
        row = {'id': identifier, 'status': 'failed', 'error': str(error) if isinstance(error, AssertionError) else type(error).__name__}
    row['elapsed_ms'] = round((time.monotonic() - before) * 1000, 2)
    rows.append(row)
    print(json.dumps({'id': identifier, 'status': row['status']}), flush=True)
    return row['status'] == 'passed'


def control(action):
    print(json.dumps({'control': action}), flush=True)
    answer = sys.stdin.readline()
    require(answer and json.loads(answer).get('ok') is True, 'Host restoration/control did not succeed')


def core(path, body=None):
    return client.request('POST' if body else 'GET', CORE + path, headers={
        'api-key': KEY, 'cdi-version': '5.4', 'content-type': 'application/json'}, json=body)


def headers(token=None):
    return {'origin': CURRENT, 'fdi-version': '4.2', 'rid': 'session', 'st-auth-mode': 'header',
            **({'authorization': 'Bearer ' + token} if token else {})}


def signup():
    response = client.post(CURRENT + '/auth/signup', headers={**headers(), 'rid': 'emailpassword'}, json={
        'formFields': [{'id': 'email', 'value': 'ready-' + uuid.uuid4().hex + '@example.test'},
                       {'id': 'password', 'value': 'Synthetic-' + uuid.uuid4().hex + '-9a!'}]})
    body = response.json()
    if body.get('status') == 'OK' and isinstance(body.get('user', {}).get('id'), str):
        users.append(body['user']['id'])
    require(response.status_code == 200 and body.get('status') == 'OK', 'Real SDK signup failed')
    require(response.headers.get('st-access-token') and response.headers.get('st-refresh-token'), 'Session tokens absent')
    return {'access': response.headers['st-access-token'], 'refresh': response.headers['st-refresh-token']}


try:
    for base in (BASELINE, CURRENT):
        for attempt in range(40):
            try:
                if client.get(base + '/ready').status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        else:
            raise AssertionError('Initial application readiness failed')

    def healthy():
        responses = [client.get(base + '/ready') for base in (BASELINE, CURRENT)]
        require(all(response.status_code == 200 for response in responses), 'Healthy readiness failed')
        require(responses[1].headers.get('cache-control') == 'no-store', 'Readiness must not be cached')
        storage = core('/users/count')
        require(storage.status_code == 200 and storage.json().get('status') == 'OK', 'Storage query failed before outage')
        return {'baseline': 200, 'current': 200, 'core_storage': 200}
    record('PY-READY-HEALTHY-STORAGE', healthy)
    session = signup()
    record('PY-READY-AUTH-BEFORE-OUTAGE', lambda: require(client.get(CURRENT + '/protected', headers=headers(session['access'])).status_code == 200, 'Session rejected before outage'))

    control('stop_owned_postgres')
    def outage():
        version = core('/apiversion')
        before = time.monotonic()
        current = client.get(CURRENT + '/ready')
        latency = (time.monotonic() - before) * 1000
        baseline = client.get(BASELINE + '/ready')
        live = client.get(CURRENT + '/live')
        require(version.status_code == 200 and '5.4' in version.json().get('versions', []), 'Core protocol advertisement did not remain available')
        require(baseline.status_code == 200, 'Baseline false-ready defect was not reproduced')
        require(current.status_code == 503 and current.headers.get('cache-control') == 'no-store', 'Corrected readiness did not fail closed')
        require(current.json() == {'detail': 'Identity service unavailable or incompatible'}, 'Dependency details leaked')
        require(latency < 4500, 'Readiness exceeded declared four-second request budget plus local scheduling allowance')
        require(live.status_code == 200 and live.json() == {'status': 'alive'}, 'Liveness was incorrectly tied to database health')
        return {'core_protocol_http': version.status_code, 'baseline_false_ready_http': baseline.status_code,
                'current_ready_http': current.status_code, 'current_live_http': live.status_code,
                'current_ready_ms': round(latency, 2), 'database': 'host confirmed same owned container stopped'}
    record('PY-READY-DATABASE-OUTAGE', outage)

    control('start_owned_postgres')
    def recovered():
        observed = []
        start = time.monotonic()
        for attempt in range(30):
            response = client.get(CURRENT + '/ready')
            observed.append(response.status_code)
            if response.status_code == 200:
                return {'http_sequence': observed, 'ready_after_host_pg_ready_ms': round((time.monotonic() - start) * 1000, 2)}
            time.sleep(0.5)
        raise AssertionError('Readiness did not recover after database restoration')
    record('PY-READY-DATABASE-RECOVERY', recovered)
    def continuity():
        refreshed = client.post(CURRENT + '/auth/session/refresh', headers=headers(session['refresh']))
        require(refreshed.status_code == 200, 'Persisted session could not refresh after database restart')
        access, refresh = refreshed.headers['st-access-token'], refreshed.headers['st-refresh-token']
        require(client.get(CURRENT + '/protected', headers=headers(access)).status_code == 200, 'Online session denied after database restart')
        require(client.post(CURRENT + '/auth/signout', headers=headers(access)).status_code == 200, 'Signout failed after recovery')
        require(client.post(CURRENT + '/auth/session/refresh', headers=headers(refresh)).status_code == 401, 'Revoked session refreshed after recovery')
        return {'refresh': 200, 'online': 200, 'logout': 200, 'post_logout_refresh': 401}
    record('PY-READY-SESSION-CONTINUITY', continuity)
except Exception as error:
    rows.append({'id': 'HARNESS', 'status': 'failed', 'error': str(error) if isinstance(error, AssertionError) else type(error).__name__})
finally:
    # Host finally restores PostgreSQL even if this process fails before control.
    # Request restoration here too before removing any synthetic identity.
    try:
        control('ensure_postgres_running')
    except Exception:
        rows.append({'id': 'PY-READY-RESTORATION-CONTROL', 'status': 'failed'})
    removed = 0
    for user in users:
        try:
            response = core('/user/remove', {'userId': user, 'removeAllLinkedAccounts': False})
            if response.status_code == 200 and response.json().get('status') == 'OK':
                removed += 1
        except httpx.HTTPError:
            pass
    rows.append({'id': 'PY-READY-SYNTHETIC-CLEANUP', 'status': 'passed' if removed == len(users) else 'failed',
                 'created': len(users), 'removed': removed})
    client.close()
    report = {'schema': 'expertauth-python-readiness-proof-v1', 'started': started,
              'finished': datetime.now(timezone.utc).isoformat(), 'rows': rows, 'skipped': 0,
              'passed': sum(row['status'] == 'passed' for row in rows), 'failed': sum(row['status'] == 'failed' for row in rows),
              'requirements': ['OPS-004', 'OPS-011'], 'foundation_passed': False,
              'probe_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'limits': ['Private single-database failure/recovery; not production traffic removal, database HA or backup restore qualification.',
                         'Representative Python application only; no new platform/profile completion.']}
    encoded = json.dumps(report, indent=2) + '\n'
    require(KEY not in encoded, 'Secret in evidence')
    with (OUT / 'probe-report.json').open('xb') as stream:
        stream.write(encoded.encode())
    print(json.dumps({'finished': True, 'passed': report['passed'], 'failed': report['failed']}), flush=True)
    raise SystemExit(int(report['failed'] != 0))
