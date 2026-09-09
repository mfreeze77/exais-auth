"""Real transport failure against the Python probe; no authentication doubles.

An HTTP proxy forwards to the actual FastAPI application except that it closes
the second signout connection before forwarding. Core owns all auth state.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
from urllib.parse import urlsplit

import httpx

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(os.environ['EVIDENCE_DIR'])
KEY = os.environ['EXPERTAUTH_CORE_API_KEY']
UPSTREAM = urlsplit(os.environ['FAULT_UPSTREAM'])
ORIGIN = os.environ['FAULT_ORIGIN']
created = set()
secrets = {KEY}
requests = []
signouts = 0
drops = 0
lock = threading.Lock()


def require(value, detail):
    if not value:
        raise AssertionError(detail)


def redact(value):
    for secret in sorted(secrets, key=len, reverse=True):
        if secret:
            value = value.replace(secret, '[REDACTED]')
    return re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[REDACTED_JWT]', value)


class Proxy(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def forward(self):
        global signouts, drops
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        path = urlsplit(self.path).path
        # Secrets are retained in memory solely to redact a failed child process.
        try:
            for field in json.loads(body).get('formFields', []):
                if field.get('id') == 'password':
                    secrets.add(field['value'])
        except (ValueError, AttributeError, TypeError):
            pass
        with lock:
            if self.command == 'POST' and path == '/auth/signout':
                signouts += 1
                if signouts == 2:
                    drops += 1
                    requests.append({'method': self.command, 'path': path, 'outcome': 'connection-dropped-before-forward'})
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
        upstream = http.client.HTTPConnection(UPSTREAM.hostname, UPSTREAM.port, timeout=12)
        try:
            headers = {key: value for key, value in self.headers.items()
                       if key.lower() not in {'connection', 'host', 'transfer-encoding'}}
            headers['Host'] = urlsplit(ORIGIN).netloc
            upstream.request(self.command, self.path, body=body, headers=headers)
            response = upstream.getresponse()
            data = response.read()
            for key, value in response.getheaders():
                if key.lower() in {'st-access-token', 'st-refresh-token'}:
                    secrets.add(value)
                if key.lower() == 'set-cookie':
                    secrets.add(value.split(';', 1)[0].split('=', 1)[-1])
            if self.command == 'POST' and path == '/auth/signup':
                result = json.loads(data)
                if result.get('status') == 'OK' and isinstance(result.get('user', {}).get('id'), str):
                    created.add(result['user']['id'])
            with lock:
                requests.append({'method': self.command, 'path': path, 'outcome': 'forwarded', 'http_status': response.status})
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in {'connection', 'content-length', 'transfer-encoding'}:
                    self.send_header(key, value)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(data)
            self.close_connection = True
        except Exception as error:
            with lock:
                requests.append({'method': self.command, 'path': path, 'outcome': 'proxy-error', 'error': type(error).__name__})
            self.close_connection = True
        finally:
            upstream.close()


def identities(client):
    # AuthRecipe.USER_PAGINATION_LIMIT is 500 in the pinned Core source.
    response = client.get('http://core-a:3567/users?limit=500', headers={'api-key': KEY, 'cdi-version': '5.4'})
    require(response.status_code == 200, 'Real Core identity snapshot unavailable: HTTP ' + str(response.status_code))
    value = response.json()
    require(value.get('status') == 'OK' and not value.get('nextPaginationToken'), 'Identity snapshot exceeded bounded single page')
    return {user['id'] for user in value['users']}


def main():
    started = datetime.now(timezone.utc).isoformat()
    require(not (OUT / 'fault-report.json').exists(), 'Preserve previous fault evidence')
    (OUT / 'child').mkdir()
    report = {'schema': 'expertauth-python-probe-cleanup-fault-v1', 'started': started,
              'foundation_passed': False, 'rows': [], 'errors': [], 'skipped': 0,
              'limits': ['Harness transport-failure cleanup only; authentication parity and independent review remain unqualified.',
                         'One local auxiliary signout connection is dropped before forwarding; no database outage or engine failure.']}
    server = None
    before = None
    with httpx.Client(timeout=10, trust_env=False) as core:
        try:
            before = identities(core)
            server = ThreadingHTTPServer(('0.0.0.0', 8300), Proxy)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            child = subprocess.run([sys.executable, str(ROOT / 'tests/clients/python_probe.py'), '--url', ORIGIN,
                                    '--origin', ORIGIN, '--evidence-dir', str(OUT / 'child'), '--cleanup-created-users'],
                                   capture_output=True, text=True, timeout=75)
            (OUT / 'child-output.log').write_text(redact(child.stdout + child.stderr))
            result = json.loads((OUT / 'child/probe-report.json').read_text())
            after = identities(core)
            report['child_exit_code'] = child.returncode
            report['child_summary'] = {key: result.get(key) for key in
                                       ['executed', 'passed', 'failed', 'unexecuted', 'skipped', 'exit_code', 'harness_error', 'synthetic_cleanup']}
            require(signouts == 2 and drops == 1 and len(created) == 1, 'Expected exactly two signouts, one dropped request and one created user')
            require(not any(row['outcome'] == 'proxy-error' for row in requests), 'Unexpected proxy forwarding failure')
            report['rows'].append({'id': 'PY-PROBE-AUXILIARY-SIGNOUT-TRANSPORT-FAULT', 'status': 'passed',
                                   'signout_requests': signouts, 'dropped_before_forward': drops,
                                   'forwarded_signouts': sum(row['path'] == '/auth/signout' and row['outcome'] == 'forwarded' for row in requests)})
            require(child.returncode != 0 and result['exit_code'] != 0 and result['unexecuted'] > 0 and
                    result.get('harness_error') == 'RemoteProtocolError' and result['skipped'] == 0,
                    'Transport failure was not preserved as an incomplete failed probe')
            report['rows'].append({'id': 'PY-PROBE-FAILURE-EVIDENCE-PRESERVED', 'status': 'passed',
                                   'error': result['harness_error'], 'unexecuted': result['unexecuted']})
            require(result['synthetic_cleanup'] == {'requested': True, 'created': 1, 'removed': 1},
                    'Probe did not remove its one synthetic user')
            require(created.isdisjoint(before) and created.isdisjoint(after) and before == after,
                    'Core identity preservation or synthetic deletion differs')
            report['rows'].append({'id': 'PY-PROBE-OWN-USER-REMOVED-OTHERS-PRESERVED', 'status': 'passed',
                                   'created': 1, 'removed_by_child': 1, 'other_identity_count': len(before),
                                   'before_after_identity_set_sha256': hashlib.sha256('\n'.join(sorted(before)).encode()).hexdigest()})
            for path in OUT.rglob('*'):
                if path.is_file():
                    text = path.read_text()
                    require(all(not value or value not in text for value in secrets), 'Secret leaked into child evidence')
                    require(not re.search(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', text), 'JWT shape in evidence')
            report['rows'].append({'id': 'PY-PROBE-FAULT-EVIDENCE-REDACTED', 'status': 'passed'})
        except Exception as error:
            report['errors'].append(str(error) if isinstance(error, AssertionError) else type(error).__name__)
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            # Failure compensation may remove only IDs actually seen created by
            # this proxy and absent from the pre-run set. It never counts as pass.
            compensated = 0
            try:
                remaining = identities(core)
                for user in (created - (before or set())) & remaining:
                    response = core.post('http://core-a:3567/user/remove', headers={'api-key': KEY, 'cdi-version': '5.4'},
                                         json={'userId': user, 'removeAllLinkedAccounts': False})
                    require(response.status_code == 200 and response.json().get('status') == 'OK', 'Fallback synthetic cleanup failed')
                    compensated += 1
                if compensated:
                    report['errors'].append('Parent probe left synthetic users; fault harness compensated')
            except Exception as error:
                report['errors'].append('Fallback cleanup: ' + type(error).__name__)
            report['fallback_users_removed'] = compensated
    report['requests'] = requests
    report['passed'] = len(report['rows'])
    report['failed'] = len(report['errors'])
    report['probe_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report['finished'] = datetime.now(timezone.utc).isoformat()
    with (OUT / 'fault-report.json').open('x') as stream:
        stream.write(redact(json.dumps(report, indent=2)) + '\n')
    passed = len(report['rows']) == 4 and not report['errors']
    print(json.dumps({'fault_regression_passed': passed, 'checks': report['passed'], 'errors': report['errors']}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
