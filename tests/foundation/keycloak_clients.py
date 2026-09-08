"""Real candidate backend qualification. Never serializes credentials or engine tokens."""
import argparse
import base64
import concurrent.futures
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys
import time
import unittest
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
CLIENT_DIR = ROOT / 'examples/keycloak-clients'
spec = importlib.util.spec_from_file_location('candidate_client', CLIENT_DIR / 'python_client.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
CandidateClient = module.CandidateClient


class ClientProof(unittest.TestCase):
    def client(self):
        client = CandidateClient(self.origin)
        status, _ = client.request('/candidate/csrf')
        self.assertEqual(status, 200)
        return client

    def started(self):
        client = self.client()
        status, result = client.begin()
        self.assertEqual((status, result.get('step'), result.get('authenticated')), (200, 'password', False))
        self.assertNotIn('action', result)
        return client

    def test_01_python_password_totp_resource_refresh_logout(self):
        client = self.started()
        self.assertEqual(client.resource()[0], 401)
        user = self.fixtures['users']['client-python']
        status, result = client.password(user['username'], user['password'])
        self.assertEqual((status, result.get('step'), result.get('authenticated')), (200, 'totp', False))
        self.assertEqual(client.resource()[0], 401, 'Password alone must not create privileges')
        status, result = client.totp(self.pyotp.TOTP(user['otp_secret']).now())
        self.assertEqual((status, result.get('status'), result.get('authenticated')), (200, 'AUTHENTICATED', True))
        self.assertNotIn('access_token', result)
        self.assertNotIn('refresh_token', result)
        self.assertEqual(client.resource()[0], 200)
        self.assertEqual(client.resource('beta')[0], 403)
        self.assertEqual(client.refresh()[0], 200)
        saved = [copy.copy(cookie) for cookie in client.cookies]
        self.assertEqual(client.logout()[0], 200)
        self.assertEqual(client.resource()[0], 401)
        replay = self.client()
        for cookie in saved:
            if cookie.name.endswith('refresh'):
                replay.cookies.set_cookie(copy.copy(cookie))
        self.assertEqual(replay.refresh()[0], 401, 'Private engine must deny revoked refresh token')

    def test_02_missing_csrf_rejected(self):
        self.assertEqual(self.client().request('/candidate/start', {'tenant': 'alpha'}, csrf=False)[0], 403)

    def test_03_cross_origin_rejected(self):
        self.assertEqual(self.client().request('/candidate/start', {'tenant': 'alpha'}, origin='https://attacker.example')[0], 403)

    def test_04_unsupported_tenant_rejected(self):
        self.assertEqual(self.client().begin('beta')[0], 403)

    def test_05_action_url_injection_rejected(self):
        client = self.started()
        self.assertEqual(client.step(action='http://attacker.example/steal', username='x', password='x')[0], 400)

    def test_06_cross_browser_transaction_rejected(self):
        first = self.started()
        second = self.client()
        second.challenge = copy.deepcopy(first.challenge)
        self.assertEqual(second.password('x', 'x')[0], 409)

    def test_07_wrong_password_keeps_unauthenticated_state(self):
        client = self.started()
        status, result = client.password('nonexistent-' + str(time.time_ns()), 'synthetic-invalid-password')
        self.assertEqual((status, result.get('step'), result.get('error')), (401, 'password', 'AUTHENTICATION_FAILED'))
        self.assertEqual(client.resource()[0], 401)

    def test_08_consumed_action_replay_rejected(self):
        client = self.started()
        held = copy.deepcopy(client.challenge)
        self.assertEqual(client.password('nonexistent-' + str(time.time_ns()), 'synthetic-invalid-password')[0], 401)
        client.challenge = held
        self.assertEqual(client.password('x', 'x')[0], 409)

    def test_09_concurrent_action_has_one_owner(self):
        client = self.started()
        peer = self.client()
        for cookie in client.cookies:
            peer.cookies.set_cookie(copy.copy(cookie))
        peer.csrf = client.csrf
        peer.challenge = copy.deepcopy(client.challenge)
        user = self.fixtures['users']['client-negative']
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(candidate.password, user['username'], user['password']) for candidate in (client, peer)]
            statuses = sorted(future.result()[0] for future in futures)
        self.assertEqual(statuses, [200, 409])

    def test_10_wrong_totp_keeps_unauthenticated_state(self):
        client = self.started()
        user = self.fixtures['users']['client-negative']
        self.assertEqual(client.password(user['username'], user['password'])[0], 200)
        valid = self.pyotp.TOTP(user['otp_secret']).now()
        invalid = '000001' if valid == '000000' else '000000'
        status, result = client.totp(invalid)
        self.assertEqual((status, result.get('step'), result.get('authenticated')), (401, 'totp', False))
        self.assertEqual(client.resource()[0], 401)

    def test_11_factor_out_of_order_rejected(self):
        self.assertEqual(self.started().step(otp='123456')[0], 400)

    def test_12_public_callback_injection_rejected(self):
        self.assertEqual(self.client().request('/candidate/callback?code=attacker&state=attacker')[0], 400)

    def test_13_unsigned_or_malformed_access_rejected(self):
        client = self.client()
        encode = lambda obj: base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip('=')
        forged = encode({'alg': 'none'}) + '.' + encode({'sub': 'attacker', 'organization': {'alpha': {}}}) + '.'
        self.assertEqual(client.request('/candidate/resource?tenant=alpha', authorization='Bearer ' + forged)[0], 401)
        self.assertEqual(client.request('/candidate/resource?tenant=alpha', authorization='Bearer malformed')[0], 401)

    def test_14_refresh_without_session_rejected(self):
        self.assertEqual(self.client().refresh()[0], 401)

    def test_15_refresh_rejects_caller_supplied_token(self):
        self.assertEqual(self.client().request('/candidate/refresh', {'refresh_token': 'attacker'})[0], 400)

    def test_16_unicode_action_rejected_safely(self):
        client = self.started()
        client.challenge['actionToken'] = '\u00e9' * len(client.challenge['actionToken'])
        self.assertEqual(client.password('x', 'x')[0], 409)

    def test_17_python_client_rejects_external_url(self):
        with self.assertRaises(ValueError):
            self.client().request('//attacker.example/steal')


class RedactedResult(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.outcomes = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.outcomes.append({'id': test.id(), 'status': 'passed'})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.outcomes.append({'id': test.id(), 'status': 'failed', 'error_type': err[0].__name__,
                              'detail': str(err[1])}) # Assertions compare only allowlisted statuses/state, never credentials.

    def addError(self, test, err):
        super().addError(test, err)
        self.outcomes.append({'id': test.id(), 'status': 'error', 'error_type': err[0].__name__})

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.outcomes.append({'id': test.id(), 'status': 'skipped', 'detail': reason})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--origin', default='http://expertauth-kc-clients-node:3000')
    parser.add_argument('--fixtures', type=pathlib.Path, default=ROOT / 'engine-extensions/keycloak-headless/.runtime/fixtures.json')
    parser.add_argument('--output', type=pathlib.Path, default=ROOT / 'evidence/foundation/keycloak-clients/http-results.json')
    args = parser.parse_args()
    import pyotp
    ClientProof.pyotp = pyotp
    ClientProof.origin = args.origin
    ClientProof.fixtures = json.loads(args.fixtures.read_text())
    result = RedactedResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(ClientProof).run(result)
    hashes = {str(path.relative_to(ROOT)).replace('\\', '/'): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in [pathlib.Path(__file__), *CLIENT_DIR.glob('*.mjs'), *CLIENT_DIR.glob('*.py'),
                           *CLIENT_DIR.glob('*.jsx'), CLIENT_DIR / 'package.json', CLIENT_DIR / 'package-lock.json',
                           CLIENT_DIR / 'requirements-test.txt', CLIENT_DIR / 'Dockerfile']}
    report = {'recorded_at': datetime.now(timezone.utc).isoformat(), 'profile': 'candidate-python-to-node-to-private-keycloak-json-spi',
              'auth_completion': False, 'foundation_passed': False, 'source_sha256': hashes, 'tests': result.outcomes,
              'summary': {'executed': result.testsRun, 'passed': sum(row['status'] == 'passed' for row in result.outcomes),
                          'failed': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped)},
              'limits': ['Single candidate backend/engine instance; no durable preauth failover',
                         'Password/TOTP proof only; original SDK families and 205 API contract not qualified',
                         'No independent human security review',
                         'Resource verification is offline JWT; previously copied access JWT remains usable until expiry']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    suffix = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    exact = args.output.with_name(args.output.stem + '-' + suffix + args.output.suffix)
    data = json.dumps(report, indent=2) + '\n'
    exact.write_text(data)
    args.output.write_text(data)
    print(json.dumps({'profile': report['profile'], 'summary': report['summary'], 'artifact': str(exact), 'auth_completion': False}))
    return 0 if result.wasSuccessful() and not result.skipped and result.testsRun else 1


if __name__ == '__main__':
    raise SystemExit(main())
