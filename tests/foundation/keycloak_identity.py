"""Owned-provider Keycloak broker/link characterization with real browser+PKCE.

No password grant, bearer seeding, fabricated callback, or existing realm edits.
Account APIs mutate only users in this run's uniquely named fixture realms.
"""
from __future__ import annotations
import base64
import concurrent.futures
import hashlib
from html.parser import HTMLParser
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

BASE = 'http://keycloak:8080'
REDIRECT = 'http://app.example.test/callback'
OUT = Path('evidence/foundation/keycloak-identity')
PASSWORD = secrets.token_urlsafe(30)
RESULTS, JOURNAL = [], []
RUN = str(time.time_ns())[-12:]
PREFIX = 'ea-broker-' + RUN

def claim(token):
    # Token inspection only. Server validates signed provider JWTs during brokering.
    raw = token.split('.')[1]
    return json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)))

def fingerprint(value):
    return hashlib.sha256(str(value).encode()).hexdigest()[:16]

def record(test_id, actual, expected, requirements, note):
    passed = actual == expected
    RESULTS.append({'test_id': test_id, 'actual': actual, 'expected': expected,
                    'outcome': 'passed' if passed else 'failed', 'requirements': requirements,
                    'qualification_scope': 'Bounded Keycloak candidate characterization only', 'note': note})
    print(f'{test_id}: {"PASS" if passed else "FAIL"} {actual!r}', flush=True)
    return passed

def request(method, path, data=None, token=None, form=False, opener=None, origin=None):
    headers = {'Accept': 'application/json' if token else '*/*'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if origin:
        headers['Origin'] = origin
    if data is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        data = (urllib.parse.urlencode(data) if form else json.dumps(data)).encode()
    req = urllib.request.Request(path if path.startswith('http') else BASE + path, data=data, headers=headers, method=method)
    try:
        response = (opener or urllib.request.build_opener()).open(req, timeout=25)
    except urllib.error.HTTPError as exc:
        response = exc
    raw = response.read().decode()
    try:
        body = json.loads(raw)
    except ValueError:
        body = raw
    return response.status, body, dict(response.headers), response.url

class Forms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.current, self.text = [], None, []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.current = {'id': attrs.get('id'), 'action': attrs.get('action'), 'fields': {}, 'buttons': {}}
            self.forms.append(self.current)
        if self.current is not None and tag in ('input', 'button') and attrs.get('name'):
            kind = 'buttons' if tag == 'button' or attrs.get('type') == 'submit' else 'fields'
            self.current[kind][attrs['name']] = attrs.get('value', '')
    def handle_endtag(self, tag):
        if tag == 'form':
            self.current = None
    def handle_data(self, data):
        if data.strip():
            self.text.append(data.strip())

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.startswith(REDIRECT):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def browser():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())

def begin(realm, client, *, provider=None, action=None, opener=None, prompt=None):
    verifier = secrets.token_urlsafe(48)
    values = {'client_id': client, 'redirect_uri': REDIRECT, 'response_type': 'code', 'scope': 'openid',
              'state': secrets.token_urlsafe(24), 'nonce': secrets.token_urlsafe(24), 'code_challenge_method': 'S256',
              'code_challenge': base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')}
    if provider:
        values['kc_idp_hint'] = provider
    if action:
        values['kc_action'] = action
    if prompt:
        values['prompt'] = prompt
    opener = opener or browser()
    response = request('GET', f'/realms/{realm}/protocol/openid-connect/auth?' + urllib.parse.urlencode(values), opener=opener)
    return {'realm': realm, 'client': client, 'verifier': verifier, 'state': values['state'], 'opener': opener,
            'response': response, 'provider': provider, 'action': action}

def finish(flow, *, upstream_user='same-provider', local_user=None, wrong_password=False, cancel_link=False, stop_at_provider_login=False, max_forms=12):
    status, body, headers, url = flow['response']
    for step in range(max_forms):
        url_path = urllib.parse.urlparse(url).path
        if status == 302 and headers.get('Location', '').startswith(REDIRECT):
            params = urllib.parse.parse_qs(urllib.parse.urlparse(headers['Location']).query)
            assert params.get('state') == [flow['state']], 'OAuth state mismatch'
            if 'error' in params:
                return {'kind': 'oauth-error', 'error': params['error'][0], 'code_issued': False, 'flow': flow}
            assert 'code' in params, 'No OAuth code or error at callback'
            status, tokens, _, _ = request('POST', f'/realms/{flow["realm"]}/protocol/openid-connect/token',
                {'grant_type': 'authorization_code', 'client_id': flow['client'], 'redirect_uri': REDIRECT,
                 'code': params['code'][0], 'code_verifier': flow['verifier']}, form=True)
            assert status == 200, f'PKCE code exchange failed HTTP{status}'
            return {'kind': 'tokens', 'tokens': tokens, 'claims': claim(tokens['access_token']),
                    'code_issued': True, 'aia_status': params.get('kc_action_status'), 'flow': flow}
        parser = Forms()
        if isinstance(body, str):
            parser.feed(body)
        JOURNAL.append({'realm': flow['realm'], 'step': step, 'status': status, 'path': url_path,
                        'forms': [{'id': form['id'], 'fields': sorted(form['fields']), 'buttons': form['buttons'],
                                   'action_path': urllib.parse.urlparse(form['action'] or '').path} for form in parser.forms]})
        if status != 200 or not parser.forms:
            safe_text = [text for text in parser.text if any(word in text.lower() for word in ('link', 'error', 'invalid', 'account', 'password'))]
            return {'kind': 'intermediate', 'http_status': status, 'path': url_path, 'code_issued': False,
                    'page_messages': safe_text[:12], 'flow': flow}
        form = next((item for item in parser.forms if item['action']), None)
        if not form:
            return {'kind': 'no-action-form', 'code_issued': False, 'flow': flow}
        fields = dict(form['fields'])
        password_submitted = False
        if 'username' in fields or 'password' in fields:
            current_realm = url_path.split('/realms/', 1)[-1].split('/')[0]
            if current_realm.endswith('-idp') and stop_at_provider_login:
                flow['response'] = (status, body, headers, url)
                return {'kind': 'provider-proof-required', 'code_issued': False, 'flow': flow}
            username = upstream_user if current_realm.endswith('-idp') else local_user
            if not username:
                return {'kind': 'requires-local-proof', 'code_issued': False, 'path': url_path, 'flow': flow}
            if 'username' in fields:
                fields['username'] = username
            if 'password' in fields:
                fields['password'] = 'deliberately-wrong-synthetic-password' if wrong_password else PASSWORD
                password_submitted = True
        elif flow['action'] and cancel_link:
            fields['cancel-aia'] = 'true'
        elif 'submitAction' in form['buttons']:
            fields['submitAction'] = 'linkAccount'
        elif form['buttons']:
            # Confirm supported AIA and first-broker forms with their own actual fields.
            fields.update(next(iter(form['buttons'].items())) and dict([next(iter(form['buttons'].items()))]))
        status, body, headers, url = request('POST', urllib.parse.urljoin(url, form['action']), fields, form=True, opener=flow['opener'])
        if wrong_password and password_submitted:
            flow['response'] = (status, body, headers, url)
            return {'kind': 'wrong-password-result', 'http_status': status, 'code_issued': status == 302 and 'code=' in headers.get('Location', ''), 'flow': flow}
    return {'kind': 'form-limit', 'code_issued': False, 'flow': flow}

def success(outcome):
    assert outcome['kind'] == 'tokens', 'Browser broker outcome: ' + json.dumps({k:v for k,v in outcome.items() if k != 'flow'})
    return outcome

def admin_user(admin, realm, username, *, email=None, password=True):
    payload = {'username': username, 'email': email or username + '@example.test', 'emailVerified': True,
               'firstName': 'Synthetic', 'lastName': 'Characterization', 'enabled': True}
    if password:
        payload['credentials'] = [{'type': 'password', 'value': PASSWORD, 'temporary': False}]
    status, _, headers, _ = request('POST', f'/admin/realms/{realm}/users', payload, admin)
    assert status == 201, f'User fixture create HTTP{status}'
    return headers['Location'].rsplit('/', 1)[-1]

def api_links(admin, realm, subject):
    status, links, _, _ = request('GET', f'/admin/realms/{realm}/users/{subject}/federated-identity', token=admin)
    assert status == 200
    return links

def main():
    status, auth, _, _ = request('POST', '/realms/master/protocol/openid-connect/token',
        {'grant_type': 'client_credentials', 'client_id': os.environ['KC_BOOTSTRAP_ADMIN_CLIENT_ID'],
         'client_secret': os.environ['KC_BOOTSTRAP_ADMIN_CLIENT_SECRET']}, form=True)
    assert status == 200, 'Bootstrap service account token unavailable'
    admin = auth['access_token']
    provider_realm = PREFIX + '-idp'
    apps = [PREFIX + '-a', PREFIX + '-b']
    realms = [provider_realm] + apps
    for realm in realms:
        status, _, _, _ = request('POST', '/admin/realms', {'realm': realm, 'enabled': True, 'sslRequired': 'none',
            'duplicateEmailsAllowed': True, 'loginWithEmailAllowed': False, 'registrationEmailAsUsername': False}, admin)
        assert status == 201, f'Realm fixture create HTTP{status}'
    upstream_subject = admin_user(admin, provider_realm, 'same-provider', email='same@example.test')
    other_upstream_subject = admin_user(admin, provider_realm, 'other-provider', email='same@example.test')
    secret = secrets.token_urlsafe(32)
    callbacks = [f'{BASE}/realms/{realm}/broker/{alias}/endpoint' for realm in apps for alias in ('alpha-provider', 'beta-provider', 'shared-provider', 'extra-provider', 'race-provider')]
    status, _, _, _ = request('POST', f'/admin/realms/{provider_realm}/clients', {'clientId': 'broker-client', 'enabled': True,
        'publicClient': False, 'secret': secret, 'standardFlowEnabled': True, 'directAccessGrantsEnabled': False,
        'redirectUris': callbacks, 'attributes': {'pkce.code.challenge.method': 'S256'}}, admin)
    assert status == 201
    for realm in apps:
        for tenant in ('alpha', 'beta'):
            status, _, _, _ = request('POST', f'/admin/realms/{realm}/clients', {'clientId': tenant, 'enabled': True,
                'publicClient': True, 'standardFlowEnabled': True, 'directAccessGrantsEnabled': False,
                'fullScopeAllowed': True, 'redirectUris': [REDIRECT], 'webOrigins': ['http://app.example.test'],
                'attributes': {'pkce.code.challenge.method': 'S256'}}, admin)
            assert status == 201
        for alias in ('alpha-provider', 'beta-provider', 'shared-provider', 'extra-provider', 'race-provider'):
            provider = {'alias': alias, 'providerId': 'oidc', 'enabled': True, 'trustEmail': True,
                'firstBrokerLoginFlowAlias': 'first broker login', 'config': {'clientId': 'broker-client', 'clientSecret': secret,
                'authorizationUrl': f'{BASE}/realms/{provider_realm}/protocol/openid-connect/auth',
                'tokenUrl': f'{BASE}/realms/{provider_realm}/protocol/openid-connect/token',
                'userInfoUrl': f'{BASE}/realms/{provider_realm}/protocol/openid-connect/userinfo',
                'jwksUrl': f'{BASE}/realms/{provider_realm}/protocol/openid-connect/certs',
                'issuer': f'{BASE}/realms/{provider_realm}', 'useJwksUrl': 'true', 'validateSignature': 'true',
                'pkceEnabled': 'true', 'pkceMethod': 'S256', 'defaultScope': 'openid profile email', 'syncMode': 'IMPORT'}}
            status, _, _, _ = request('POST', f'/admin/realms/{realm}/identity-provider/instances', provider, admin)
            assert status == 201
            status, _, _, _ = request('POST', f'/admin/realms/{realm}/identity-provider/instances/{alias}/mappers',
                {'name': 'tenant-qualified-username', 'identityProviderAlias': alias, 'identityProviderMapper': 'oidc-username-idp-mapper',
                 'config': {'template': '${ALIAS}.${CLAIM.preferred_username}', 'target': 'LOCAL', 'syncMode': 'INHERIT'}}, admin)
            assert status == 201
    identities = {}
    for realm in apps:
        for tenant in ('alpha', 'beta'):
            outcome = success(finish(begin(realm, tenant, provider=tenant + '-provider')))
            subject = outcome['claims']['sub']
            identities[realm, tenant] = outcome
            links = api_links(admin, realm, subject)
            record('KC-BROKER-PROVIDER-SUB-' + realm[-1] + '-' + tenant,
                   len(links) == 1 and links[0]['userId'] == upstream_subject and links[0]['identityProvider'] == tenant + '-provider',
                   True, ['SOC-002', 'SOC-003', 'IDN-003'], 'Actual signed local OIDC provider authentication and PKCE token exchange; no admin-created identity link.')
    record('KC-BROKER-APP-TENANT-ISOLATION', len({outcome['claims']['sub'] for outcome in identities.values()}), 4,
           ['IDN-001', 'IDN-003'], 'Same upstream issuer/subject/email across two applications and two provider aliases per realm yields four isolated engine users.')
    substituted = success(finish(begin(apps[0], 'alpha', provider='beta-provider')))
    RESULTS.append({'test_id': 'KC-BROKER-ALIAS-SUBSTITUTION', 'outcome': 'observed',
                    'alpha_client_accepts_beta_provider_identity': substituted['claims']['sub'] == identities[apps[0], 'beta']['claims']['sub'],
                    'requirements': ['IDN-003', 'IDN-010'],
                    'note': 'Provider alias namespacing alone is not tenant authorization. An explicit client/tenant provider policy still must reject substitution.'})
    for realm in apps:
        shared_a = success(finish(begin(realm, 'alpha', provider='shared-provider')))
        shared_b = success(finish(begin(realm, 'beta', provider='shared-provider')))
        record('KC-BROKER-SHARED-ALIAS-' + realm[-1], shared_a['claims']['sub'] == shared_b['claims']['sub'], True,
               ['IDN-004'], 'Explicitly configured shared provider alias reuses the same engine identity; tenant session/membership/permissions require separate policy qualification.')
    realm = apps[0]
    victim = identities[realm, 'alpha']
    subject = victim['claims']['sub']
    status, credentials, _, _ = request('GET', f'/admin/realms/{realm}/users/{subject}/credentials', token=admin)
    record('KC-BROKER-FEDERATED-CREDENTIAL-INVENTORY', status == 200 and credentials == [], True, ['IDN-005'],
           'Federated-only user has stable engine user ID and provider tuple; imported login does not silently create a password credential.')
    # Supported account API must prevent removing the sole login method.
    status, body, _, _ = request('DELETE', f'/realms/{realm}/account/linked-accounts/alpha-provider',
                                token=victim['tokens']['access_token'], origin='http://app.example.test')
    record('KC-BROKER-LAST-METHOD-UNLINK', status == 400 and len(api_links(admin, realm, subject)) == 1, True, ['LNK-006'],
           'Self-service account unlink rejects sole provider with no password. An unauthorized response would not count as policy enforcement.')
    # AIA obtains proof at a second real provider login. A new browser requires local proof first.
    link = begin(realm, 'alpha', action='idp_link:extra-provider', opener=victim['flow']['opener'])
    linked = finish(link)
    record('KC-BROKER-AIA-LINK', linked['kind'] == 'tokens' and len(api_links(admin, realm, subject)) == 2, True, ['LNK-003', 'LNK-005'],
           'Supported idp_link AIA confirmed by user and followed through real owned-provider authentication; no administrative link insertion.')
    if linked['kind'] != 'tokens':
        RESULTS.append({'test_id': 'KC-BROKER-AIA-DIAGNOSTIC', 'outcome': 'observed', 'details': {k:v for k,v in linked.items() if k != 'flow'}})
    else:
        record('KC-BROKER-LINK-STABLE-PRIMARY', linked['claims']['sub'] == subject, True, ['IDN-005', 'LNK-005'],
               'Engine user subject remains stable after supported linking. No separate recipe-user UUID is exposed by this native model.')
    # A separate local account proves that existing-account and provider proofs are distinct.
    local_subject = admin_user(admin, realm, 'local-target')
    rejected_local = finish(begin(realm, 'alpha', action='idp_link:extra-provider'), local_user='local-target', wrong_password=True)
    record('KC-BROKER-WRONG-LOCAL-PROOF', rejected_local['kind'] == 'wrong-password-result' and not rejected_local['code_issued'] and api_links(admin, realm, local_subject) == [],
           True, ['LNK-003'], 'Incorrect actual local credential does not authorize linking or issue an authorization code.')
    local_login = success(finish(begin(realm, 'alpha'), local_user='local-target'))
    staged = finish(begin(realm, 'alpha', action='idp_link:extra-provider', opener=local_login['flow']['opener']), stop_at_provider_login=True)
    record('KC-BROKER-PROVIDER-PROOF-REQUIRED', staged['kind'] == 'provider-proof-required', True, ['LNK-003'],
           'Authenticated local account and user confirmation alone do not establish ownership of the new provider identity.')
    if staged['kind'] == 'provider-proof-required':
        denied_provider = finish(staged['flow'], wrong_password=True)
        record('KC-BROKER-WRONG-PROVIDER-PROOF', denied_provider['kind'] == 'wrong-password-result' and not denied_provider['code_issued'] and api_links(admin, realm, local_subject) == [],
               True, ['LNK-003', 'SOC-004'], 'Incorrect owned-provider password rejects linking; no fabricated callback or seeded bearer token.')
        conflict = finish(denied_provider['flow'])
        record('KC-BROKER-EXISTING-OWNER-CONFLICT', conflict['kind'] != 'tokens' and api_links(admin, realm, local_subject) == [] and len(api_links(admin, realm, subject)) == 2,
               True, ['LNK-002', 'LNK-003', 'LNK-007'], 'Valid control of a provider identity already owned by another primary does not transfer ownership.')
        RESULTS.append({'test_id': 'KC-BROKER-CONFLICT-DIAGNOSTIC', 'outcome': 'observed', 'details': {k:v for k,v in conflict.items() if k != 'flow'}})
    # Race two supported AIA flows at the final real provider-credential submission.
    contenders = []
    for number in range(2):
        username = 'race-target-' + str(number)
        contender_subject = admin_user(admin, realm, username)
        authenticated = success(finish(begin(realm, 'alpha'), local_user=username))
        staged = finish(begin(realm, 'alpha', action='idp_link:race-provider', opener=authenticated['flow']['opener']), stop_at_provider_login=True)
        assert staged['kind'] == 'provider-proof-required', 'Concurrent link fixture did not reach actual provider proof'
        contenders.append((contender_subject, staged['flow']))
    import threading
    barrier = threading.Barrier(2)
    def complete_link(contender):
        barrier.wait(timeout=10)
        return finish(contender[1], upstream_user='other-provider')
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        competing = list(pool.map(complete_link, contenders))
    persisted_links = [api_links(admin, realm, contender[0]) for contender in contenders]
    owner_counts = [len(links) for links in persisted_links]
    record('KC-BROKER-CONCURRENT-LINK-OWNERSHIP', sum(owner_counts), 1, ['IDN-012', 'LNK-007'],
           'Two actual provider callbacks for one provider alias/subject must leave exactly one primary owner; single-node bounded race.')
    RESULTS.append({'test_id': 'KC-BROKER-CONCURRENT-LINK-DETAILS', 'outcome': 'observed',
                    'browser_outcomes': [outcome['kind'] for outcome in competing], 'owner_counts': owner_counts,
                    'persisted_provider_aliases': [[link['identityProvider'] for link in links] for links in persisted_links],
                    'all_links_match_same_real_provider_subject': all(link['userId'] == other_upstream_subject for links in persisted_links for link in links),
                    'owner_fingerprints': [fingerprint(contender[0]) for contender in contenders],
                    'expected_provider_subject_fingerprint': fingerprint(other_upstream_subject),
                    'provider_subject_fingerprints': [[fingerprint(link['userId']) for link in links] for links in persisted_links],
                    'note': 'Does not establish a two-replica race guarantee.'})
    # Self-service last-method protection must survive parallel unlinks, not only sequential checks.
    def unlink(alias):
        return request('DELETE', f'/realms/{realm}/account/linked-accounts/{alias}',
                       token=victim['tokens']['access_token'], origin='http://app.example.test')[0]
    barrier = threading.Barrier(2)
    def concurrent_unlink(alias):
        barrier.wait(timeout=10)
        return unlink(alias)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        unlink_statuses = list(pool.map(concurrent_unlink, ['alpha-provider', 'extra-provider']))
    remaining = api_links(admin, realm, subject)
    record('KC-BROKER-CONCURRENT-LAST-METHOD', len(remaining) >= 1, True, ['LNK-006', 'LNK-007'],
           'Parallel self-service unlink of both real linked providers must preserve a valid remaining authentication method.')
    RESULTS.append({'test_id': 'KC-BROKER-CONCURRENT-UNLINK-DETAILS', 'outcome': 'observed',
                    'http_statuses': unlink_statuses, 'remaining_provider_count': len(remaining)})
    # Observe authoritative refresh-state consequences after method mutation.
    refresh_status, refresh_body, _, _ = request('POST', f'/realms/{realm}/protocol/openid-connect/token',
        {'grant_type': 'refresh_token', 'client_id': 'alpha', 'refresh_token': victim['tokens']['refresh_token']}, form=True)
    RESULTS.append({'test_id': 'KC-BROKER-UNLINK-SESSION-CONSEQUENCE', 'outcome': 'observed',
                    'refresh_http_status': refresh_status, 'refresh_succeeded': refresh_status == 200,
                    'same_primary_after_refresh': claim(refresh_body['access_token'])['sub'] == subject if refresh_status == 200 else None,
                    'requirements': ['LNK-008'], 'note': 'Native unlink does not imply session revocation. Product policy still needs explicit definition and proof.'})
    RESULTS.append({'test_id': 'KC-BROKER-METHOD-ID-MODEL-GAP', 'outcome': 'unverified',
                    'requirements': ['IDN-005', 'LNK-006', 'LNK-008'],
                    'note': 'Native primary UUID is stable; provider method is exposed as alias plus upstream subject, with no standalone recipe-user UUID or split lifecycle. A stable explicit compatibility mapping is still needed.'})
    # A separate app tests the positive sequential unlink and post-unlink method lifecycle.
    other_realm = apps[1]
    sequential = identities[other_realm, 'alpha']
    sequential_sub = sequential['claims']['sub']
    success(finish(begin(other_realm, 'alpha', action='idp_link:extra-provider', opener=sequential['flow']['opener'])))
    status, _, _, _ = request('DELETE', f'/realms/{other_realm}/account/linked-accounts/extra-provider',
                            token=sequential['tokens']['access_token'], origin='http://app.example.test')
    remaining = api_links(admin, other_realm, sequential_sub)
    record('KC-BROKER-SEQUENTIAL-UNLINK', status == 204 and len(remaining) == 1 and remaining[0]['identityProvider'] == 'alpha-provider',
           True, ['LNK-006'], 'Supported self-service unlink preserves the remaining provider in a sequential positive case.')
    existing = success(finish(begin(other_realm, 'alpha', provider='alpha-provider')))
    recreated = success(finish(begin(other_realm, 'alpha', provider='extra-provider')))
    record('KC-BROKER-UNLINK-REMAINING-LOGIN', existing['claims']['sub'] == sequential_sub, True, ['LNK-006'],
           'Remaining provider authenticates to the original stable primary after unlink.')
    RESULTS.append({'test_id': 'KC-BROKER-UNLINK-METHOD-LIFECYCLE', 'outcome': 'observed',
                    'unlinked_provider_creates_distinct_primary_on_next_login': recreated['claims']['sub'] != sequential_sub,
                    'same_upstream_provider_subject': api_links(admin, other_realm, recreated['claims']['sub'])[0]['userId'] == upstream_subject,
                    'requirements': ['IDN-005', 'LNK-006'],
                    'note': 'Keycloak native method lifecycle imports a new primary after unlink. Stable SuperTokens recipe-user identity semantics need a separately specified mapping.'})

if __name__ == '__main__':
    OUT.mkdir(parents=True, exist_ok=True)
    started = time.time()
    error = None
    try:
        main()
    except Exception as exc:
        error = str(exc)
        print('HARNESS_OR_FLOW_ERROR: ' + error, flush=True)
    report = {'engine': 'Keycloak', 'version': '26.7.3', 'source_commit': '6d238b6558037085cc25c915893c3d301a80243e',
              'run': RUN, 'fixture_realm_prefix': PREFIX, 'elapsed_seconds': round(time.time() - started, 3),
              'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'results': RESULTS, 'browser_steps': JOURNAL, 'error': error, 'foundation_passed': False,
              'production_approved': False, 'provider_qualification': 'Owned local OIDC provider realm; not a third-party live-provider test',
              'unqualified': ['Independent tenant session/permission policy', 'Recipe-method identity lifecycle mapping',
                              'Multi-replica and repeated-race qualification', 'Session consequences and recent-authentication policy',
                              'Native/live third-party providers and independent security review']}
    attempt = OUT / 'attempts' / RUN
    attempt.mkdir(parents=True, exist_ok=True)
    (attempt / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    (OUT / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': sum(item.get('outcome') == 'passed' for item in RESULTS),
                      'failed': sum(item.get('outcome') == 'failed' for item in RESULTS), 'error': error, 'foundation_passed': False}))
    raise SystemExit(1 if error else 0)
