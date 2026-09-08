"""Real Keycloak API/browser-form characterization, no password grant or mocks.

The initial mapping is app=realm, tenant=client; a second probe adds real organizations.
Negative outcomes reject THIS mapping; they are not universal impossibility claims.
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
import urllib.error
import urllib.parse
import urllib.request

BASE = 'http://keycloak:8080'
OUT = Path('evidence/foundation/keycloak')
RESULTS = []
PASSWORD = secrets.token_urlsafe(24)

def request(method, path, data=None, token=None, *, form=False, opener=None):
    headers = {}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if data is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        data = (urllib.parse.urlencode(data) if form else json.dumps(data)).encode()
    req = urllib.request.Request(path if path.startswith('http') else BASE + path, data=data, headers=headers, method=method)
    try:
        response = opener.open(req, timeout=20) if opener else urllib.request.urlopen(req, timeout=20)
    except urllib.error.HTTPError as e:
        response = e
    body = response.read().decode()
    try:
        body = json.loads(body)
    except ValueError:
        pass
    return response.status, body, dict(response.headers)

def result(id, actual, expected, requirements, note):
    passed = actual == expected
    RESULTS.append({'test_id':id,'actual':actual,'expected':expected,'outcome':'passed' if passed else 'failed',
                    'requirements':requirements,'note':note})
    print(f'{id}: {"PASS" if passed else "FAIL"} actual={actual!r} expected={expected!r}', flush=True)
    return passed

class Form(HTMLParser):
    def __init__(self):
        super().__init__()
        self.action = None
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form' and attrs.get('id') == 'kc-form-login':
            self.action = attrs['action']

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl.startswith('http://app.example.test/'):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def authorize(realm, client, username, opener=None, organization=None):
    opener = opener or urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),NoRedirect())
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    state, nonce = secrets.token_urlsafe(20), secrets.token_urlsafe(20)
    redirect = 'http://app.example.test/callback'
    scope = 'openid' + (f' organization:{organization}' if organization else '')
    query = urllib.parse.urlencode({'client_id':client,'redirect_uri':redirect,'response_type':'code','scope':scope,
                                   'state':state,'nonce':nonce,'code_challenge':challenge,'code_challenge_method':'S256'})
    status, page, headers = request('GET',f'/realms/{realm}/protocol/openid-connect/auth?{query}',opener=opener)
    for _ in range(4):
        if status != 200:
            break
        parser = Form()
        parser.feed(page)
        if not parser.action:
            return {'kind':'no-login-form','http_status':status,'code_issued':False}, opener
        status, page, headers = request('POST',parser.action,{'username':username,'password':PASSWORD},form=True,opener=opener)
    if status != 302:
        return {'kind':'http-error','http_status':status,'code_issued':False}, opener
    values = urllib.parse.parse_qs(urllib.parse.urlparse(headers['Location']).query)
    assert values['state'] == [state]
    if 'error' in values:
        return {'kind':'oauth-error','error':values['error'][0],'code_issued':'code' in values}, opener
    assert 'code' in values
    status, tokens, _ = request('POST',f'/realms/{realm}/protocol/openid-connect/token',
                              {'grant_type':'authorization_code','client_id':client,'redirect_uri':redirect,
                               'code':values['code'][0],'code_verifier':verifier},form=True)
    assert status == 200, f'Authorization-code token exchange {status}'
    return {'kind':'tokens','tokens':tokens,'code_issued':True}, opener

def login(realm, client, username, opener=None, organization=None):
    outcome, opener = authorize(realm,client,username,opener,organization)
    assert outcome['kind'] == 'tokens', f'Authorization failed: {outcome}'
    return outcome['tokens'], opener

def claims(jwt):
    # Inspection only; this decoder is deliberately NOT a resource token verifier.
    payload = jwt.split('.')[1]
    return json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))

def main():
    OUT.mkdir(parents=True,exist_ok=True)
    ready = False
    for _ in range(90):
        try:
            if request('GET','/realms/master/.well-known/openid-configuration')[0] == 200:
                ready = True
                break
        except (urllib.error.URLError,TimeoutError,ConnectionError):
            pass
        time.sleep(1)
    assert ready, 'Keycloak did not become ready in 90 seconds'
    status, auth, _ = request('POST','/realms/master/protocol/openid-connect/token',
                             {'grant_type':'client_credentials','client_id':os.environ['KC_BOOTSTRAP_ADMIN_CLIENT_ID'],
                              'client_secret':os.environ['KC_BOOTSTRAP_ADMIN_CLIENT_SECRET']},form=True)
    assert status == 200, f'Bootstrap service account failed: {status}'
    admin = auth['access_token']
    result('KC-PRIVATE-001',request('GET','/admin/realms')[0],401,['CFG-004'],'Untrusted admin API request rejected.')
    users = {}
    for realm in ['ea-app-a','ea-app-b']:
        status, _, _ = request('POST','/admin/realms',{'realm':realm,'enabled':True,'sslRequired':'none',
               'duplicateEmailsAllowed':True,'registrationEmailAsUsername':False,'loginWithEmailAllowed':False,
               'organizationsEnabled':True,'revokeRefreshToken':True,'refreshTokenMaxReuse':0},admin)
        assert status == 201, f'Create realm {status}'
        for tenant in ['alpha','beta']:
            status, _, _ = request('POST',f'/admin/realms/{realm}/clients',{'clientId':tenant,'enabled':True,
                  'publicClient':True,'standardFlowEnabled':True,'directAccessGrantsEnabled':False,
                  'redirectUris':['http://app.example.test/callback'],'webOrigins':['http://app.example.test'],
                  'attributes':{'pkce.code.challenge.method':'S256'}},admin)
            assert status == 201
            status, body, headers = request('POST',f'/admin/realms/{realm}/users',{'username':f'{tenant}.same',
                  'email':'same@example.test','firstName':'Synthetic','lastName':'Probe','enabled':True,
                  'emailVerified':False,'credentials':[{'type':'password','value':PASSWORD,'temporary':False}]},admin)
            assert status == 201, f'User create failed: {status} {body}'
            users[realm,tenant] = headers['Location'].rsplit('/',1)[-1]
    result('KC-IDENTITY-001',len(set(users.values())),4,['IDN-001','IDN-003'],'Tenant-qualified usernames permit isolated equal emails; email login deliberately disabled, so not full embedded/email parity.')
    realm = 'ea-app-a'
    # Admin linking API reaches the engine uniqueness constraint without any live IdP.
    status, _, _ = request('POST',f'/admin/realms/{realm}/identity-provider/instances',
                           {'alias':'owned-provider','providerId':'oidc','enabled':True,'config':{
                               'clientId':'synthetic','authorizationUrl':'https://idp.example.test/auth',
                               'tokenUrl':'https://idp.example.test/token','userInfoUrl':'https://idp.example.test/userinfo'}},admin)
    assert status == 201
    links = []
    for tenant in ['alpha','beta']:
        links.append(request('POST',f'/admin/realms/{realm}/users/{users[realm,tenant]}/federated-identity/owned-provider',
                             {'identityProvider':'owned-provider','userId':'same-provider-subject','userName':'synthetic'},admin)[0])
    result('KC-PROVIDER-ISOLATION-001',links,[204,204],['IDN-003','SOC-003'],'Required distinct tenant identities under one provider alias; this is an engine mapping test, not live provider authentication.')
    # One shared identity signing into two tenant clients in the same browser.
    tokens_a, browser = login(realm,'alpha','alpha.same')
    tokens_b, _ = login(realm,'beta','alpha.same',browser)
    a, b = claims(tokens_a['access_token']), claims(tokens_b['access_token'])
    result('KC-PKCE-001',a['sub']==users[realm,'alpha'] and b['sub']==a['sub'],True,['OAU-001'],'Actual browser-form authorization code + PKCE, no resource-owner password grant.')
    RESULTS.append({'test_id':'KC-TENANT-SESSION-001','outcome':'observed','shared_realm_sid':a.get('sid')==b.get('sid'),
                    'note':'Shared realm SSO sid does not alone disprove independent client sessions. No acceptance claim.'})
    # A valid first-tenant identity can enter another client without explicit membership.
    RESULTS.append({'test_id':'KC-TENANT-MEMBERSHIP-001','outcome':'observed','bare_client_issued_token':True,
                    'note':'No organization scope or membership was configured for this request. Bare clients alone do not enforce desired tenant authorization.'})
    status, sessions, _ = request('GET',f'/admin/realms/{realm}/users/{users[realm,"alpha"]}/sessions',token=admin)
    assert status == 200
    RESULTS.append({'test_id':'KC-SESSION-INVENTORY','outcome':'observed','session_count':len(sessions),
                    'client_counts':[len(s.get('clients',{})) for s in sessions], 'note':'Token/session identifiers omitted.'})
    organizations = {}
    for tenant in ['alpha','beta']:
        status, body, headers = request('POST',f'/admin/realms/{realm}/organizations',
                              {'name':tenant,'alias':tenant,'enabled':True,'domains':[{'name':f'{tenant}.example.test'}]},admin)
        assert status == 201, f'Create organization {status} {body}'
        organizations[tenant] = headers['Location'].rsplit('/',1)[-1]
    status, body, _ = request('POST',f'/admin/realms/{realm}/organizations/{organizations["alpha"]}/members',users[realm,'alpha'],admin)
    assert status == 201, f'Add member {status} {body}'
    member_a, _ = login(realm,'alpha','alpha.same',organization='alpha')
    result('KC-ORG-MEMBER-001',sorted(claims(member_a['access_token']).get('organization',{})),['alpha'],['IDN-004'],'Selected organization claim from real membership through PKCE.')
    denied, _ = authorize(realm,'beta','alpha.same',organization='beta')
    result('KC-ORG-NONMEMBER-001',denied['kind']=='oauth-error' and not denied['code_issued'],True,['IDN-006'],'Explicit beta organization scope must reject a nonmember without code/token. Non-OAuth intermediate errors are not treated as passes.')
    status, body, _ = request('POST',f'/admin/realms/{realm}/organizations/{organizations["beta"]}/members',users[realm,'alpha'],admin)
    assert status == 201, f'Add shared member {status} {body}'
    member_b, _ = login(realm,'beta','alpha.same',organization='beta')
    result('KC-ORG-SHARING-001',claims(member_b['access_token'])['sub']==claims(member_a['access_token'])['sub'] and sorted(claims(member_b['access_token']).get('organization',{}))==['beta'],True,['IDN-004'],'One engine user explicitly associated with two organizations; selected org claims stay distinct.')
    def refresh(raw):
        status, body, _ = request('POST',f'/realms/{realm}/protocol/openid-connect/token',
                    {'grant_type':'refresh_token','client_id':'alpha','refresh_token':raw},form=True)
        return status, body
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        races = list(pool.map(refresh,[tokens_a['refresh_token']]*2))
    RESULTS.append({'test_id':'KC-REFRESH-RACE-OBSERVED','outcome':'observed','http_statuses':[r[0] for r in races],
                    'note':'Single-node diagnostic only; no multi-replica or response-loss acceptance claim.'})
    request('POST',f'/admin/realms/{realm}/users/{users[realm,"alpha"]}/logout',token=admin)
    active_refresh = next((r[1]['refresh_token'] for r in races if r[0]==200),tokens_a['refresh_token'])
    result('KC-REVOKE-001',refresh(active_refresh)[0],400,['SES-005'],'Refresh denied after authoritative logout. Offline access revocation is not claimed.')
    report = {'engine':'Keycloak','version':'26.7.3','mapping':'app=realm; tenant=client; isolated username=tenant.identifier',
              'foundation_passed':False,'production_approved':False,'results':RESULTS,
              'remaining':['Provider alias per tenant needs separate configuration proof','Explicit organization sharing/permissions',
                           'Primary/method identity link/unlink conflict and proof of control','Supported headless/embedded MFA and hooks',
                           'Node/React and Python adapter contract','Two-replica response loss, replay, cookies/header profiles'],
              'disposition':'No engine selected. Bare client mapping needs explicit tenant policy; shared SSO sid alone is not a failure. Further org/session/headless/link proofs and audited-source alternative evaluation remain.'}
    (OUT/'results.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'observations':len(RESULTS),'failed_mapping_cases':sum(r['outcome']=='failed' for r in RESULTS),'foundation_passed':False}))
    # Mapping failures are evidence, not harness failure. Overall foundation remains false.

if __name__ == '__main__':
    main()
