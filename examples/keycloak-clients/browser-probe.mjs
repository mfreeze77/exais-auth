// Real Chromium UI and signed-token policy checks; all credentials/tokens stay in memory.
import { chromium } from 'playwright';
import { CookieJar } from 'tough-cookie';
import * as oidc from 'openid-client';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';

const root = process.env.WORKSPACE || '/workspace';
const origin = 'http://expertauth-kc-clients-node:3000';
const issuer = 'http://kc-headless.example.test:8080/realms/expertauth-headless-proof';
const fixtures = JSON.parse(await readFile(`${root}/engine-extensions/keycloak-headless/.runtime/fixtures.json`, 'utf8'));
const directory = `${root}/evidence/foundation/keycloak-clients`;
await mkdir(directory, { recursive: true });
const outcomes = [];
function otp(user) {
  const execution = spawnSync('python3', ['-c', "import sys;sys.path.insert(0,sys.argv[1]);import pyotp;print(pyotp.TOTP(sys.stdin.read()).now())", `${root}/examples/keycloak-clients/.runtime/testdeps`],
    { input: user.otp_secret, encoding: 'utf8' });
  if (execution.status !== 0 || !/^\d{6}\s*$/.test(execution.stdout)) throw new Error('OTP_FIXTURE_TOOL_FAILED');
  return execution.stdout.trim();
}
async function test(id, operation) {
  try { await operation(); outcomes.push({ id, status: 'passed' }); }
  catch (error) { outcomes.push({ id, status: 'failed', error_type: error.name }); }
}
async function engineToken(clientId, callback, scope, user) {
  const config = await oidc.discovery(new URL(issuer), clientId, undefined, oidc.None(), { execute: [oidc.allowInsecureRequests] });
  const state = oidc.randomState(), nonce = oidc.randomNonce(), verifier = oidc.randomPKCECodeVerifier();
  let url = oidc.buildAuthorizationUrl(config, { redirect_uri: callback, scope, state, nonce,
    code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256' });
  const jar = new CookieJar();
  for (const [step, data] of [[null, null], ['password', { username: user.username, password: user.password }], ['totp', { otp: otp(user) }]]) {
    const headers = { Accept: 'application/json', Cookie: await jar.getCookieString(url.href) };
    if (data) headers['Content-Type'] = 'application/x-www-form-urlencoded';
    const response = await fetch(url, { method: data ? 'POST' : 'GET', headers, body: data ? new URLSearchParams(data) : undefined, redirect: 'manual' });
    for (const cookie of response.headers.getSetCookie()) await jar.setCookie(cookie, url.href);
    if (step === 'totp') {
      assert.equal(response.status, 302);
      const target = new URL(response.headers.get('location'));
      assert.equal(target.origin + target.pathname, callback);
      const tokens = await oidc.authorizationCodeGrant(config, target, { pkceCodeVerifier: verifier, expectedState: state, expectedNonce: nonce, idTokenExpected: true });
      const { payload } = await jwtVerify(tokens.access_token, createRemoteJWKSet(new URL(config.serverMetadata().jwks_uri)), { issuer, algorithms: ['RS256'] });
      return { token: tokens.access_token, claims: payload, config, refresh: tokens.refresh_token };
    }
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.step, step === null ? 'password' : 'totp');
    url = new URL(body.action);
    assert.equal(url.origin, new URL(issuer).origin);
    assert.equal(url.pathname, new URL(issuer).pathname + '/login-actions/authenticate');
  }
  throw new Error('NO_FINAL_TOKEN');
}

await test('KC-CLIENT-SIGNED-MISSING-TENANT', async () => {
  const actual = await engineToken('expertauth-node-candidate', origin + '/candidate/callback', 'openid', fixtures.users['client-negative']);
  try {
    assert.equal(actual.claims.azp, 'expertauth-node-candidate');
    assert.ok([actual.claims.aud].flat().includes('expertauth-candidate-api'));
    assert.ok(!Array.isArray(actual.claims.organization) || !actual.claims.organization.includes('alpha'));
    const response = await fetch(origin + '/candidate/resource?tenant=alpha', { headers: { Authorization: 'Bearer ' + actual.token } });
    assert.equal(response.status, 403);
  } finally { await oidc.tokenRevocation(actual.config, actual.refresh, { token_type_hint: 'refresh_token' }); }
});
await test('KC-CLIENT-SIGNED-WRONG-AUDIENCE', async () => {
  const actual = await engineToken('headless-proof-client', 'http://headless-client.example.test/callback', 'openid', fixtures.users['client-audit']);
  try {
    assert.ok(![actual.claims.aud].flat().includes('expertauth-candidate-api'));
    const response = await fetch(origin + '/candidate/resource?tenant=alpha', { headers: { Authorization: 'Bearer ' + actual.token } });
    assert.equal(response.status, 401);
  } finally { await oidc.tokenRevocation(actual.config, actual.refresh, { token_type_hint: 'refresh_token' }); }
});

let browser;
try {
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const page = await context.newPage();
  page.setDefaultTimeout(15_000);
  const contacted = new Set(), errors = [];
  page.on('request', request => contacted.add(new URL(request.url()).origin));
  page.on('pageerror', error => errors.push(error.name));
  const user = fixtures.users['client-browser'];
  await test('KC-CLIENT-REACT-PASSWORD-TOTP-RESOURCE', async () => {
    await page.goto(origin);
    await page.getByRole('button', { name: 'Start sign in' }).click();
    await page.getByLabel('Username', { exact: true }).fill(user.username);
    await page.getByLabel('Password', { exact: true }).fill(user.password);
    await page.getByRole('button', { name: 'Continue', exact: true }).click();
    await page.getByRole('heading', { name: 'Authenticator code' }).waitFor();
    assert.equal(await page.getByRole('heading', { name: 'Signed in', exact: true }).count(), 0);
    const intermediate = await page.request.get(origin + '/candidate/resource?tenant=alpha');
    assert.equal(intermediate.status(), 401);
    await page.getByLabel('Six-digit code', { exact: true }).fill(otp(user));
    await page.getByRole('button', { name: 'Verify code', exact: true }).click();
    await page.getByRole('heading', { name: 'Signed in', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Open protected resource' }).click();
    await page.getByRole('status').filter({ hasText: 'Private candidate resource authorized' }).waitFor();
    await page.screenshot({ path: directory + '/react-authenticated-mobile.png', fullPage: true });
  });
  await test('KC-CLIENT-BROWSER-BOUNDARY-HTTPONLY-CSRF', async () => {
    assert.deepEqual([...contacted], [origin]);
    const allCookies = await context.cookies();
    for (const suffix of ['access', 'refresh', 'binding', 'csrf']) {
      const cookie = allCookies.find(candidate => candidate.name.endsWith(suffix));
      assert.ok(cookie && cookie.httpOnly && cookie.sameSite === 'Strict');
    }
    const browserState = await page.evaluate(() => ({ cookies: document.cookie, local: localStorage.length, session: sessionStorage.length,
      overflow: document.documentElement.scrollWidth > window.innerWidth }));
    assert.equal(browserState.cookies, '');
    assert.equal(browserState.local, 0);
    assert.equal(browserState.session, 0);
    assert.equal(browserState.overflow, false);
    assert.deepEqual(errors, []);
    const missingCsrf = await page.evaluate(async () => (await fetch('/candidate/refresh', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status);
    assert.equal(missingCsrf, 403);
  });
  await test('KC-CLIENT-REACT-REFRESH-LOGOUT', async () => {
    await page.getByRole('button', { name: 'Refresh session' }).click();
    await page.getByRole('status').filter({ hasText: 'Session refreshed by Keycloak.' }).waitFor();
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await page.getByRole('button', { name: 'Start sign in' }).waitFor();
    await page.getByRole('status').filter({ hasText: 'Signed out.' }).waitFor();
    const response = await page.request.get(origin + '/candidate/resource?tenant=alpha');
    assert.equal(response.status(), 401);
    assert.ok(!(await context.cookies()).some(cookie => /-(access|refresh)$/.test(cookie.name)));
    await page.screenshot({ path: directory + '/react-signed-out-mobile.png', fullPage: true });
  });
} catch (error) { outcomes.push({ id: 'KC-CLIENT-BROWSER-HARNESS', status: 'error', error_type: error.name }); }
finally { if (browser) await browser.close(); }

const sourceHashes = {};
for (const path of ['server.mjs', 'client.jsx', 'python_client.py', 'browser-probe.mjs', 'package.json', 'package-lock.json', 'requirements-test.txt', 'public/index.html', 'public/style.css']) {
  sourceHashes[`examples/keycloak-clients/${path}`] = createHash('sha256').update(await readFile(`${root}/examples/keycloak-clients/${path}`)).digest('hex');
}
const report = { timestamp_utc: new Date().toISOString(), profile: 'real-chromium-react-private-keycloak-candidate',
  auth_completion: false, foundation_passed: false, browser_version: browser?.version(), tests: outcomes, source_sha256: sourceHashes,
  limits: ['Single candidate application and alpha organization', 'Browser only Chromium Linux; Safari, Firefox and native SDK qualification incomplete',
    'Headless password/TOTP does not prove all original FDI/CDI APIs, providers, SDK/plugin profiles, or independent security review'] };
const data = JSON.stringify(report, null, 2) + '\n';
await writeFile(`${directory}/browser-results-${Date.now()}.json`, data);
await writeFile(`${directory}/browser-results.json`, data);
console.log(JSON.stringify({ profile: report.profile, passed: outcomes.filter(row => row.status === 'passed').length,
  failed: outcomes.filter(row => row.status !== 'passed').length, auth_completion: false }));
process.exitCode = outcomes.some(row => row.status !== 'passed') ? 1 : 0;
