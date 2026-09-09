// Unmodified React/browser interceptor with the explicit ExpertAuth Node CDI5.6 adaptation.
import { chromium } from 'playwright';
import { randomUUID, createHash } from 'node:crypto';
import { readFile, writeFile, statfs } from 'node:fs/promises';

const origin = process.env.EXPERTAUTH_PUBLIC_ORIGIN;
const output = process.env.EVIDENCE_DIR;
const rows = [], statuses = [], errors = [], network = [];
const privateValues = [];
const temporaryMemory = [];
async function measureTemporaryMemory(stage) {
  const fs = await statfs('/tmp');
  temporaryMemory.push({ stage, capacity_bytes: fs.bsize * fs.blocks, free_bytes: fs.bsize * fs.bavail });
}
function diagnostic(error) {
  let message = String(error.message);
  for (const value of privateValues) if (value) message = message.replaceAll(value, '[REDACTED]');
  return message.replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[TOKEN]')
    .replace(/Bearer\s+[^\s"']+/gi, 'Bearer [TOKEN]').slice(0, 1600);
}
let browser, context, userId, refreshRequests = 0, stage = 'launch';
const started = new Date().toISOString();
class ProbeCheckError extends Error {}
function require(value, detail) { if (!value) throw new ProbeCheckError(detail); }
try {
  await measureTemporaryMemory('before-browser');
  browser = await chromium.launch({ headless: true });
  context = await browser.newContext();
  context.on('request', request => { if (new URL(request.url()).pathname === '/auth/session/refresh') refreshRequests++; });
  context.on('requestfailed', request => network.push({ event: 'failed', path: new URL(request.url()).pathname,
    method: request.method(), error: request.failure()?.errorText }));
  context.on('response', response => { const path = new URL(response.url()).pathname;
    if (path.startsWith('/auth/') || path.startsWith('/api/')) network.push({ event: 'response', path, status: response.status() }); });
  const page = await context.newPage();
  page.on('pageerror', () => errors.push('pageerror'));
  stage = 'open-signup';
  await page.goto(origin + '/auth');
  await page.getByText('Sign Up', { exact: true }).click();
  await page.getByRole('button', { name: 'SIGN UP', exact: true }).waitFor();
  stage = 'fill-signup';
  const email = `session-tabs-${randomUUID()}@example.test`, password = `Synthetic-${randomUUID()}-9a!`;
  privateValues.push(email, password);
  await page.getByPlaceholder('Email address').fill(email);
  await page.getByPlaceholder('Password', { exact: true }).fill(password);
  const responsePromise = page.waitForResponse(response => new URL(response.url()).pathname === '/auth/signup' && response.request().method() === 'POST');
  stage = 'submit-signup';
  await page.getByRole('button', { name: 'SIGN UP', exact: true }).click();
  const signup = await (await responsePromise).json();
  require(signup.status === 'OK' && typeof signup.user?.id === 'string', 'Signup did not return a user');
  userId = signup.user.id;
  stage = 'open-account-tabs';
  await page.getByRole('button', { name: 'Check active session' }).waitFor();
  const tabs = [page];
  for (let i = 1; i < 4; i++) {
    const tab = await context.newPage(); tabs.push(tab);
    tab.on('pageerror', () => errors.push('pageerror'));
    await tab.goto(origin);
    await tab.getByRole('button', { name: 'Check active session' }).waitFor();
  }
  const cookie = (await context.cookies()).find(row => row.name === 'sAccessToken');
  privateValues.push(...(await context.cookies()).map(row => row.value));
  require(cookie?.httpOnly === true, 'Expected real HttpOnly session cookie');
  const payload = JSON.parse(Buffer.from(cookie.value.split('.')[1], 'base64url'));
  require(payload.sub === userId, 'Signup and session user differed');
  const waitMs = Math.max(0, payload.exp * 1000 - Date.now() + 1500);
  require(waitMs <= 65000, 'Unexpected access-token TTL; refusing unbounded wait');
  console.log(JSON.stringify({ waiting_for_real_access_expiry_ms: waitMs, tabs: tabs.length }));
  stage = 'real-expiry';
  await new Promise(resolve => setTimeout(resolve, waitMs));
  const refreshBefore = refreshRequests;
  const startedRequests = Date.now();
  stage = 'concurrent-fetch';
  await measureTemporaryMemory('before-concurrency');
  const results = await Promise.all(tabs.map(tab => tab.evaluate(async () =>
    Promise.all(Array.from({ length: 8 }, async () => {
      try { return (await fetch('/api/session/online', { signal: AbortSignal.timeout(20000) })).status; }
      catch (error) { return error.name; }
    })))));
  statuses.push(...results.flat());
  await measureTemporaryMemory('after-concurrency');
  require(statuses.length === 32 && statuses.every(status => status === 200), 'Concurrent interceptor request failed');
  require(refreshRequests > refreshBefore && refreshRequests - refreshBefore <= 4, 'Expected bounded real refresh after expiry');
  require(errors.length === 0, 'Browser page error');
  rows.push({ id: 'SDK56-BROWSER-FOUR-TAB-REFRESH', outcome: 'passed', requirements: ['SES-003', 'SES-004', 'SES-007', 'SES-017', 'SDK-005'],
    tabs: 4, concurrent_requests: statuses.length, statuses, refresh_requests: refreshRequests - refreshBefore,
    waited_for_expiry_ms: waitMs, elapsed_requests_ms: Date.now() - startedRequests });
  stage = 'cross-tab-logout';
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await page.getByRole('button', { name: 'SIGN IN', exact: true }).waitFor();
  await page.reload();
  await page.getByRole('button', { name: 'SIGN IN', exact: true }).waitFor();
  await page.screenshot({path:`${output}/signed-out.png`,fullPage:true});
  const afterLogout = await Promise.all(tabs.map(tab => tab.evaluate(async () => (await fetch('/api/session/online')).status)));
  require(afterLogout.every(status => status === 401), 'Signed-out tab retained online authorization');
  rows.push({ id: 'SDK56-BROWSER-CROSS-TAB-LOGOUT', outcome: 'passed', requirements: ['SES-005', 'SDK-005'], statuses: afterLogout });
} catch (error) { rows.push({ id: 'SDK56-BROWSER', outcome: 'failed',
  stage, error: diagnostic(error) }); }
finally {
  await measureTemporaryMemory('before-cleanup');
  let removed = false;
  if (userId) {
    try {
      const response = await fetch(`http://${process.env.GRACE_CORE_A}:3567/user/remove`, { method: 'POST',
        headers: { 'api-key': process.env.EXPERTAUTH_CORE_API_KEY, 'cdi-version': '5.4', 'content-type': 'application/json' },
        body: JSON.stringify({ userId, removeAllLinkedAccounts: false }), signal: AbortSignal.timeout(15000) });
      removed = response.ok && (await response.json()).status === 'OK';
    } catch {}
  }
  rows.push({ id: 'SDK56-BROWSER-SYNTHETIC-CLEANUP', outcome: removed ? 'passed' : 'failed' });
  if (browser) await browser.close();
  const report = { schema: 'expertauth-adapted-cdi56-browser-session-v1', started, finished: new Date().toISOString(),
    foundation_passed: false, skipped: 0, rows, refresh_requests: refreshRequests, errors, statuses, network, temporaryMemory,
    probe_sha256: createHash('sha256').update(await readFile(new URL(import.meta.url))).digest('hex'),
    limitation: 'One Chromium/Linux cookie profile in a shared browser context. Node refresh/verify protocol is explicitly adapted to CDI5.6. No Safari, native, multi-device or complete SDK qualification.' };
  await writeFile(`${output}/browser-results.json`, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
  console.log(JSON.stringify({ checks: rows.map(row => ({ id: row.id, outcome: row.outcome })) }));
  process.exitCode = rows.some(row => row.outcome !== 'passed') ? 1 : 0;
}
