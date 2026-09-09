/** Real maintained Node SDK, unchanged application and two source-built Cores.
 * The proxy only transports or drops bytes. It never issues an auth response,
 * chooses token validity, edits credentials, or keeps authoritative session state.
 */
import http from 'node:http';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { once } from 'node:events';

const output = process.env.EVIDENCE_DIR;
const origin = 'http://session-sdk.example.test:3000';
const key = process.env.EXPERTAUTH_CORE_API_KEY;
if (!output || !key) throw Error('Private test environment required');
const replicas = ['core-a', 'session-core-b'];
const rows = [], wire = [], faults = [], users = new Set();
const started = new Date().toISOString();
let sequence = 0, forcedReplica, fault, app, fatal = false;
const input = createInterface({ input: process.stdin });
class ProbeCheckError extends Error {}
function require(value, detail) { if (!value) throw new ProbeCheckError(detail); }
const safeError = error => error instanceof ProbeCheckError ? error.message : `Unexpected ${error.name || 'operation error'}`;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
async function control(action) {
  const answer = once(input, 'line');
  console.log(JSON.stringify({ control: action }));
  let timeout;
  const [line] = await Promise.race([answer, new Promise((_, reject) => {
    timeout = setTimeout(() => reject(Error('Host control timed out')), 180000);
  })]).finally(() => clearTimeout(timeout));
  require(JSON.parse(line).ok === true, 'Host action failed');
}
async function check(id, action, requirements = ['SES-003', 'SES-004']) {
  try { const detail = await action(); rows.push({ id, outcome: 'passed', requirements, ...detail }); }
  catch (error) { rows.push({ id, outcome: 'failed', requirements, error: safeError(error) }); }
  console.log(JSON.stringify({ check: id, outcome: rows.at(-1).outcome }));
}
const proxy = http.createServer(async (request, response) => {
  const path = new URL(request.url, 'http://proxy').pathname;
  const target = forcedReplica ?? sequence++ % 2;
  const entry = { method: request.method, path, replica: target, cdi: request.headers['cdi-version'] ?? null };
  wire.push(entry);
  const selectedFault = fault?.path === path ? fault.stage : undefined;
  if (selectedFault === 'before-forward') {
    entry.fault = selectedFault;
    faults.push({ path, stage: selectedFault, replica: target, upstream_received: false });
    request.resume(); response.destroy(); return;
  }
  const upstream = http.request({ host: replicas[target], port: 3567, path: request.url,
    method: request.method, headers: { ...request.headers, host: `${replicas[target]}:3567` } }, incoming => {
    const chunks = [];
    incoming.on('data', part => chunks.push(part));
    incoming.on('end', () => {
      const bytes = Buffer.concat(chunks);
      entry.http = incoming.statusCode;
      try { entry.status = JSON.parse(bytes).status ?? null; } catch { entry.status = null; }
      if (selectedFault) {
        entry.fault = selectedFault;
        const sent = selectedFault === 'partial-body' ? Math.min(8, Math.max(1, bytes.length - 1)) : 0;
        faults.push({ path, stage: selectedFault, replica: target, upstream_received: true,
          upstream_http: incoming.statusCode, upstream_status: entry.status,
          upstream_body_bytes: bytes.length, downstream_body_bytes: sent });
        if (sent) {
          const headers = { ...incoming.headers, 'content-length': String(bytes.length), connection: 'close' };
          delete headers['transfer-encoding'];
          response.writeHead(incoming.statusCode, headers); response.flushHeaders(); response.write(bytes.subarray(0, sent));
          setTimeout(() => response.destroy(), 30);
        } else response.destroy();
        return;
      }
      response.writeHead(incoming.statusCode, incoming.headers); response.end(bytes);
    });
    incoming.on('error', () => response.destroy());
  });
  upstream.setTimeout(10000, () => upstream.destroy());
  upstream.on('error', () => { entry.transport_error = true; response.destroy(); });
  request.on('error', () => upstream.destroy());
  request.pipe(upstream);
});

async function direct(path, body, replica = 0) {
  const response = await fetch(`http://${replicas[replica]}:3567${path}`, {
    method: body ? 'POST' : 'GET', headers: { 'api-key': key, 'cdi-version': '5.4', 'content-type': 'application/json', rid: 'session' },
    body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(15000) });
  return { http: response.status, body: await response.json() };
}
async function call(path, token, body, rid = 'session') {
  const response = await fetch(`http://127.0.0.1:3000${path}`, {
    method: path.startsWith('/auth/') ? 'POST' : 'GET',
    headers: { origin, 'content-type': 'application/json', 'fdi-version': '4.2', rid, 'st-auth-mode': 'header',
      ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(25000) });
  return { http: response.status, body: await response.json(), access: response.headers.get('st-access-token'),
    refresh: response.headers.get('st-refresh-token') };
}
async function signup() {
  const response = await call('/auth/signup', null, { formFields: [
    { id: 'email', value: `sdk-fault-${randomUUID()}@example.test` },
    { id: 'password', value: `Synthetic-${randomUUID()}-9a!` }] }, 'emailpassword');
  if (response.body.status === 'OK' && typeof response.body.user?.id === 'string') users.add(response.body.user.id);
  require(response.http === 200 && response.body.status === 'OK' && response.access && response.refresh, 'Signup failed');
  return response;
}
const refresh = session => call('/auth/session/refresh', session.refresh);
const verify = session => call('/api/session/online', session.access);
function handle(session) { return JSON.parse(Buffer.from(session.access.split('.')[1], 'base64url')).sessionHandle; }
async function ready() {
  for (let attempt = 0; attempt < 45; attempt++) {
    try { if ((await fetch('http://127.0.0.1:3000/health/ready', { signal: AbortSignal.timeout(2000) })).ok) return; } catch {}
    await delay(1000);
  }
  throw Error('Application storage readiness failed');
}

try {
  for (let replica = 0; replica < 2; replica++) {
    let storageReady = false;
    for (let attempt = 0; attempt < 45; attempt++) {
      try { storageReady = (await direct('/users/count', null, replica)).body.status === 'OK'; if (storageReady) break; } catch {}
      await delay(1000);
    }
    require(storageReady, 'Core replica storage readiness failed');
  }
  proxy.listen(3568, '127.0.0.1'); await once(proxy, 'listening');
  app = spawn(process.execPath, ['/app/server.js'], { env: { ...process.env, EXPERTAUTH_PUBLIC_ORIGIN: origin,
    EXPERTAUTH_CORE_URL: 'http://127.0.0.1:3568', EXPERTAUTH_LOCAL_PROBE: 'true' }, stdio: 'ignore' });
  await ready();
  await check('SDK54-WIRE-PROTOCOL', async () => {
    const user = await signup(); require((await verify(user)).http === 200, 'Online session rejected');
    const calls = wire.filter(row => row.path.startsWith('/recipe/session'));
    require(calls.length > 0 && calls.every(row => row.cdi === '5.4'), 'SDK session CDI differed from frozen 5.4 profile');
    require(new Set(wire.filter(row => row.http === 200).map(row => row.replica)).size === 2, 'Both replicas were not reached');
    return { observed_session_cdi: [...new Set(calls.map(row => row.cdi))], replicas_used: 2 };
  }, ['SES-003', 'SDK-001']);
  await check('SDK54-SERIAL-PROMOTION', async () => {
    const original = await signup(), child = await refresh(original);
    require(child.http === 200 && child.refresh !== original.refresh, 'Refresh mint failed');
    require(handle(child) === handle(original), 'Session family changed');
    require((await verify(child)).http === 200, 'Child promotion failed');
    require((await refresh(child)).http === 200, 'Promoted child could not continue');
    return { candidate_mint: 200, promotion: 200, continuation: 200 };
  });
  for (const stage of ['before-forward', 'after-upstream-body', 'partial-body']) {
    await check(`SDK54-LOSS-${stage.toUpperCase()}`, async () => {
      const original = await signup(), offset = faults.length;
      fault = { path: '/recipe/session/refresh', stage };
      let lost;
      try { lost = await refresh(original); } finally { fault = undefined; }
      require(lost.http === 500 && !lost.refresh, 'Failed transport unexpectedly delivered a refresh token');
      const injected = faults.slice(offset);
      require(injected.length > 0 && injected.every(row => stage === 'before-forward' ? !row.upstream_received : row.upstream_status === 'OK'), 'Fault point not observed');
      const retry = await refresh(original);
      require(retry.http === 200 && (await verify(retry)).http === 200, 'Lost response retry did not converge');
      const stale = await refresh(original), winner = await refresh(retry);
      require(stale.http === 401 && winner.http === 401, 'SDK theft handler did not revoke the intended session');
      return { fault_stage: stage, injections: injected.length, lost_http: lost.http, retry_http: retry.http,
        stale_parent_http: stale.http, family_after_theft_http: winner.http,
        limit: stage === 'before-forward' ? 'Before Core receives request; not an in-transaction failure.' : 'Proxy drops after a complete real Core response; no engine-internal commit hook.' };
    });
  }
  await check('SDK54-COMMITTED-PROMOTION-CRASH', async () => {
    const original = await signup(), child = await refresh(original);
    require(child.http === 200, 'Child mint failed');
    forcedReplica = 1; fault = { path: '/recipe/session/verify', stage: 'after-upstream-body' };
    const offset = faults.length;
    let lost;
    try { lost = await verify(child); } finally { fault = undefined; forcedReplica = undefined; }
    require(lost.http === 500 && faults.slice(offset).some(row => row.replica === 1 && row.upstream_status === 'OK'), 'Committed verification response was not lost');
    const before = await direct('/recipe/session/refresh', { refreshToken: original.refresh, enableAntiCsrf: false, useDynamicSigningKey: true });
    require(before.body.status === 'TOKEN_THEFT_DETECTED', 'Parent was not retired before restart');
    await control('kill_and_restart_owned_b');
    let readyB = false;
    for (let attempt = 0; attempt < 45; attempt++) {
      try { readyB = (await direct('/users/count', null, 1)).body.status === 'OK'; if (readyB) break; } catch {}
      await delay(1000);
    }
    require(readyB, 'Restarted replica did not reach database readiness');
    const after = await direct('/recipe/session/refresh', { refreshToken: original.refresh, enableAntiCsrf: false, useDynamicSigningKey: true }, 1);
    require(after.body.status === 'TOKEN_THEFT_DETECTED', 'Retired parent regained validity after crash');
    require((await refresh(child)).http === 200, 'Committed child lost continuity after restart');
    require((await refresh(original)).http === 401 && (await refresh(child)).http === 401, 'SDK theft revocation did not persist');
    return { lost_promotion_http: lost.http, parent_before_crash: before.body.status, parent_after_crash: after.body.status,
      child_after_crash_http: 200, crash: 'SIGKILL then start same disposable Core B; shared PostgreSQL remains running' };
  });
  await check('SDK54-THEFT-SESSION-ISOLATION', async () => {
    const original = await signup(), other = await signup(), child = await refresh(original);
    require((await verify(child)).http === 200, 'Promotion failed');
    const theft = await refresh(original), revoked = await verify(child), survivor = await verify(other);
    require(theft.http === 401 && revoked.http === 401 && survivor.http === 200, 'Theft revocation isolation failed');
    return { theft_http: theft.http, compromised_session_http: revoked.http, unrelated_session_http: survivor.http };
  }, ['SES-004', 'SES-005']);
  await check('SDK54-LOGOUT-REFRESH-CONCURRENCY', async () => {
    const rounds = [];
    for (let round = 0; round < 12; round++) {
      const original = await signup();
      const [renewed, logout] = await Promise.all([refresh(original), call('/auth/signout', original.access)]);
      const final = await refresh(renewed.refresh ? renewed : original);
      require(logout.http === 200 && final.http === 401, 'Logout race resurrected a refresh session');
      rounds.push({ refresh_http: renewed.http, logout_http: logout.http, final_refresh_http: final.http });
    }
    return { rounds };
  }, ['SES-003', 'SES-005']);
  // Characterize the raw-header-client hazard explicitly, rather than requiring
  // a valid token to survive confirmed-theft revocation or hiding the availability loss.
  await check('SDK54-UNCOORDINATED-RACE-THEFT', async () => {
    const original = await signup();
    const raced = await Promise.all([refresh(original), refresh(original)]);
    require(raced.every(row => row.http === 200) && new Set(raced.map(handle)).size === 1, 'Expected two candidate tokens in one legacy family');
    require((await verify(raced[0])).http === 200, 'Selected candidate promotion failed');
    const loser = await refresh(raced[1]), winner = await refresh(raced[0]);
    require(loser.http === 401 && winner.http === 401, 'Expected SDK theft handler behavior not observed');
    rows.push({ id: 'SDK54-UNCOORDINATED-CLIENT-AVAILABILITY', outcome: 'failed', requirements: ['SES-003', 'SES-004'],
      initial_http: raced.map(row => row.http), loser_http: loser.http, selected_child_http: winner.http,
      detail: 'Uncoordinated callers that use both candidate branches lose the session through the default SDK theft handler. Raw header concurrency is not qualified.' });
    return { initial_http: raced.map(row => row.http), loser_http: loser.http, selected_child_http: winner.http };
  });
  await control('browser_coordination');
} catch (error) { fatal = true; rows.push({ id: 'HARNESS', outcome: 'failed', error: safeError(error) }); }
finally {
  fault = undefined; forcedReplica = undefined;
  let removed = 0;
  for (const userId of users) {
    try { const result = await direct('/user/remove', { userId, removeAllLinkedAccounts: false }); if (result.body.status === 'OK') removed++; } catch {}
  }
  rows.push({ id: 'SDK54-SYNTHETIC-USER-CLEANUP', outcome: removed === users.size ? 'passed' : 'failed', created: users.size, removed });
  if (app) { const exited = once(app, 'exit'); app.kill('SIGTERM'); await Promise.race([exited, delay(3000)]); if (app.exitCode === null) app.kill('SIGKILL'); }
  proxy.closeAllConnections(); await new Promise(resolve => proxy.close(resolve)); input.close();
  const paths = ['server.js', 'client.jsx', 'package-lock.json', 'node_modules/supertokens-node/lib/build/version.js',
    'node_modules/supertokens-node/lib/build/querier.js', 'node_modules/supertokens-node/lib/build/recipe/session/utils.js',
    'node_modules/supertokens-node/lib/build/recipe/session/recipe.js'];
  const inputs = {};
  for (const path of paths) inputs[path] = digest(await readFile(`/app/${path}`));
  const report = { schema: 'expertauth-sdk-session-characterization-v1', started, finished: new Date().toISOString(),
    foundation_passed: false, fatal, node: process.version, sdk_version: '24.0.3', cdi: '5.4',
    inputs, probe_sha256: digest(await readFile(new URL(import.meta.url))), rows, wire, faults,
    passed: rows.filter(row => row.outcome === 'passed').length, failed: rows.filter(row => row.outcome === 'failed').length,
    skipped: 0, limitations: ['One Node application, two Core replicas and one existing database; not application HA.',
      'No transaction-internal pre-commit failure or PostgreSQL crash/failover injection.',
      'Cookie/native/other SDK support requires separate evidence. No final engine selection or requirement verification.'] };
  const encoded = JSON.stringify(report, null, 2) + '\n';
  require(!encoded.includes(key), 'Secret in report');
  await writeFile(`${output}/sdk-results.json`, encoded, { flag: 'wx' });
  console.log(JSON.stringify({ execution_finished: true, passed: report.passed, failed: report.failed, foundation_passed: false }));
  process.exitCode = report.failed ? 1 : 0;
}
