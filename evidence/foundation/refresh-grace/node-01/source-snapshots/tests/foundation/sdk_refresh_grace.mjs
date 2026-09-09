/** Explicit ExpertAuth Node CDI5.6 adaptation and two installed Core replicas.
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
const origin = process.env.EXPERTAUTH_PUBLIC_ORIGIN;
const key = process.env.EXPERTAUTH_CORE_API_KEY;
const browserOnly = false;
if (!output || !key) throw Error('Private test environment required');
const replicas = [process.env.GRACE_CORE_A, process.env.GRACE_CORE_B];
if (!replicas.every(host => /^expertauth-reset-core-[ab]-[a-f0-9]+$/.test(host))) throw Error('Disposable Core replicas required');
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
      try { const body = JSON.parse(bytes); entry.status = body.status ?? null; entry.reuse_subtype = body.recentTokenReuseSubtype ?? null; } catch { entry.status = null; }
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
    method: body ? 'POST' : 'GET', headers: { 'api-key': key, 'cdi-version': '5.6', 'content-type': 'application/json', rid: 'session' },
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
  await new Promise(resolve => proxy.listen(3101, '127.0.0.1', resolve));
  const env = {...process.env, EXPERTAUTH_CORE_URL:'http://127.0.0.1:3101', EXPERTAUTH_RESET_POLICY:'atomic-v1', EXPERTAUTH_SESSION_POLICY:'core-cdi56-grace-v1'};
  app = spawn(process.execPath, ['/app/server.js'], {env, stdio:['ignore','pipe','pipe']});
  app.stdout.resume(); app.stderr.resume();
  await ready();
  await check('SDK56-SERIAL-ROTATION', async () => {
    const original=await signup(), child=await refresh(original);
    require(child.http===200 && child.refresh!==original.refresh && (await verify(child)).http===200,'Serial rotation failed');
    return {refresh_http:child.http,online_http:200};
  });
  await check('SDK56-PARENT-GRACE-RETRY', async () => {
    const root=await signup(), first=await refresh(root), retry=await refresh(root);
    require(first.http===200 && retry.http===200 && first.refresh!==retry.refresh,'Grace retry did not replace token');
    require((await verify(first)).http===401 && (await verify(retry)).http===200,'Online branch selection differs');
    return {replaced_branch_online:401,current_branch_online:200};
  });
  for(const stage of ['after-body','partial-body']) await check('SDK56-LOSS-'+(stage==='after-body'?'COMPLETE':'PARTIAL'),async()=>{
    const root=await signup(), before=faults.length;
    fault={path:'/recipe/session/refresh',stage};let lost;
    try {lost=await refresh(root);} finally {fault=undefined;}
    require(lost.http===500 && !lost.access && !lost.refresh,'Interrupted Core response exposed credentials');
    require(faults.length===before+1 && faults.at(-1).upstream_status==='OK','Actual successful upstream response was not lost once');
    const retry=await refresh(root);
    require(retry.http===200 && (await verify(retry)).http===200,'Same-parent retry after response loss failed');
    return {lost_http:lost.http,retry_http:200,fault:faults.at(-1)};
  });
  await check('SDK56-CONCURRENT-RESPONSES-CONVERGE',async()=>{
    const root=await signup(), children=await Promise.all([refresh(root),refresh(root)]);
    require(children.every(r=>r.http===200),'Concurrent same-parent refresh rejected');
    const states=await Promise.all(children.map(verify));
    require(states.filter(r=>r.http===200).length===1 && states.filter(r=>r.http===401).length===1,'Concurrent results did not converge');
    const winner=children[states.findIndex(r=>r.http===200)];require((await refresh(winner)).http===200,'Selected successor unusable');
    return {responses:2,online_statuses:states.map(r=>r.http),client_selection:'test inspects both branches; this is not production client coordination'};
  });
  await check('SDK56-ORPHAN-REUSE-REVOKES-FAMILY',async()=>{
    const root=await signup(), other=await signup(), first=await refresh(root), second=await refresh(root);
    const start=wire.length, stale=await refresh(first);
    require(stale.http===401 && (await refresh(second)).http===401 && (await verify(second)).http===401,'Orphan reuse did not revoke family');
    require(wire.slice(start).some(r=>r.reuse_subtype==='ORPHANED_BRANCH' && r.cdi==='5.6'),'Core orphan classification missing');
    require((await refresh(other)).http===200,'Other family revoked');
    return {orphan_http:401,current_after_reuse_http:401,other_family_http:200,uncoordinated_clients_qualified:false};
  });
  await check('SDK56-EXPIRED-PARENT-REPLAY',async()=>{
    const root=await signup(), child=await refresh(root), other=await signup();require(child.http===200,'Initial rotation failed');
    await delay(5250);const start=wire.length;
    require((await refresh(root)).http===401 && (await refresh(child)).http===401,'Retired parent did not revoke family');
    require(wire.slice(start).some(r=>r.reuse_subtype==='RECENT_PREV' && r.cdi==='5.6'),'Expired-window classification missing');
    require((await refresh(other)).http===200,'Other family revoked');return {waited_ms:5250,subtype:'RECENT_PREV'};
  });
  await check('SDK56-ONLINE-VERSUS-OFFLINE-REVOCATION',async()=>{
    const root=await signup();require((await call('/api/session/offline',root.access)).http===200,'Offline JWT fixture failed');
    require((await call('/auth/signout',root.access)).http===200,'Signout failed');
    require((await verify(root)).http===401 && (await refresh(root)).http===401,'Revoked session still online');
    require((await call('/api/session/offline',root.access)).http===200,'Offline residual was incorrectly hidden');
    return {online_http:401,refresh_http:401,offline_before_expiry_http:200,full_residual_window_qualified:false};
  });
  await check('SDK56-PUBLIC-PRIVATE-BOUNDARY',async()=>{
    const response=await fetch('http://127.0.0.1:3000/recipe/session/refresh',{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
    require(response.status===404,'Private Core route was publicly served');
    const root=await signup();const wrong=await fetch('http://127.0.0.1:3000/api/session/online',{headers:{authorization:`Bearer ${root.access}`,origin:'https://untrusted.example.test'}});
    require(wrong.status===403 && (await verify(root)).http===200,'Cross-origin request altered valid session');
    return {private_route_http:404,wrong_origin_http:403};
  });
  const browserStart=wire.length;
  await control('browser_coordination');
  const browser=JSON.parse(await readFile(`${output}/browser-results.json`,'utf8'));
  await check('SDK56-WIRE-AND-BROWSER-PROFILE',async()=>{
    const sessionCalls=wire.filter(r=>/\/recipe\/session\/(refresh|verify)$/.test(r.path));
    require(sessionCalls.length>0 && sessionCalls.every(r=>r.cdi==='5.6'),'Adapted operations used another protocol');
    require(wire.some(r=>r.path.endsWith('/expertauth/password/session') && r.cdi==='5.4'),'Atomic password session writer was not used');
    require(new Set(sessionCalls.map(r=>r.replica)).size===2,'Only one Core replica used');
    require(browser.rows.length===3 && browser.rows.every(r=>r.outcome==='passed'),'Real browser cases failed');
    const browserRefresh=wire.slice(browserStart).filter(r=>r.path.endsWith('/recipe/session/refresh'));
    require(browserRefresh.length>0 && browserRefresh.every(r=>r.cdi==='5.6' && r.status==='OK'),'Browser did not exercise adapted refresh');
    return {observed_cdi:'5.6',upstream_sdk_declared_cdi:'5.4',explicit_adaptation:true,session_calls:sessionCalls.length,browser_refreshes:browserRefresh.length,core_replicas:2};
  });
} catch(error) {fatal=true;rows.push({id:'SDK56-HARNESS',outcome:'failed',error:safeError(error)});}
finally {
  fault=undefined;
  await check('SDK56-OWNED-FIXTURE-CLEANUP',async()=>{
    for(const userId of users){const result=await direct('/user/remove',{userId,removeAllLinkedAccounts:false});require(result.http===200 && result.body.status==='OK','Owned cleanup failed');}
    return {owned_users_removed:users.size,source_database_contacted:false};
  });
  if(app && app.exitCode===null){app.kill('SIGTERM');await Promise.race([once(app,'exit'),delay(3000)]);if(app.exitCode===null)app.kill('SIGKILL');}
  proxy.closeAllConnections();await new Promise(resolve=>proxy.close(resolve));input.close();
  const inputs={};for(const path of ['server.js','client.jsx','package-lock.json']) inputs[path]=digest(await readFile('/app/'+path));
  const report={kind:'actual-adapted-node-cdi56-grace',started,finished:new Date().toISOString(),foundation_passed:false,complete:false,
    unmodified_sdk_qualified:false,independent_human_review:false,rows,wire,faults,inputs,fatal,skipped:0,
    passed:rows.filter(r=>r.outcome==='passed').length,failed:rows.filter(r=>r.outcome!=='passed').length,
    limitation:'Explicit private refresh/verify protocol adaptation on public tenant only; no all-SDK/platform or configured-tenant qualification.'};
  await writeFile(`${output}/sdk-results.json`,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
  console.log(JSON.stringify({passed:report.passed,failed:report.failed,fatal}));process.exitCode=fatal||report.failed?1:0;
}
