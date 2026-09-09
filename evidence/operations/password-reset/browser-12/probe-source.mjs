/** Actual SDK HTTP, authenticated TLS mail, and Chromium recovery characterization.
 * Fixture credentials/tokens and baseline identities are private. No mock transport,
 * direct database mutation, engine patch, live provider, or entitlement is used.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { randomUUID, createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { chromium } from '../browser/node_modules/playwright/index.mjs';
import { runPasswordResetBrowser } from '../browser/password-reset.mjs';

const out = process.env.EVIDENCE_DIR, privateDir = process.env.PRIVATE_DIR;
const apps = JSON.parse(process.env.RESET_APPS);
const browserOnly = process.env.RESET_BROWSER_ONLY === 'true';
const settings = JSON.parse(await readFile(`${privateDir}/settings.json`, 'utf8'));
const core = 'http://core-a:3567', key = process.env.EXPERTAUTH_CORE_API_KEY;
const mailbox = `https://${settings.mail_host}:8025`;
const auth = 'Basic ' + Buffer.from(`${settings.ui_username}:${settings.ui_password}`).toString('base64');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const rows = [], wire = [], users = [], started = new Date().toISOString();
let baseline, browser, failed = false;
const save = () => writeFile(`${privateDir}/fixtures.json`, JSON.stringify({baseline, users}, null, 2), {mode:0o600});
const need = (ok, text) => { if (!ok) throw new Error(text); };
async function check(id, fn, requirement = 'PWD-006') {
  const start = performance.now();
  try { const details = await fn(); rows.push({id, status:'passed', requirement, elapsed_ms:Math.round(performance.now()-start), ...details}); }
  catch { failed = true; rows.push({id, status:'failed', requirement, error:'Actual assertion or operation failed', elapsed_ms:Math.round(performance.now()-start)}); }
  console.log(JSON.stringify(rows.at(-1)));
}
async function direct(path, body) {
  const response = await fetch(core + path, {method:body ? 'POST':'GET', headers:{'api-key':key,'cdi-version':'5.4','content-type':'application/json'},
    body:body ? JSON.stringify(body):undefined, signal:AbortSignal.timeout(10000)});
  return {http:response.status, body:await response.json()};
}
async function identities() {
  const result = await direct('/users?limit=500');
  need(result.http === 200 && result.body.status === 'OK' && !result.body.nextPaginationToken, 'Identity page unavailable');
  need(Array.isArray(result.body.users), 'Identity shape differs');
  return result.body.users;
}
async function call(app, path, body, token, rid='emailpassword') {
  const response = await fetch(app + path, {method:body !== undefined ? 'POST':'GET',
    headers:{origin:app,'fdi-version':'4.2',rid,'st-auth-mode':'header','content-type':'application/json', ...(token ? {authorization:'Bearer '+token}:{})},
    body:body !== undefined ? JSON.stringify(body):undefined, signal:AbortSignal.timeout(18000)});
  let data; try {data = await response.json();} catch {data = null;}
  wire.push({role:Object.keys(apps).find(role=>apps[role]===app),path,http:response.status,status:data?.status || null});
  return {http:response.status, body:data, access:response.headers.get('st-access-token'), refresh:response.headers.get('st-refresh-token')};
}
const form = (email,password) => ({formFields:[{id:'email',value:email},{id:'password',value:password}]});
async function signup(app=apps.good) {
  const user = {email:`reset-${randomUUID()}@example.test`, oldPassword:`Synthetic-${randomUUID()}-9a!`, newPassword:`Synthetic-${randomUUID()}-8a!`, app};
  users.push(user); await save();
  const result = await call(app,'/auth/signup',form(user.email,user.oldPassword));
  if(result.body?.status === 'OK') {user.id = result.body.user.id; user.session = result; await save();}
  need(result.http === 200 && result.body?.status === 'OK' && result.access && result.refresh && !baseline.includes(user.id), 'Signup failed');
  return user;
}
async function mails() {
  const response = await fetch(mailbox+'/api/v1/messages?start=0&limit=50',{headers:{authorization:auth},signal:AbortSignal.timeout(5000)});
  need(response.status === 200,'Mailbox unavailable');
  const body = await response.json(); need(Array.isArray(body.messages),'Mailbox shape differs'); return body.messages;
}
async function linkFor(email, excluded=[]) {
  const deadline = Date.now()+12000;
  while(Date.now()<deadline) {
    const found = (await mails()).filter(row=>!excluded.includes(row.ID) && row.Subject === 'Reset your ExpertAuth password' && row.To.some(to=>to.Address===email));
    if(found.length) {
      need(found.length===1,'Ambiguous owned message');
      const response = await fetch(mailbox+'/api/v1/message/'+found[0].ID,{headers:{authorization:auth},signal:AbortSignal.timeout(5000)});
      need(response.status===200,'Message unavailable');
      const message = await response.json();
      need(!message.HTML && message.Username === settings.smtp_username,'Message transport/content differs');
      const matches = message.Text.match(/https?:\/\/\S+/g) || [];
      need(matches.length===1,'Reset link shape differs');
      return matches[0];
    }
    await delay(150);
  }
  throw new Error('Owned message was not delivered');
}
const request = (app,email) => call(app,'/auth/user/password/reset/token',{formFields:[{id:'email',value:email}]});
async function tokenFor(user, app=user.app) {
  const before = (await mails()).map(row=>row.ID);
  const response = await request(app,user.email);
  need(response.http===200 && response.body?.status==='OK','Reset request failed');
  const link = new URL(await linkFor(user.email,before));
  need(link.origin===app && link.pathname==='/auth/reset-password' && link.searchParams.get('tenantId')==='public','SDK link binding differs');
  return link.searchParams.get('token');
}
const reset = (app,token,password,path='/auth/user/password/reset') => call(app,path,{token,formFields:[{id:'password',value:password}]});
const ok = result => result.http===200 && result.body?.status==='OK';
const invalid = result => result.http===200 && result.body?.status==='RESET_PASSWORD_INVALID_TOKEN_ERROR';
async function assertChanged(user,password) {
  need((await call(user.app,'/auth/signin',form(user.email,user.oldPassword))).body?.status==='WRONG_CREDENTIALS_ERROR','Old password accepted');
  const current = await call(user.app,'/auth/signin',form(user.email,password)); need(ok(current),'New password denied');
  need((await call(user.app,'/api/session/online',undefined,current.access,'session')).http===200,'New online session denied');
  need((await call(user.app,'/api/session/online',undefined,user.session.access,'session')).http===401,'Prior online session accepted');
  need((await call(user.app,'/auth/session/refresh',{},user.session.refresh,'session')).http===401,'Prior refresh accepted');
  return current;
}

try {
  baseline = (await identities()).map(user=>user.id).sort(); await save();
  if(!browserOnly) {
  await check('RESET-HTTP-001-DELIVERY-CONSUME-REPLAY-SESSIONS',async()=>{
    const user = await signup(), token = await tokenFor(user);
    need(ok(await reset(user.app,token,user.newPassword)),'Reset failed');
    need(invalid(await reset(user.app,token,user.oldPassword)),'Replay accepted');
    await assertChanged(user,user.newPassword);
    return {old_online_and_refresh_denied:true, atomic_reset_revoke_qualified:false};
  });
  await check('RESET-HTTP-002-INVALID-AND-WEAK-PASSWORD',async()=>{
    const user = await signup(), token = await tokenFor(user);
    need(invalid(await reset(user.app,'invalid-'+randomUUID(),user.newPassword)),'Invalid token accepted');
    const weak = await reset(user.app,token,'a'); need(weak.body?.status==='FIELD_ERROR','Weak password accepted');
    need(ok(await reset(user.app,token,user.newPassword)),'Validation consumed a valid token');
    await assertChanged(user,user.newPassword);
  });
  await check('RESET-HTTP-003-EIGHT-CONCURRENT-CONSUMERS',async()=>{
    const user = await signup(), token = await tokenFor(user);
    const passwords = Array.from({length:8},()=>`Concurrent-${randomUUID()}-9a!`);
    const responses = await Promise.all(passwords.map(password=>reset(user.app,token,password)));
    need(responses.filter(ok).length===1 && responses.filter(invalid).length===7,'Concurrent consume invariant failed');
    await assertChanged(user,passwords[responses.findIndex(ok)]);
    return {consumers:8,winners:1,rejected_replays:7};
  });
  await check('RESET-HTTP-004-SIBLING-TOKEN-INVALIDATION',async()=>{
    const user = await signup(), first = await tokenFor(user), second = await tokenFor(user);
    need(first!==second && ok(await reset(user.app,first,user.newPassword)),'First token failed');
    need(invalid(await reset(user.app,second,user.oldPassword)),'Sibling token remained valid');
  });
  await check('RESET-HTTP-005-NONEXISTENT-TENANT-FAIL-CLOSED',async()=>{
    const user = await signup(), token = await tokenFor(user);
    const result = await reset(user.app,token,user.newPassword,'/auth/nonexistent-'+randomUUID()+'/user/password/reset');
    need(!ok(result),'Nonexistent tenant accepted reset');
    need(ok(await reset(user.app,token,user.newPassword)),'Wrong path consumed public token');
    return {negative_http:result.http, configured_cross_tenant_qualified:false};
  });
  await check('RESET-HTTP-006-UNKNOWN-EMAIL-GENERIC-NO-DELIVERY',async()=>{
    const before = (await mails()).map(row=>row.ID).sort();
    const result = await request(apps.good,`unknown-${randomUUID()}@example.test`);
    assert.deepEqual(result.body,{status:'OK'}); need(result.http===200,'Unknown response differs');
    assert.deepEqual((await mails()).map(row=>row.ID).sort(),before);
    return {timing_enumeration_resistance_qualified:false};
  });
  await check('RESET-HTTP-007-CONFIGURED-EXPIRY',async()=>{
    const immediate = await signup(apps.expiry), first = await tokenFor(immediate);
    need(ok(await reset(immediate.app,first,immediate.newPassword)),'Short TTL token immediately failed');
    const expired = await signup(apps.expiry), token = await tokenFor(expired), before = Date.now();
    await delay(6500);
    need(invalid(await reset(expired.app,token,expired.newPassword)),'Expired token accepted');
    need(ok(await call(expired.app,'/auth/signin',form(expired.email,expired.oldPassword))),'Expired token changed password');
    return {configured_lifetime_ms:5000, observed_wait_ms:Date.now()-before};
  });
  for(const role of ['wrong-auth','untrusted','outage']) await check('RESET-SMTP-'+role.toUpperCase()+'-GENERIC-RETRY',async()=>{
    const user = await signup(), before = (await mails()).map(row=>row.ID).sort();
    const existing = await request(apps[role],user.email), unknown = await request(apps[role],`unknown-${randomUUID()}@example.test`);
    need(existing.http===200 && unknown.http===200,'Failure response status differs');
    assert.deepEqual(existing.body,{status:'OK'}); assert.deepEqual(existing.body,unknown.body);
    assert.deepEqual((await mails()).map(row=>row.ID).sort(),before);
    const token = await tokenFor(user); need(ok(await reset(user.app,token,user.newPassword)),'Healthy resend recovery failed');
    return {durable_retry_queue_implemented:false};
  },'PWD-006');
  await check('RESET-HTTP-008-DISABLED-WITHOUT-SMTP',async()=>{
    need((await request(apps.disabled,`disabled-${randomUUID()}@example.test`)).http===404,'Unconfigured request enabled');
    need((await reset(apps.disabled,'synthetic-invalid','Synthetic-123456-9a!')).http===404,'Unconfigured reset enabled');
  });
  }
  await check('RESET-BROWSER-REAL-REACT-FLOW',async()=>{
    const user = await signup();
    browser = await chromium.launch({headless:true});
    let browserRows;
    const progress = [];
    let progressWrite = Promise.resolve();
    try {
      browserRows = await runPasswordResetBrowser({browser,origin:user.app,email:user.email,oldPassword:user.oldPassword,newPassword:user.newPassword,
        findResetLink:({email})=>linkFor(email), captureSuccess:page=>page.screenshot({path:out+'/reset-success.png',fullPage:true}), onProgress:async row=>{
          if(progress.length>=100) return;
          progress.push(row);
          progressWrite = progressWrite.then(()=>writeFile(out+'/browser-progress.json',JSON.stringify(progress,null,2)+'\n'));
          await progressWrite;
        }});
    } catch(error) { browserRows = error.rows || [{id:'BROWSER-UNEXPECTED-FAILURE',status:'failed'}]; throw error; }
    finally {
      await writeFile(out+'/browser-results.json',JSON.stringify({rows:browserRows,source_sha256:createHash('sha256').update(await readFile('/repo/tests/browser/password-reset.mjs')).digest('hex'),live_provider_tested:false},null,2)+'\n');
    }
    return {actual_browser_checks:browserRows.length};
  });
} catch { failed=true; rows.push({id:'RESET-WORKER',status:'failed',error:'Worker precondition or operation failed'}); }
finally {
  if(browser) {
    let deadline;
    try {await Promise.race([browser.close(),new Promise((_,reject)=>{deadline=setTimeout(()=>reject(new Error('Browser close deadline exceeded')),5000);})]);}
    catch {failed=true; rows.push({id:'BROWSER-CLOSE',status:'failed',error:'Owned browser did not close'});}
    finally {clearTimeout(deadline);}
  }
  await check('RESET-OWNED-FIXTURE-CLEANUP',async()=>{
    need(Array.isArray(baseline),'Cannot clean without baseline');
    const current = await identities();
    for(const user of users) {
      const matches = current.filter(value=>(value.emails || [value.email]).includes(user.email));
      need(matches.length<=1,'Ambiguous fixture ownership');
      for(const found of matches) {
        need(!baseline.includes(found.id) && (!user.id || user.id===found.id),'Cleanup identity mismatch');
        need(ok(await direct('/user/remove',{userId:found.id,removeAllLinkedAccounts:false})),'Owned identity cleanup failed');
      }
    }
    assert.deepEqual((await identities()).map(user=>user.id).sort(),baseline);
    return {source_identity_count:baseline.length,owned_fixture_count:users.length,original_identity_set_restored:true};
  });
  await save();
  await writeFile(out+'/probe-results.json',JSON.stringify({schema:'expertauth-password-reset-lab-v1',started,finished:new Date().toISOString(),rows,wire,
    passed:!failed && rows.every(row=>row.status==='passed'),mode:browserOnly?'browser-only':'full-reference-lab',skipped:0,foundation_passed:false,full_PWD_006_qualified:false,
    live_provider_tested:false,independent_security_review:false,
    limitations:['No configured cross-tenant proof','Reset/password-update/session-revoke are separate transactions','SMTP timing privacy and durable outbox remain unqualified','Browser HTTP is internal lab transport; SMTP and mailbox use verified TLS']},null,2)+'\n');
}
// This is the sole foreground worker in an owned --rm container. A failed browser
// teardown cannot keep its child processes alive after durable reports/cleanup.
process.exit(failed ? 1:0);
