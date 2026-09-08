import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

const base = process.env.EXPERTAUTH_TEST_URL || 'http://node-app.example.test:3000';
const origin = new URL(base).origin;
const password = `Synthetic-${randomUUID()}-a9!`;
const headers = { 'content-type': 'application/json', 'fdi-version': '4.2', rid: 'emailpassword', 'st-auth-mode': 'header', origin };
async function signup(mode = 'header') {
  const email = `node-${randomUUID()}@example.test`;
  const response = await fetch(`${base}/auth/signup`, { method: 'POST', headers: {...headers,'st-auth-mode':mode}, body: JSON.stringify({ formFields: [{id:'email',value:email},{id:'password',value:password}] }) });
  assert.equal(response.status,200);
  const body = await response.json();
  assert.equal(body.status,'OK');
  return { email, body, access: response.headers.get('st-access-token'), refresh: response.headers.get('st-refresh-token'), cookies: response.headers.getSetCookie() };
}
function bearer(access) { return {...headers,rid:'session',authorization:`Bearer ${access}`}; }

test('NODE-LIVE-001 readiness performs an authenticated database query', async () => {
  const response = await fetch(`${base}/health/ready`);
  assert.equal(response.status,200);
  assert.equal((await response.json()).status,'ready');
});
test('NODE-PWD-001 signup creates a real online-verifiable session', async () => {
  const user = await signup();
  assert.ok(user.access && user.refresh);
  const response = await fetch(`${base}/api/session/online`,{headers:bearer(user.access)});
  assert.equal(response.status,200);
  const body = await response.json();
  assert.equal(body.userId,user.body.user.id);
  assert.equal(body.tenantId,'public');
});
test('NODE-PWD-002 wrong password produces no session', async () => {
  const user = await signup();
  const response = await fetch(`${base}/auth/signin`,{method:'POST',headers,body:JSON.stringify({formFields:[{id:'email',value:user.email},{id:'password',value:password+'wrong'}]})});
  assert.equal(response.status,200);
  assert.equal((await response.json()).status,'WRONG_CREDENTIALS_ERROR');
  assert.equal(response.headers.get('st-access-token'),null);
});
test('NODE-SESSION-001 no token and malformed token rejected', async () => {
  assert.equal((await fetch(`${base}/api/session/online`)).status,401);
  assert.equal((await fetch(`${base}/api/session/online`,{headers:bearer('invalid.token.value')})).status,401);
});
test('NODE-SESSION-002 refresh rotates and logout blocks online access and refresh', async () => {
  const user = await signup();
  const refreshed = await fetch(`${base}/auth/session/refresh`,{method:'POST',headers:bearer(user.refresh)});
  assert.equal(refreshed.status,200);
  let access = refreshed.headers.get('st-access-token');
  const refresh = refreshed.headers.get('st-refresh-token');
  assert.ok(access && refresh);
  assert.notEqual(refresh,user.refresh);
  const settled = await fetch(`${base}/api/session`,{headers:bearer(access)});
  assert.equal(settled.status,200);
  // Respect returned SDK tokens. CDI5.6 keeps a parent marker and the unmodified
  // Node SDK can continue checking Core; explicit offline verification is separate.
  access = settled.headers.get('st-access-token') || access;
  assert.equal((await fetch(`${base}/api/session/offline`,{headers:bearer(access)})).status,200);
  const logout = await fetch(`${base}/auth/signout`,{method:'POST',headers:bearer(access)});
  assert.equal(logout.status,200);
  assert.equal((await fetch(`${base}/api/session/online`,{headers:bearer(access)})).status,401);
  assert.equal((await fetch(`${base}/auth/session/refresh`,{method:'POST',headers:bearer(refresh)})).status,401);
  // Offline verification deliberately has a residual access-token validity window.
  assert.equal((await fetch(`${base}/api/session/offline`,{headers:bearer(access)})).status,200);
});
test('NODE-TENANT-001 valid session cannot substitute its tenant', async () => {
  const user = await signup();
  assert.equal((await fetch(`${base}/api/tenants/public/session`,{headers:bearer(user.access)})).status,200);
  assert.equal((await fetch(`${base}/api/tenants/other-tenant/session`,{headers:bearer(user.access)})).status,403);
});
test('NODE-ORIGIN-001 foreign origin cannot submit authenticated or anonymous calls', async () => {
  const response = await fetch(`${base}/auth/signup`,{method:'POST',headers:{...headers,origin:'https://attacker.example'},body:'{}'});
  assert.equal(response.status,403);
  assert.equal(response.headers.get('access-control-allow-origin'),null);
});
test('NODE-PRIVATE-001 Core business APIs are not public routes', async () => {
  assert.equal((await fetch(`${base}/recipe/session`,{method:'POST',headers,body:'{}'})).status,404);
  assert.equal((await fetch(`${base}/recipe/multitenancy/app/v2`,{method:'PUT',headers,body:'{}'})).status,404);
});
test('NODE-COOKIE-001 cookie attributes and refresh CSRF', async () => {
  const user = await signup('cookie');
  const access = user.cookies.find(c=>c.startsWith('sAccessToken='));
  const refresh = user.cookies.find(c=>c.startsWith('sRefreshToken='));
  assert.ok(access?.includes('HttpOnly') && access?.includes('SameSite=Lax'));
  assert.ok(refresh?.includes('HttpOnly') && refresh?.includes('Path=/auth/session/refresh'));
  assert.equal(user.access,null);
  const cookie = user.cookies.map(c=>c.split(';')[0]).join('; ');
  const response = await fetch(`${base}/auth/session/refresh`,{method:'POST',headers:{cookie,'fdi-version':'4.2',origin,'st-auth-mode':'cookie'}});
  assert.equal(response.status,401);
});
test('NODE-LIMIT-001 oversized JSON rejected without reflecting payload', async () => {
  const response = await fetch(`${base}/auth/signup`,{method:'POST',headers,body:JSON.stringify({password:'SENSITIVE'.repeat(6000)})});
  assert.equal(response.status,413);
  assert.equal((await response.text()).includes('SENSITIVE'),false);
});
test('NODE-OFFLINE-001 real Core-signed wrong issuer and audience tokens are rejected', async () => {
  const user = await signup();
  assert.ok(process.env.EXPERTAUTH_CORE_API_KEY,'Owned Core key required for signed negative fixtures');
  for (const payload of [{iss:'https://wrong-issuer.example',aud:`${origin}/api`},{iss:origin,aud:'https://wrong-audience.example/api'}]) {
    const response = await fetch('http://core-a:3567/recipe/session',{method:'POST',headers:{'content-type':'application/json','api-key':process.env.EXPERTAUTH_CORE_API_KEY,'cdi-version':'5.6'},body:JSON.stringify({userId:user.body.user.id,userDataInJWT:payload,userDataInDatabase:{},enableAntiCsrf:false,useDynamicSigningKey:true})});
    assert.equal(response.status,200);
    const signed = await response.json();
    assert.equal(signed.status,'OK');
    assert.equal((await fetch(`${base}/api/session/offline`,{headers:bearer(signed.accessToken.token)})).status,401);
    assert.equal((await fetch(`${base}/api/session/online`,{headers:bearer(signed.accessToken.token)})).status,401);
  }
});
test('NODE-OFFLINE-002 malformed and unsigned tokens cannot access offline route', async () => {
  assert.equal((await fetch(`${base}/api/session/offline`)).status,401);
  const fake = `${Buffer.from(JSON.stringify({alg:'none'})).toString('base64url')}.${Buffer.from(JSON.stringify({sub:'invented',iss:origin,aud:`${origin}/api`,exp:9999999999,tId:'public',sessionHandle:'invented'})).toString('base64url')}.`;
  assert.equal((await fetch(`${base}/api/session/offline`,{headers:bearer(fake)})).status,401);
});
