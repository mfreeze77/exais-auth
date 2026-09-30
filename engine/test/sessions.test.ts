import assert from 'node:assert/strict';
import { createPublicKey, createVerify } from 'node:crypto';
import { after, before, describe, it } from 'node:test';
import { type Harness, startHarness } from './helpers.ts';

let h: Harness;
before(async () => { h = await startHarness(); });
after(async () => { await h.close(); });

const create = (extra: Record<string, unknown> = {}, path = '/recipe/session') =>
  h.call('POST', path, { userId: 'user-' + Math.random().toString(36).slice(2), userDataInJWT: { role: 'member' }, userDataInDatabase: { n: 1 }, ...extra });
const refresh = (refreshToken: string, extra: Record<string, unknown> = {}) => h.call('POST', '/recipe/session/refresh', { refreshToken, ...extra });
const verify = (accessToken: string, extra: Record<string, unknown> = {}) =>
  h.call('POST', '/recipe/session/verify', { accessToken, doAntiCsrfCheck: false, enableAntiCsrf: false, checkDatabase: true, ...extra });
const expireGrace = (handle: string) => h.db.query('UPDATE ea_sessions SET previous_valid_until = 0 WHERE session_handle = $1', [handle]);

describe('access tokens', () => {
  it('issues RS256 tokens that verify offline against the public JWKS', async () => {
    const s = await create();
    assert.equal(s.body.status, 'OK');
    const jwks = await fetch(h.base + '/.well-known/jwks.json').then((r) => r.json()) as { keys: any[] };
    const [header, payload, signature] = s.body.accessToken.token.split('.');
    const kid = JSON.parse(Buffer.from(header, 'base64url').toString()).kid;
    const jwk = jwks.keys.find((k) => k.kid === kid);
    assert.ok(jwk && !('d' in jwk), 'JWKS exposes only public material');
    assert.ok(createVerify('RSA-SHA256').update(`${header}.${payload}`).verify(createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(signature, 'base64url')));
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
    assert.equal(claims.sub, s.body.session.userId);
    assert.equal(claims.sessionHandle, s.body.session.handle);
    assert.equal(claims.tId, 'public');
    assert.equal(claims.role, 'member');
    const v = await verify(s.body.accessToken.token);
    assert.equal(v.body.status, 'OK');
    assert.deepEqual(v.body.session.userDataInJWT, { role: 'member' });
  });

  it('keeps protected claims authoritative and refuses tampered or unsigned tokens', async () => {
    const s = await create({ userDataInJWT: { sub: 'attacker', sessionHandle: 'forged', tId: 'other', exp: 9999999999, keep: 1 } });
    const claims = JSON.parse(Buffer.from(s.body.accessToken.token.split('.')[1], 'base64url').toString());
    assert.equal(claims.sub, s.body.session.userId); assert.equal(claims.sessionHandle, s.body.session.handle);
    assert.equal(claims.tId, 'public'); assert.ok(claims.exp < 9999999999); assert.equal(claims.keep, 1);
    const [header, payload] = s.body.accessToken.token.split('.');
    const forged = Buffer.from(JSON.stringify({ ...claims, sub: 'attacker' })).toString('base64url');
    assert.equal((await verify(`${header}.${forged}.${s.body.accessToken.token.split('.')[2]}`)).body.status, 'TRY_REFRESH_TOKEN');
    const none = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    assert.equal((await verify(`${none}.${payload}.`)).body.status, 'TRY_REFRESH_TOKEN');
    assert.equal((await verify('garbage')).body.status, 'TRY_REFRESH_TOKEN');
  });

  it('enforces the anti-CSRF token when enabled', async () => {
    const s = await create({ enableAntiCsrf: true });
    assert.ok(s.body.antiCsrfToken);
    assert.equal((await verify(s.body.accessToken.token, { doAntiCsrfCheck: true })).body.status, 'TRY_REFRESH_TOKEN');
    assert.equal((await verify(s.body.accessToken.token, { doAntiCsrfCheck: true, antiCsrfToken: s.body.antiCsrfToken })).body.status, 'OK');
    assert.equal((await refresh(s.body.refreshToken.token)).body.status, 'UNAUTHORISED');
    assert.equal((await refresh(s.body.refreshToken.token, { antiCsrfToken: s.body.antiCsrfToken })).body.status, 'OK');
  });
});

describe('refresh rotation', () => {
  it('rotates, and the new refresh token is required afterwards', async () => {
    const s = await create();
    const r1 = await refresh(s.body.refreshToken.token);
    assert.equal(r1.body.status, 'OK');
    assert.notEqual(r1.body.refreshToken.token, s.body.refreshToken.token);
    const r2 = await refresh(r1.body.refreshToken.token);
    assert.equal(r2.body.status, 'OK');
    assert.equal((await verify(r2.body.accessToken.token)).body.status, 'OK');
  });

  it('converges eight concurrent refreshes of one token on a single successor', async () => {
    const s = await create();
    const results = await Promise.all(Array.from({ length: 8 }, () => refresh(s.body.refreshToken.token)));
    assert.ok(results.every((r) => r.body.status === 'OK'), JSON.stringify(results.map((r) => r.body.status)));
    assert.equal(new Set(results.map((r) => r.body.refreshToken.token)).size, 1);
    const row = await h.db.query('SELECT generation FROM ea_sessions WHERE session_handle = $1', [s.body.session.handle]);
    assert.equal(row.rows[0].generation, 1);
    assert.equal((await refresh(results[0]!.body.refreshToken.token)).body.status, 'OK', 'the shared successor keeps working');
  });

  it('recovers a lost refresh response by retrying the parent within the grace window', async () => {
    const s = await create();
    const lost = await refresh(s.body.refreshToken.token);
    const retry = await refresh(s.body.refreshToken.token);
    assert.equal(retry.body.status, 'OK');
    assert.equal(retry.body.refreshToken.token, lost.body.refreshToken.token);
  });

  it('treats parent reuse after the grace window as theft and revokes the session', async () => {
    const s = await create();
    const child = await refresh(s.body.refreshToken.token);
    await expireGrace(s.body.session.handle);
    const replay = await refresh(s.body.refreshToken.token);
    assert.equal(replay.body.status, 'TOKEN_THEFT_DETECTED');
    assert.equal(replay.body.session.handle, s.body.session.handle);
    assert.equal((await refresh(child.body.refreshToken.token)).body.status, 'UNAUTHORISED', 'the whole family is revoked');
    assert.equal((await verify(child.body.accessToken.token)).body.status, 'UNAUTHORISED');
  });

  it('treats grandparent reuse as theft even inside the grace window', async () => {
    const s = await create();
    const c1 = await refresh(s.body.refreshToken.token);
    await refresh(c1.body.refreshToken.token);
    assert.equal((await refresh(s.body.refreshToken.token)).body.status, 'TOKEN_THEFT_DETECTED');
  });

  it('refuses unknown, revoked and expired refresh tokens', async () => {
    assert.equal((await refresh('not-a-real-token')).body.status, 'UNAUTHORISED');
    const s = await create();
    await h.db.query('UPDATE ea_sessions SET expires_at = 0 WHERE session_handle = $1', [s.body.session.handle]);
    assert.equal((await refresh(s.body.refreshToken.token)).body.status, 'UNAUTHORISED');
  });

  it('with zero grace, a concurrent duplicate refresh is treated as reuse (strict policy, opt-in)', async () => {
    const strict = await startHarness({ EXPERTAUTH_REFRESH_GRACE_SECONDS: '0' });
    try {
      const s = await strict.call('POST', '/recipe/session', { userId: 'strict' });
      const first = await strict.call('POST', '/recipe/session/refresh', { refreshToken: s.body.refreshToken.token });
      const second = await strict.call('POST', '/recipe/session/refresh', { refreshToken: s.body.refreshToken.token });
      assert.equal(first.body.status, 'OK');
      assert.equal(second.body.status, 'TOKEN_THEFT_DETECTED');
    } finally {
      await strict.close();
    }
  });
});

describe('revocation and tenancy', () => {
  it('revokes by handle and by user, and verify with checkDatabase then fails', async () => {
    const a = await create({ userId: 'revoke-me' });
    const b = await create({ userId: 'revoke-me' });
    const byHandle = await h.call('POST', '/recipe/session/remove', { sessionHandles: [a.body.session.handle] });
    assert.deepEqual(byHandle.body.sessionHandlesRevoked, [a.body.session.handle]);
    assert.equal((await verify(a.body.accessToken.token)).body.status, 'UNAUTHORISED');
    assert.equal((await verify(a.body.accessToken.token, { checkDatabase: false })).body.status, 'OK', 'offline verification is a separate profile');
    const byUser = await h.call('POST', '/recipe/session/remove', { userId: 'revoke-me' });
    assert.deepEqual(byUser.body.sessionHandlesRevoked, [b.body.session.handle]);
    assert.equal((await refresh(b.body.refreshToken.token)).body.status, 'UNAUTHORISED');
  });

  it('binds the tenant at creation and exposes session info without token material', async () => {
    await h.call('PUT', '/recipe/multitenancy/tenant/v2', { tenantId: 'blue' });
    const s = await create({}, '/blue/recipe/session');
    assert.equal(s.body.session.tenantId, 'blue');
    const info = await h.call('GET', '/recipe/session?sessionHandle=' + s.body.session.handle);
    assert.equal(info.body.tenantId, 'blue');
    assert.deepEqual(info.body.userDataInDatabase, { n: 1 });
    assert.doesNotMatch(info.text, /refresh|antiCsrf/i);
    assert.equal((await create({}, '/no-such-tenant/recipe/session')).status, 400);
  });

  it('isolates apps: a token from one app does not verify in another', async () => {
    await h.call('PUT', '/recipe/multitenancy/app/v2', { appId: 'other' });
    const s = await create();
    assert.equal((await h.call('POST', '/appid-other/recipe/session/verify', { accessToken: s.body.accessToken.token, checkDatabase: false })).body.status, 'TRY_REFRESH_TOKEN');
    assert.equal((await h.call('POST', '/appid-other/recipe/session/refresh', { refreshToken: s.body.refreshToken.token })).body.status, 'UNAUTHORISED');
  });
});
