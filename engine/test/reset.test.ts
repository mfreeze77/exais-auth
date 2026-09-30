import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { email, type Harness, startHarness } from './helpers.ts';

let h: Harness;
before(async () => { h = await startHarness(); });
after(async () => { await h.close(); });

async function account(path = '') {
  const e = email('reset');
  const up = await h.call('POST', `${path}/recipe/signup`, { email: e, password: 'old-password-1' });
  return { email: e, id: up.body.recipeUserId as string };
}
const token = async (a: { email: string; id: string }, path = '') =>
  (await h.call('POST', `${path}/recipe/user/password/reset/token`, { userId: a.id, email: a.email })).body.token as string;

describe('password reset', () => {
  it('atomically replaces the password and revokes every session', async () => {
    const a = await account();
    const s = await h.call('POST', '/recipe/session', { userId: a.id });
    const t = await token(a);
    assert.match(t, /^[A-Za-z0-9_-]{64}$/);
    const r = await h.call('POST', '/recipe/user/password/reset', { method: 'token', token: t, newPassword: 'new-password-2' });
    assert.deepEqual(r.body, { status: 'OK', userId: a.id, email: a.email });
    assert.equal((await h.call('POST', '/recipe/signin', { email: a.email, password: 'old-password-1' })).body.status, 'WRONG_CREDENTIALS_ERROR');
    assert.equal((await h.call('POST', '/recipe/signin', { email: a.email, password: 'new-password-2' })).body.status, 'OK');
    assert.equal((await h.call('POST', '/recipe/session/refresh', { refreshToken: s.body.refreshToken.token })).body.status, 'UNAUTHORISED');
    assert.equal((await h.call('POST', '/recipe/user/password/reset', { token: t, newPassword: 'again-3' })).body.status, 'RESET_PASSWORD_INVALID_TOKEN_ERROR');
    const stored = await h.db.query('SELECT count(*)::int AS n FROM ea_reset_tokens WHERE token_hash = $1', [t]);
    assert.equal(stored.rows[0].n, 0, 'the raw token is never stored');
  });

  it('lets exactly one of eight concurrent consumers win', async () => {
    const a = await account();
    const t = await token(a);
    const results = await Promise.all(Array.from({ length: 8 }, (_, i) =>
      h.call('POST', '/recipe/user/password/reset', { token: t, newPassword: `racer-${i}-password` })));
    const winners = results.map((r, i) => [r.body.status, i] as const).filter(([s]) => s === 'OK');
    assert.equal(winners.length, 1);
    const winner = winners[0]![1];
    assert.equal((await h.call('POST', '/recipe/signin', { email: a.email, password: `racer-${winner}-password` })).body.status, 'OK');
  });

  it('spends every outstanding token on success, but an expired token spends only itself', async () => {
    const a = await account();
    const [t1, t2, t3] = [await token(a), await token(a), await token(a)];
    await h.db.query("UPDATE ea_reset_tokens SET expires_at = 0 WHERE token_hash = encode(sha256(convert_to($1, 'UTF8')), 'hex')", [t1]);
    assert.equal((await h.call('POST', '/recipe/user/password/reset', { token: t1, newPassword: 'x-password' })).body.status, 'RESET_PASSWORD_INVALID_TOKEN_ERROR');
    assert.equal((await h.call('POST', '/recipe/user/password/reset', { token: t2, newPassword: 'y-password' })).body.status, 'OK');
    assert.equal((await h.call('POST', '/recipe/user/password/reset', { token: t3, newPassword: 'z-password' })).body.status, 'RESET_PASSWORD_INVALID_TOKEN_ERROR');
  });

  it('confines tokens to their tenant and to the owner email', async () => {
    await h.call('PUT', '/recipe/multitenancy/tenant/v2', { tenantId: 'green' });
    const a = await account('/green');
    const t = await token(a, '/green');
    assert.equal((await h.call('POST', '/recipe/user/password/reset', { token: t, newPassword: 'cross-tenant' })).body.status, 'RESET_PASSWORD_INVALID_TOKEN_ERROR');
    assert.equal((await h.call('POST', '/green/recipe/user/password/reset', { token: t, newPassword: 'same-tenant' })).body.status, 'OK');
    const b = await account();
    assert.equal((await h.call('POST', '/recipe/user/password/reset/token', { userId: b.id, email: email('someone-else') })).body.status, 'UNKNOWN_USER_ID_ERROR');
    assert.equal((await h.call('POST', '/green/recipe/user/password/reset/token', { userId: b.id, email: b.email })).body.status, 'UNKNOWN_USER_ID_ERROR');
  });

  it('supports the two-step consume flow with single use', async () => {
    const a = await account();
    const t = await token(a);
    assert.deepEqual((await h.call('POST', '/recipe/user/password/reset/token/consume', { token: t })).body, { status: 'OK', userId: a.id, email: a.email });
    assert.equal((await h.call('POST', '/recipe/user/password/reset/token/consume', { token: t })).body.status, 'RESET_PASSWORD_INVALID_TOKEN_ERROR');
    assert.equal((await h.call('PUT', '/recipe/user', { recipeUserId: a.id, password: 'updated-password' })).body.status, 'OK');
    assert.equal((await h.call('POST', '/recipe/signin', { email: a.email, password: 'updated-password' })).body.status, 'OK');
  });
});
