import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { email, type Harness, startHarness } from './helpers.ts';

let h: Harness;
before(async () => { h = await startHarness(); });
after(async () => { await h.close(); });

async function account(tenant = '') {
  const e = email('verify');
  const r = await h.call('POST', `${tenant}/recipe/signup`, { email: e, password: 'pw-verify-1' });
  return { id: r.body.recipeUserId as string, email: e };
}
const issue = (a: { id: string; email: string }, tenant = '') =>
  h.call('POST', `${tenant}/recipe/user/email/verify/token`, { userId: a.id, email: a.email });
const status = async (a: { id: string; email: string }) =>
  (await h.call('GET', `/recipe/user/email/verify?userId=${a.id}&email=${encodeURIComponent(a.email)}`)).body.isVerified as boolean;

describe('email verification', () => {
  it('verifies with a single-use token and reflects it on the user', async () => {
    const a = await account();
    assert.equal(await status(a), false);
    const t = (await issue(a)).body.token;
    assert.match(t, /^[A-Za-z0-9_-]{64}$/);
    assert.deepEqual((await h.call('POST', '/recipe/user/email/verify', { method: 'token', token: t })).body, { status: 'OK', userId: a.id, email: a.email });
    assert.equal(await status(a), true);
    assert.equal((await h.call('GET', `/recipe/user?userId=${a.id}`)).body.user.loginMethods[0].verified, true);
    assert.equal((await h.call('POST', '/recipe/user/email/verify', { token: t })).body.status, 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR');
    assert.equal((await issue(a)).body.status, 'EMAIL_ALREADY_VERIFIED_ERROR');
  });

  it('lets exactly one of eight concurrent consumers succeed', async () => {
    const a = await account();
    const t = (await issue(a)).body.token;
    const results = await Promise.all(Array.from({ length: 8 }, () => h.call('POST', '/recipe/user/email/verify', { token: t })));
    assert.equal(results.filter((r) => r.body.status === 'OK').length, 1);
    assert.equal(await status(a), true);
  });

  it('binds tokens to their tenant and refuses expired or removed tokens', async () => {
    await h.call('PUT', '/recipe/multitenancy/tenant/v2', { tenantId: 'mail' });
    const a = await account('/mail');
    const t = (await issue(a, '/mail')).body.token;
    assert.equal((await h.call('POST', '/recipe/user/email/verify', { token: t })).body.status, 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR');
    const expired = (await issue(a, '/mail')).body.token;
    await h.db.query("UPDATE ea_email_verification_tokens SET expires_at = 0 WHERE token_hash = encode(sha256(convert_to($1, 'UTF8')), 'hex')", [expired]);
    assert.equal((await h.call('POST', '/mail/recipe/user/email/verify', { token: expired })).body.status, 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR');
    assert.equal((await h.call('POST', '/mail/recipe/user/email/verify/token/remove', { userId: a.id, email: a.email })).body.status, 'OK');
    assert.equal((await h.call('POST', '/mail/recipe/user/email/verify', { token: t })).body.status, 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR');
    assert.equal(await status(a), false);
    const fresh = (await issue(a, '/mail')).body.token;
    assert.equal((await h.call('POST', '/mail/recipe/user/email/verify', { token: fresh })).body.status, 'OK');
  });

  it('can be revoked, and verification belongs to the exact email', async () => {
    const a = await account();
    await h.call('POST', '/recipe/user/email/verify', { token: (await issue(a)).body.token });
    assert.equal(await status({ id: a.id, email: 'other-' + a.email }), false);
    assert.equal((await h.call('POST', '/recipe/user/email/verify/remove', { userId: a.id, email: a.email })).body.status, 'OK');
    assert.equal(await status(a), false);
    assert.equal((await h.call('POST', '/recipe/user/email/verify', { token: 'x'.repeat(64) })).body.status, 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR');
    assert.equal((await h.call('POST', '/recipe/user/email/verify', { method: 'link', token: 'x' })).status, 400);
  });
});
