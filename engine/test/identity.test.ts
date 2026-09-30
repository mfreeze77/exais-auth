import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { hash as argon2Hash } from '@node-rs/argon2';
import bcrypt from 'bcryptjs';
import { email, type Harness, startHarness, UNICODE_PASSWORD } from './helpers.ts';

let h: Harness;
before(async () => { h = await startHarness(); });
after(async () => { await h.close(); });

const HASH_MARKERS = /\$2[abxy]\$|\$argon2|password_hash|passwordHash/;
const stored = async (methodId: string) =>
  (await h.db.query('SELECT password_hash FROM ea_password_credentials WHERE method_id = $1', [methodId])).rows[0].password_hash as string;

describe('email/password identity', () => {
  it('signs up and signs in with a Unicode password decoded as UTF-8', async () => {
    const e = email('unicode');
    const up = await h.call('POST', '/recipe/signup', { email: e, password: UNICODE_PASSWORD });
    assert.equal(up.body.status, 'OK');
    assert.equal(up.body.user.loginMethods[0].email, e);
    assert.deepEqual(up.body.user.tenantIds, ['public']);
    const inn = await h.call('POST', '/recipe/signin', { email: e.toUpperCase(), password: UNICODE_PASSWORD });
    assert.equal(inn.body.status, 'OK');
    assert.equal(inn.body.user.id, up.body.user.id);
    const latin1 = Buffer.from(UNICODE_PASSWORD, 'utf8').toString('latin1');
    assert.equal((await h.call('POST', '/recipe/signin', { email: e, password: latin1 })).body.status, 'WRONG_CREDENTIALS_ERROR');
    assert.ok((await stored(up.body.recipeUserId)).startsWith('$argon2id$v=19$m=8192,t=1,p=1$'));
    assert.doesNotMatch(up.text + inn.text, HASH_MARKERS);
  });

  it('refuses wrong passwords and unknown users with the same status', async () => {
    const e = email('wrong');
    await h.call('POST', '/recipe/signup', { email: e, password: 'correct horse' });
    assert.equal((await h.call('POST', '/recipe/signin', { email: e, password: 'wrong horse' })).body.status, 'WRONG_CREDENTIALS_ERROR');
    assert.equal((await h.call('POST', '/recipe/signin', { email: email('nobody'), password: 'x' })).body.status, 'WRONG_CREDENTIALS_ERROR');
  });

  it('rejects a duplicate email in the same tenant, including under concurrency', async () => {
    const e = email('dup');
    const results = await Promise.all(Array.from({ length: 8 }, () => h.call('POST', '/recipe/signup', { email: e, password: 'pw-123456' })));
    assert.equal(results.filter((r) => r.body.status === 'OK').length, 1);
    assert.equal(results.filter((r) => r.body.status === 'EMAIL_ALREADY_EXISTS_ERROR').length, 7);
    const orphans = await h.db.query(`SELECT count(*)::int AS n FROM ea_login_methods m WHERE m.email = $1
      AND NOT EXISTS (SELECT 1 FROM ea_tenant_methods t WHERE t.method_id = m.method_id)`, [e]);
    assert.equal(orphans.rows[0].n, 0, 'losing signups must roll back completely');
  });

  it('rejects malformed input, missing API keys and unsupported CDI versions', async () => {
    assert.equal((await h.call('POST', '/recipe/signup', { email: 'not-an-email', password: 'x' })).status, 400);
    assert.equal((await h.call('POST', '/recipe/signup', { email: email('x'), password: '' })).status, 400);
    assert.equal((await h.call('POST', '/recipe/signin', { email: email('x'), password: 'x' }, { 'api-key': 'wrong-key-wrong-key-00' })).status, 401);
    assert.equal((await h.call('GET', '/apiversion', undefined, { 'cdi-version': '2.0' })).status, 400);
    assert.equal((await h.call('POST', '/recipe/signup', '{"email":')).status, 400);
    assert.equal((await h.call('POST', '/recipe/signup', new Uint8Array([0x7b, 0xff, 0x7d]))).status, 400, 'non-UTF-8 bytes are refused');
    assert.equal((await h.call('POST', '/recipe/signup', JSON.stringify({ email: 'a@b.c', password: 'x'.repeat(70000) }))).status, 413);
    assert.equal((await h.call('POST', '/appid-nosuchapp/recipe/signin', { email: 'a@b.c', password: 'x' })).status, 400);
  });
});

describe('native multi-tenancy', () => {
  it('creates apps and tenants and keeps the same email distinct per tenant', async () => {
    assert.equal((await h.call('PUT', '/recipe/multitenancy/app/v2', { appId: 'acme' })).body.createdNew, true);
    assert.equal((await h.call('PUT', '/recipe/multitenancy/app/v2', { appId: 'acme' })).body.createdNew, false);
    assert.equal((await h.call('PUT', '/appid-acme/recipe/multitenancy/tenant/v2', { tenantId: 'east' })).body.createdNew, true);
    await h.call('PUT', '/appid-acme/recipe/multitenancy/tenant/v2', { tenantId: 'west' });
    const tenants = await h.call('GET', '/appid-acme/recipe/multitenancy/tenant/list/v2');
    assert.deepEqual(tenants.body.tenants.map((t: any) => t.tenantId), ['east', 'public', 'west']);

    const e = email('shared');
    const east = await h.call('POST', '/appid-acme/east/recipe/signup', { email: e, password: 'east-password' });
    const west = await h.call('POST', '/appid-acme/west/recipe/signup', { email: e, password: 'west-password' });
    assert.equal(east.body.status, 'OK'); assert.equal(west.body.status, 'OK');
    assert.notEqual(east.body.user.id, west.body.user.id);
    assert.equal((await h.call('POST', '/appid-acme/east/recipe/signin', { email: e, password: 'west-password' })).body.status, 'WRONG_CREDENTIALS_ERROR');
    assert.equal((await h.call('POST', '/appid-acme/west/recipe/signin', { email: e, password: 'west-password' })).body.status, 'OK');
    // Apps are isolated identity namespaces.
    assert.equal((await h.call('POST', '/recipe/signin', { email: e, password: 'east-password' })).body.status, 'WRONG_CREDENTIALS_ERROR');
  });

  it('shares an identity with another tenant only explicitly, and refuses email conflicts', async () => {
    await h.call('PUT', '/recipe/multitenancy/app/v2', { appId: 'share' });
    for (const tenantId of ['a', 'b']) await h.call('PUT', '/appid-share/recipe/multitenancy/tenant/v2', { tenantId });
    const e = email('member');
    const a = await h.call('POST', '/appid-share/a/recipe/signup', { email: e, password: 'pw-a-123' });
    assert.equal((await h.call('POST', '/appid-share/b/recipe/signin', { email: e, password: 'pw-a-123' })).body.status, 'WRONG_CREDENTIALS_ERROR');
    const joined = await h.call('POST', '/appid-share/b/recipe/multitenancy/tenant/user', { recipeUserId: a.body.recipeUserId });
    assert.deepEqual(joined.body, { status: 'OK', wasAlreadyAssociated: false });
    assert.equal((await h.call('POST', '/appid-share/b/recipe/multitenancy/tenant/user', { recipeUserId: a.body.recipeUserId })).body.wasAlreadyAssociated, true);
    assert.equal((await h.call('POST', '/appid-share/b/recipe/signin', { email: e, password: 'pw-a-123' })).body.user.id, a.body.user.id);

    const other = email('conflict');
    const inA = await h.call('POST', '/appid-share/a/recipe/signup', { email: other, password: 'pw-1234' });
    await h.call('POST', '/appid-share/b/recipe/signup', { email: other, password: 'pw-5678' });
    const clash = await h.call('POST', '/appid-share/b/recipe/multitenancy/tenant/user', { recipeUserId: inA.body.recipeUserId });
    assert.equal(clash.body.status, 'EMAIL_ALREADY_EXISTS_ERROR');

    const removed = await h.call('POST', '/appid-share/b/recipe/multitenancy/tenant/user/remove', { recipeUserId: a.body.recipeUserId });
    assert.equal(removed.body.wasAssociated, true);
    assert.equal((await h.call('POST', '/appid-share/b/recipe/signin', { email: e, password: 'pw-a-123' })).body.status, 'WRONG_CREDENTIALS_ERROR');
  });

  it('refuses sign-in on a tenant with email/password disabled and unknown tenants', async () => {
    await h.call('PUT', '/recipe/multitenancy/tenant/v2', { tenantId: 'locked', emailPasswordEnabled: false });
    assert.equal((await h.call('POST', '/locked/recipe/signup', { email: email('l'), password: 'pw-123' })).status, 400);
    assert.equal((await h.call('POST', '/nosuchtenant/recipe/signin', { email: email('l'), password: 'pw' })).status, 400);
    assert.equal((await h.call('PUT', '/appid-acme/recipe/multitenancy/app/v2', { appId: 'x' })).status, 400, 'only the public app manages apps');
  });
});

describe('password hash import and rehash', () => {
  it('imports bcrypt and argon2i hashes from independent libraries and rehashes to argon2id on login', async () => {
    const fixtures: Record<string, string> = {
      bcrypt: await bcrypt.hash(UNICODE_PASSWORD, 10),
      argon2i: await argon2Hash(UNICODE_PASSWORD, { algorithm: 1, memoryCost: 19456, timeCost: 2, parallelism: 1 }),
    };
    for (const [name, value] of Object.entries(fixtures)) {
      const e = email('import-' + name);
      const imported = await h.call('POST', '/recipe/user/passwordhash/import', { email: e, passwordHash: value });
      assert.equal(imported.body.status, 'OK', name);
      assert.doesNotMatch(imported.text, HASH_MARKERS);
      const id = imported.body.user.loginMethods[0].recipeUserId;
      assert.equal((await h.call('POST', '/recipe/signin', { email: e, password: 'wrong' })).body.status, 'WRONG_CREDENTIALS_ERROR');
      assert.equal(await stored(id), value, 'a failed login never rehashes');
      assert.equal((await h.call('POST', '/recipe/signin', { email: e, password: UNICODE_PASSWORD })).body.status, 'OK');
      const rehashed = await stored(id);
      assert.ok(rehashed.startsWith('$argon2id$v=19$m=8192,t=1,p=1$'), name);
      assert.equal((await h.call('POST', '/recipe/signin', { email: e, password: UNICODE_PASSWORD })).body.status, 'OK');
      assert.equal(await stored(id), rehashed, 'current hashes are stable');
    }
  });

  it('accepts all eight concurrent first logins on an imported hash and leaves it rehashed', async () => {
    const e = email('concurrent-import');
    const imported = await h.call('POST', '/recipe/user/passwordhash/import', { email: e, passwordHash: await bcrypt.hash('pw-conc', 10) });
    const results = await Promise.all(Array.from({ length: 8 }, () => h.call('POST', '/recipe/signin', { email: e, password: 'pw-conc' })));
    assert.ok(results.every((r) => r.body.status === 'OK'));
    assert.ok((await stored(imported.body.user.loginMethods[0].recipeUserId)).startsWith('$argon2id$'));
  });

  it('reports unsupported, malformed and over-cost hashes', async () => {
    const good = await bcrypt.hash('x', 10);
    const bad = ['5f4dcc3b5aa765d61d8327deb882cf99', '$6$salt$' + 'a'.repeat(86), 'plaintext', '$2a$10$short', good.slice(0, -1) + '!',
      '$2b$17' + good.slice(6), '$argon2id$garbage', '$argon2id$v=19$m=4194304,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA'];
    for (const passwordHash of bad) {
      const r = await h.call('POST', '/recipe/user/passwordhash/import', { email: email('bad'), passwordHash });
      assert.equal(r.status, 400, passwordHash);
    }
  });
});
