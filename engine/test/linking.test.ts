import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { transaction } from '../src/db.ts';
import { email, type Harness, startHarness } from './helpers.ts';

let h: Harness;
before(async () => { h = await startHarness(); });
after(async () => { await h.close(); });

async function user(tenant = '', password = 'pw-linking-1') {
  const e = email('link');
  const r = await h.call('POST', `${tenant}/recipe/signup`, { email: e, password });
  assert.equal(r.body.status, 'OK');
  return { id: r.body.recipeUserId as string, email: e, tenant, password };
}
const primary = (id: string) => h.call('POST', '/recipe/accountlinking/user/primary', { recipeUserId: id });
const link = (recipeUserId: string, primaryUserId: string) => h.call('POST', '/recipe/accountlinking/user/link', { recipeUserId, primaryUserId });
const unlink = (recipeUserId: string) => h.call('POST', '/recipe/accountlinking/user/unlink', { recipeUserId });
const signIn = (u: { email: string; tenant: string; password: string }) => h.call('POST', `${u.tenant}/recipe/signin`, { email: u.email, password: u.password });

/** Global invariants that must hold after any interleaving. */
async function assertInvariants() {
  const empty = await h.db.query(`SELECT count(*)::int AS n FROM ea_users u WHERE NOT EXISTS
    (SELECT 1 FROM ea_login_methods m WHERE m.app_id = u.app_id AND m.primary_user_id = u.user_id)`);
  assert.equal(empty.rows[0].n, 0, 'no user row may exist without login methods');
  const multi = await h.db.query(`SELECT count(*)::int AS n FROM ea_users u WHERE NOT u.is_primary AND
    (SELECT count(*) FROM ea_login_methods m WHERE m.app_id = u.app_id AND m.primary_user_id = u.user_id) > 1`);
  assert.equal(multi.rows[0].n, 0, 'only primary users may own several methods');
  const sharedEmail = await h.db.query(`SELECT count(*)::int AS n FROM (
      SELECT t.tenant_id, m.email FROM ea_login_methods m JOIN ea_users u ON u.app_id = m.app_id AND u.user_id = m.primary_user_id AND u.is_primary
        JOIN ea_tenant_methods t ON t.app_id = m.app_id AND t.method_id = m.method_id
       GROUP BY t.tenant_id, m.email HAVING count(DISTINCT m.primary_user_id) > 1) x`);
  assert.equal(sharedEmail.rows[0].n, 0, 'no two primary users share an email in a tenant');
}

describe('account linking', () => {
  it('creates primary users idempotently and links, with dry-run checks that never mutate', async () => {
    const a = await user(); const b = await user();
    assert.deepEqual((await h.call('GET', `/recipe/accountlinking/user/primary/check?recipeUserId=${a.id}`)).body, { status: 'OK', wasAlreadyAPrimaryUser: false });
    assert.equal((await h.db.query('SELECT is_primary FROM ea_users WHERE user_id = $1', [a.id])).rows[0].is_primary, false, 'check is a dry run');
    const p = await primary(a.id);
    assert.equal(p.body.status, 'OK'); assert.equal(p.body.wasAlreadyAPrimaryUser, false); assert.equal(p.body.user.isPrimaryUser, true);
    assert.equal((await primary(a.id)).body.wasAlreadyAPrimaryUser, true);
    const check = await h.call('GET', `/recipe/accountlinking/user/link/check?recipeUserId=${b.id}&primaryUserId=${a.id}`);
    assert.deepEqual(check.body, { status: 'OK', accountsAlreadyLinked: false });
    assert.equal((await h.db.query('SELECT primary_user_id FROM ea_login_methods WHERE method_id = $1', [b.id])).rows[0].primary_user_id, b.id);
    const linked = await link(b.id, a.id);
    assert.equal(linked.body.status, 'OK'); assert.equal(linked.body.accountsAlreadyLinked, false);
    assert.deepEqual(linked.body.user.loginMethods.map((m: any) => m.recipeUserId).sort(), [a.id, b.id].sort());
    assert.equal((await signIn(b)).body.user.id, a.id, 'signing in with the linked method yields the primary user');
    assert.equal((await link(b.id, a.id)).body.accountsAlreadyLinked, true);
    await assertInvariants();
  });

  it('revokes the absorbed user\'s sessions on link and keeps the primary user\'s sessions', async () => {
    const a = await user(); const b = await user();
    await primary(a.id);
    const sa = await h.call('POST', '/recipe/session', { userId: a.id });
    const sb = await h.call('POST', '/recipe/session', { userId: b.id });
    await link(b.id, a.id);
    assert.equal((await h.call('POST', '/recipe/session/refresh', { refreshToken: sb.body.refreshToken.token })).body.status, 'UNAUTHORISED');
    assert.equal((await h.call('POST', '/recipe/session/refresh', { refreshToken: sa.body.refreshToken.token })).body.status, 'OK');
  });

  it('refuses linking into non-primary users and re-linking an already-linked method', async () => {
    const a = await user(); const b = await user(); const c = await user();
    assert.equal((await link(b.id, a.id)).body.status, 'INPUT_USER_IS_NOT_A_PRIMARY_USER');
    await primary(a.id); await primary(c.id);
    await link(b.id, a.id);
    const again = await link(b.id, c.id);
    assert.equal(again.body.status, 'RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR');
    assert.equal(again.body.primaryUserId, a.id);
    assert.equal((await primary(b.id)).body.status, 'RECIPE_USER_ID_ALREADY_LINKED_WITH_PRIMARY_USER_ID_ERROR');
    assert.equal((await link(c.id, a.id)).body.status, 'RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR', 'a primary cannot be absorbed');
    assert.equal((await link('00000000-0000-4000-8000-000000000000', a.id)).body.status, 'UNKNOWN_USER_ID_ERROR');
    assert.equal((await link('not-a-uuid', a.id)).status, 400);
  });

  it('refuses a link that would give two primary users the same email in a tenant', async () => {
    for (const tenantId of ['t1', 't2']) await h.call('PUT', '/recipe/multitenancy/tenant/v2', { tenantId });
    const p = await user('/t1'); await primary(p.id);
    const z = await user('/t1'); await primary(z.id);
    const wEmail = z.email; // same email as z, but in tenant t2
    const w = await h.call('POST', '/t2/recipe/signup', { email: wEmail, password: 'pw-w-1234' });
    const result = await link(w.body.recipeUserId, p.id);
    assert.equal(result.body.status, 'ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR');
    assert.equal(result.body.primaryUserId, z.id);
    await assertInvariants();
  });

  it('unlinks into a standalone user that can still sign in, revoking its sessions', async () => {
    const a = await user(); const b = await user();
    await primary(a.id); await link(b.id, a.id);
    const s = await h.call('POST', '/recipe/session', { userId: a.id, recipeUserId: b.id });
    assert.deepEqual((await unlink(b.id)).body, { status: 'OK', wasLinked: true, wasRecipeUserDeleted: false });
    assert.equal((await signIn(b)).body.user.id, b.id);
    assert.equal((await signIn(a)).body.user.loginMethods.length, 1);
    assert.equal((await h.call('POST', '/recipe/session/refresh', { refreshToken: s.body.refreshToken.token })).body.status, 'UNAUTHORISED');
    assert.deepEqual((await unlink(b.id)).body, { status: 'OK', wasLinked: false, wasRecipeUserDeleted: false });
    assert.deepEqual((await unlink(a.id)).body, { status: 'OK', wasLinked: true, wasRecipeUserDeleted: false });
    assert.equal((await h.call('GET', `/recipe/user?userId=${a.id}`)).body.user.isPrimaryUser, false);
    await assertInvariants();
  });

  it('deletes the primary user\'s own method on unlink only while other methods remain', async () => {
    const a = await user(); const b = await user();
    await primary(a.id); await link(b.id, a.id);
    assert.deepEqual((await unlink(a.id)).body, { status: 'OK', wasLinked: true, wasRecipeUserDeleted: true });
    assert.equal((await signIn(a)).body.status, 'WRONG_CREDENTIALS_ERROR');
    assert.equal((await signIn(b)).body.user.id, a.id, 'the primary id stays stable for the remaining method');
    await assertInvariants();
  });
});

describe('account linking under concurrency', () => {
  it('links a method to exactly one of two competing primary users', async () => {
    for (let round = 0; round < 5; round++) {
      const p1 = await user(); const p2 = await user(); const r = await user();
      await primary(p1.id); await primary(p2.id);
      const results = await Promise.all(Array.from({ length: 8 }, (_, i) => link(r.id, i % 2 ? p1.id : p2.id)));
      assert.ok(results.every((x) => x.status === 200), 'no request may fail with a server error');
      const owner = (await h.db.query('SELECT primary_user_id FROM ea_login_methods WHERE method_id = $1', [r.id])).rows[0].primary_user_id;
      assert.ok(owner === p1.id || owner === p2.id);
      const firstLinks = results.filter((x) => x.body.status === 'OK' && x.body.accountsAlreadyLinked === false);
      assert.equal(firstLinks.length, 1, 'exactly one request performs the link');
      assert.ok(results.every((x) => x.body.status === 'OK' ? true : x.body.status === 'RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR' && x.body.primaryUserId === owner));
      await assertInvariants();
    }
  });

  it('keeps every remaining login method usable under parallel unlink of all methods', async () => {
    for (let round = 0; round < 5; round++) {
      const members = [await user(), await user(), await user(), await user()];
      await primary(members[0]!.id);
      for (const m of members.slice(1)) assert.equal((await link(m.id, members[0]!.id)).body.status, 'OK');
      const results = await Promise.all(members.map((m) => unlink(m.id)));
      assert.ok(results.every((x) => x.status === 200 && x.body.status === 'OK'));
      const deleted = results.filter((x) => x.body.wasRecipeUserDeleted).length;
      assert.ok(deleted <= 1, 'only the primary user\'s own method can be deleted');
      for (const [i, m] of members.entries()) {
        const signed = await signIn(m);
        if (i === 0 && deleted === 1) assert.equal(signed.body.status, 'WRONG_CREDENTIALS_ERROR');
        else assert.equal(signed.body.status, 'OK', `method ${i} must still sign in`);
      }
      await assertInvariants();
    }
  });

  it('stays consistent under mixed concurrent primary/link/unlink operations', async () => {
    const pool = [await user(), await user(), await user(), await user(), await user()];
    const ops = [];
    for (let i = 0; i < 40; i++) {
      const a = pool[i % pool.length]!.id; const b = pool[(i * 3 + 1) % pool.length]!.id;
      ops.push([() => primary(a), () => link(a, b), () => unlink(a), () => link(b, a)][i % 4]!());
    }
    const results = await Promise.all(ops);
    assert.ok(results.every((x) => x.status === 200), JSON.stringify(results.filter((x) => x.status !== 200).map((x) => x.text)));
    await assertInvariants();
    for (const m of pool) {
      const signed = await signIn(m);
      const exists = (await h.db.query('SELECT 1 FROM ea_login_methods WHERE method_id = $1', [m.id])).rowCount === 1;
      assert.equal(signed.body.status === 'OK', exists, 'a method signs in exactly when it still exists');
    }
  });
});

describe('transaction retry', () => {
  it('re-runs a transaction aborted by a deadlock and discards the failed attempt', async () => {
    await h.db.query('CREATE TABLE IF NOT EXISTS retry_probe (n int)');
    let attempts = 0;
    const result = await transaction(h.db, async (tx) => {
      attempts++;
      await tx.query('INSERT INTO retry_probe VALUES ($1)', [attempts]);
      if (attempts === 1) throw Object.assign(new Error('simulated deadlock'), { code: '40P01' });
      return 'done';
    });
    assert.equal(result, 'done'); assert.equal(attempts, 2);
    assert.deepEqual((await h.db.query('SELECT n FROM retry_probe')).rows, [{ n: 2 }], 'the aborted attempt left nothing behind');
    let other = 0;
    await assert.rejects(transaction(h.db, async () => { other++; throw Object.assign(new Error('x'), { code: '23505' }); }));
    assert.equal(other, 1, 'non-retryable errors are not retried');
  });
});
