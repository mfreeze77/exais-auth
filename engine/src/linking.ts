// Account linking: primary users own one or more login methods. Every operation locks the
// involved user rows in id order and the involved emails (advisory, sorted) before reading
// state, so concurrent link/unlink/primary operations serialise instead of racing.
//
// Invariants (tested under concurrency):
//  - a login method belongs to exactly one user (schema) and is linked to at most one primary;
//  - no two primary users share an email in any tenant either of them belongs to;
//  - a user row never survives with zero login methods;
//  - unlinking never removes the ability to sign in with that method, except the documented
//    case of the primary user's own original method, which is deleted when other methods remain
//    (reference semantics: the primary user id must stay stable).
import { type Db, type Tx, transaction } from './db.ts';
import { badRequest } from './errors.ts';
import { userJson } from './identity.ts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function id(value: unknown, field: string): string {
  if (typeof value !== 'string' || !UUID.test(value)) throw badRequest(`Field name '${field}' is invalid`);
  return value;
}

interface Method { methodId: string; ownerId: string; email: string | null; ownerIsPrimary: boolean }

async function lockEmails(tx: Tx, appId: string, emails: Array<string | null>) {
  for (const email of [...new Set(emails.filter((e): e is string => !!e))].sort()) {
    await tx.query('SELECT pg_advisory_xact_lock(727274003, hashtext($1))', [`${appId}|${email}`]);
  }
}

async function lockUsers(tx: Tx, appId: string, userIds: string[]) {
  for (const userId of [...new Set(userIds)].sort()) {
    await tx.query('SELECT 1 FROM ea_users WHERE app_id = $1 AND user_id = $2 FOR UPDATE', [appId, userId]);
  }
}

async function method(tx: Tx, appId: string, methodId: string): Promise<Method | null> {
  const row = await tx.query(
    `SELECT m.method_id, m.primary_user_id, m.email, u.is_primary FROM ea_login_methods m
       JOIN ea_users u ON u.app_id = m.app_id AND u.user_id = m.primary_user_id
      WHERE m.app_id = $1 AND m.method_id = $2`, [appId, methodId]);
  if (row.rowCount !== 1) return null;
  const r = row.rows[0];
  return { methodId: r.method_id, ownerId: r.primary_user_id, email: r.email, ownerIsPrimary: r.is_primary };
}

/**
 * Locks emails and users for an operation, then re-reads the method: the owner can change
 * between the first unlocked read and acquiring the locks.
 */
async function lockFor(tx: Tx, appId: string, methodId: string, extraUsers: string[] = []): Promise<Method | null> {
  const first = await method(tx, appId, methodId);
  if (!first) return null;
  const emails = await tx.query(
    `SELECT email FROM ea_login_methods WHERE app_id = $1 AND primary_user_id = ANY($2::uuid[])`, [appId, [first.ownerId, ...extraUsers]]);
  await lockEmails(tx, appId, [first.email, ...emails.rows.map((r) => r.email)]);
  await lockUsers(tx, appId, [first.ownerId, ...extraUsers]);
  const locked = await method(tx, appId, methodId);
  if (!locked || locked.ownerId === first.ownerId) return locked;
  await lockUsers(tx, appId, [locked.ownerId]); // owner moved while we waited; lock the new owner too
  return method(tx, appId, methodId);
}

async function tenantsOfUser(tx: Tx, appId: string, userId: string): Promise<string[]> {
  const rows = await tx.query(`SELECT DISTINCT t.tenant_id FROM ea_tenant_methods t JOIN ea_login_methods m
      ON m.app_id = t.app_id AND m.method_id = t.method_id WHERE t.app_id = $1 AND m.primary_user_id = $2`, [appId, userId]);
  return rows.rows.map((r) => r.tenant_id);
}

/** Another primary user (not in `except`) holding any of `emails` in any of `tenants`. */
async function conflictingPrimary(tx: Tx, appId: string, emails: string[], tenants: string[], except: string[]) {
  if (emails.length === 0 || tenants.length === 0) return null;
  const row = await tx.query(
    `SELECT m.primary_user_id FROM ea_login_methods m
       JOIN ea_users u ON u.app_id = m.app_id AND u.user_id = m.primary_user_id AND u.is_primary
       JOIN ea_tenant_methods t ON t.app_id = m.app_id AND t.method_id = m.method_id
      WHERE m.app_id = $1 AND m.email = ANY($2::text[]) AND t.tenant_id = ANY($3::text[]) AND NOT (m.primary_user_id = ANY($4::uuid[]))
      LIMIT 1`, [appId, emails, tenants, except]);
  return row.rowCount === 1 ? row.rows[0].primary_user_id as string : null;
}

async function emailsOfUser(tx: Tx, appId: string, userId: string): Promise<string[]> {
  const rows = await tx.query('SELECT DISTINCT email FROM ea_login_methods WHERE app_id = $1 AND primary_user_id = $2 AND email IS NOT NULL', [appId, userId]);
  return rows.rows.map((r) => r.email);
}

const conflict = (primaryUserId: string) => ({ status: 'ACCOUNT_INFO_ALREADY_ASSOCIATED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR' as const,
  primaryUserId, description: 'This user\'s email is already associated with another primary user in one of its tenants' });

async function makePrimaryIn(tx: Tx, appId: string, recipeUserId: string) {
  const m = await lockFor(tx, appId, recipeUserId);
  if (!m) return { status: 'UNKNOWN_USER_ID_ERROR' as const };
  if (m.ownerIsPrimary) {
    if (m.ownerId !== recipeUserId) return { status: 'RECIPE_USER_ID_ALREADY_LINKED_WITH_PRIMARY_USER_ID_ERROR' as const, primaryUserId: m.ownerId,
      description: 'This user ID is already linked to another user ID' };
    return { status: 'OK' as const, wasAlreadyAPrimaryUser: true, userId: m.ownerId };
  }
  const other = await conflictingPrimary(tx, appId, await emailsOfUser(tx, appId, m.ownerId), await tenantsOfUser(tx, appId, m.ownerId), [m.ownerId]);
  if (other) return conflict(other);
  await tx.query('UPDATE ea_users SET is_primary = true WHERE app_id = $1 AND user_id = $2', [appId, m.ownerId]);
  return { status: 'OK' as const, wasAlreadyAPrimaryUser: false, userId: m.ownerId };
}

export async function createPrimaryUser(db: Db, appId: string, input: { recipeUserId?: unknown }, dryRun = false) {
  const recipeUserId = id(input.recipeUserId, 'recipeUserId');
  const result = await transaction(db, (tx) => makePrimaryIn(tx, appId, recipeUserId), { rollback: dryRun });
  if (result.status !== 'OK') return result;
  if (dryRun) return { status: 'OK' as const, wasAlreadyAPrimaryUser: result.wasAlreadyAPrimaryUser };
  return { status: 'OK' as const, wasAlreadyAPrimaryUser: result.wasAlreadyAPrimaryUser, user: await userJson(db, appId, result.userId) };
}

async function linkIn(tx: Tx, appId: string, recipeUserId: string, primaryUserId: string) {
  const m = await lockFor(tx, appId, recipeUserId, [primaryUserId]);
  if (!m) return { status: 'UNKNOWN_USER_ID_ERROR' as const };
  const primary = await tx.query('SELECT is_primary FROM ea_users WHERE app_id = $1 AND user_id = $2', [appId, primaryUserId]);
  if (primary.rowCount !== 1 || !primary.rows[0].is_primary) {
    return { status: 'INPUT_USER_IS_NOT_A_PRIMARY_USER' as const, description: 'The input primary user ID is not a primary user' };
  }
  if (m.ownerId === primaryUserId) return { status: 'OK' as const, accountsAlreadyLinked: true };
  if (m.ownerIsPrimary) {
    return { status: 'RECIPE_USER_ID_ALREADY_LINKED_WITH_ANOTHER_PRIMARY_USER_ID_ERROR' as const, primaryUserId: m.ownerId,
      description: 'The input recipe user ID is already linked to another primary user ID' };
  }
  // After linking, the primary spans both users' tenants and holds both users' emails.
  const tenants = [...new Set([...(await tenantsOfUser(tx, appId, m.ownerId)), ...(await tenantsOfUser(tx, appId, primaryUserId))])];
  const emails = [...new Set([...(await emailsOfUser(tx, appId, m.ownerId)), ...(await emailsOfUser(tx, appId, primaryUserId))])];
  const other = await conflictingPrimary(tx, appId, emails, tenants, [primaryUserId, m.ownerId]);
  if (other) return conflict(other);
  await tx.query('UPDATE ea_login_methods SET primary_user_id = $3 WHERE app_id = $1 AND primary_user_id = $2', [appId, m.ownerId, primaryUserId]);
  await tx.query('DELETE FROM ea_users WHERE app_id = $1 AND user_id = $2', [appId, m.ownerId]);
  // Sessions issued to the absorbed user carry a subject that no longer exists; the caller
  // re-authenticates to receive a session for the primary user.
  await tx.query(`UPDATE ea_sessions SET revoked_at = $3, revoked_reason = 'linked'
      WHERE app_id = $1 AND user_id = $2 AND revoked_at IS NULL`, [appId, m.ownerId, Date.now()]);
  return { status: 'OK' as const, accountsAlreadyLinked: false };
}

export async function linkAccounts(db: Db, appId: string, input: { recipeUserId?: unknown; primaryUserId?: unknown }, dryRun = false) {
  const recipeUserId = id(input.recipeUserId, 'recipeUserId');
  const primaryUserId = id(input.primaryUserId, 'primaryUserId');
  const result = await transaction(db, (tx) => linkIn(tx, appId, recipeUserId, primaryUserId), { rollback: dryRun });
  if (result.status !== 'OK' || dryRun) return result;
  return { ...result, user: await userJson(db, appId, primaryUserId) };
}

export async function unlinkAccount(db: Db, appId: string, input: { recipeUserId?: unknown }) {
  const recipeUserId = id(input.recipeUserId, 'recipeUserId');
  const now = Date.now();
  return transaction(db, async (tx) => {
    const m = await lockFor(tx, appId, recipeUserId);
    if (!m) return { status: 'UNKNOWN_USER_ID_ERROR' as const };
    if (!m.ownerIsPrimary) return { status: 'OK' as const, wasLinked: false, wasRecipeUserDeleted: false };
    const count = Number((await tx.query('SELECT count(*) AS n FROM ea_login_methods WHERE app_id = $1 AND primary_user_id = $2',
      [appId, m.ownerId])).rows[0].n);
    const revoke = () => tx.query(`UPDATE ea_sessions SET revoked_at = $3, revoked_reason = 'unlinked'
        WHERE app_id = $1 AND recipe_user_id = $2 AND revoked_at IS NULL`, [appId, recipeUserId, now]);
    if (m.methodId === m.ownerId) {
      if (count === 1) {
        await tx.query('UPDATE ea_users SET is_primary = false WHERE app_id = $1 AND user_id = $2', [appId, m.ownerId]);
        return { status: 'OK' as const, wasLinked: true, wasRecipeUserDeleted: false };
      }
      // The primary id must stay stable for the remaining methods, so its original method is deleted.
      await revoke();
      await tx.query('DELETE FROM ea_login_methods WHERE app_id = $1 AND method_id = $2', [appId, m.methodId]);
      return { status: 'OK' as const, wasLinked: true, wasRecipeUserDeleted: true };
    }
    await revoke();
    await tx.query('INSERT INTO ea_users (app_id, user_id, is_primary, created_at) VALUES ($1, $2, false, $3)', [appId, m.methodId, now]);
    await tx.query('UPDATE ea_login_methods SET primary_user_id = $2 WHERE app_id = $1 AND method_id = $2', [appId, m.methodId]);
    if (count === 1) await tx.query('DELETE FROM ea_users WHERE app_id = $1 AND user_id = $2', [appId, m.ownerId]);
    return { status: 'OK' as const, wasLinked: true, wasRecipeUserDeleted: false };
  });
}
