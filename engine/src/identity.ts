// Apps, tenants, users, login methods and tenant membership. Email identity is tenant-scoped.
import { randomUUID } from 'node:crypto';
import type { Config } from './config.ts';
import { type Db, type Tx, transaction } from './db.ts';
import { badRequest, HttpError } from './errors.ts';
import { burnVerification, hashPassword, importableHash, needsRehash, passwordAcceptable, verifyPassword } from './passwords.ts';

export interface Scope { appId: string; tenantId: string }

const ID = /^[a-z0-9-]{1,64}$/;

export function normaliseEmail(value: unknown): string {
  if (typeof value !== 'string') throw badRequest("Field name 'email' is invalid in JSON input");
  const email = value.trim().toLowerCase();
  // Deliberately simple shape check; delivery-level validation belongs to the application backend.
  if (email.length > 256 || !/^[^\s@]+@[^\s@]+$/.test(email)) throw badRequest("Field name 'email' is invalid in JSON input");
  return email;
}

export async function requireTenant(db: Db | Tx, scope: Scope): Promise<{ emailpasswordEnabled: boolean }> {
  const row = await db.query('SELECT emailpassword_enabled FROM ea_tenants WHERE app_id = $1 AND tenant_id = $2',
    [scope.appId, scope.tenantId]);
  if (row.rowCount !== 1) throw badRequest('AppId or tenantId not found => Tenant with the following appId and tenantId combination not found');
  return { emailpasswordEnabled: row.rows[0].emailpassword_enabled };
}

async function requireEmailPassword(db: Db | Tx, scope: Scope): Promise<void> {
  const tenant = await requireTenant(db, scope);
  if (!tenant.emailpasswordEnabled) throw badRequest('Emailpassword login not enabled for tenant');
}

// ---------- apps and tenants (native multi-tenancy) ----------

export async function upsertApp(db: Db, appId: unknown): Promise<{ createdNew: boolean }> {
  if (typeof appId !== 'string' || !ID.test(appId)) throw badRequest('Invalid appId');
  return transaction(db, async (tx) => {
    const now = Date.now();
    const app = await tx.query('INSERT INTO ea_apps (app_id, created_at) VALUES ($1, $2) ON CONFLICT DO NOTHING', [appId, now]);
    await tx.query("INSERT INTO ea_tenants (app_id, tenant_id, created_at) VALUES ($1, 'public', $2) ON CONFLICT DO NOTHING", [appId, now]);
    return { createdNew: app.rowCount === 1 };
  });
}

export async function upsertTenant(db: Db, appId: string, input: { tenantId?: unknown; emailPasswordEnabled?: unknown }):
    Promise<{ createdNew: boolean }> {
  if (typeof input.tenantId !== 'string' || !ID.test(input.tenantId)) throw badRequest('Invalid tenantId');
  if (input.emailPasswordEnabled !== undefined && typeof input.emailPasswordEnabled !== 'boolean') {
    throw badRequest('Invalid emailPasswordEnabled');
  }
  const app = await db.query('SELECT 1 FROM ea_apps WHERE app_id = $1', [appId]);
  if (app.rowCount !== 1) throw badRequest('AppId or tenantId not found => App not found');
  const result = await db.query(
    `INSERT INTO ea_tenants (app_id, tenant_id, emailpassword_enabled, created_at) VALUES ($1, $2, COALESCE($3, true), $4)
     ON CONFLICT (app_id, tenant_id) DO UPDATE SET emailpassword_enabled = COALESCE($3, ea_tenants.emailpassword_enabled)
     RETURNING (xmax = 0) AS inserted`,
    [appId, input.tenantId, input.emailPasswordEnabled ?? null, Date.now()]);
  return { createdNew: result.rows[0].inserted };
}

export async function listTenants(db: Db, appId: string) {
  const rows = await db.query('SELECT tenant_id, emailpassword_enabled FROM ea_tenants WHERE app_id = $1 ORDER BY tenant_id', [appId]);
  return rows.rows.map((r) => ({ tenantId: r.tenant_id, emailPassword: { enabled: r.emailpassword_enabled } }));
}

// ---------- users ----------

export async function userJson(db: Db | Tx, appId: string, userId: string) {
  const user = await db.query('SELECT user_id, is_primary, created_at FROM ea_users WHERE app_id = $1 AND user_id = $2', [appId, userId]);
  if (user.rowCount !== 1) return null;
  const methods = await db.query(
    `SELECT m.method_id, m.recipe_id, m.email, m.created_at,
            COALESCE(array_agg(t.tenant_id ORDER BY t.tenant_id) FILTER (WHERE t.tenant_id IS NOT NULL), '{}') AS tenants,
            EXISTS (SELECT 1 FROM ea_email_verifications v WHERE v.app_id = m.app_id AND v.user_id = m.method_id::text AND v.email = m.email) AS verified
       FROM ea_login_methods m LEFT JOIN ea_tenant_methods t ON t.app_id = m.app_id AND t.method_id = m.method_id
      WHERE m.app_id = $1 AND m.primary_user_id = $2 GROUP BY m.app_id, m.method_id ORDER BY m.created_at, m.method_id`, [appId, userId]);
  const loginMethods = methods.rows.map((m) => ({
    recipeId: m.recipe_id, recipeUserId: m.method_id, tenantIds: m.tenants as string[], email: m.email,
    timeJoined: Number(m.created_at), verified: m.verified as boolean,
  }));
  return {
    id: user.rows[0].user_id as string,
    isPrimaryUser: user.rows[0].is_primary as boolean,
    tenantIds: [...new Set(loginMethods.flatMap((m) => m.tenantIds))].sort(),
    timeJoined: Number(user.rows[0].created_at),
    emails: [...new Set(loginMethods.map((m) => m.email).filter(Boolean))],
    phoneNumbers: [] as string[],
    thirdParty: [] as unknown[],
    loginMethods,
  };
}

class EmailTaken extends Error {}

async function createPasswordUser(db: Db, scope: Scope, email: string, passwordHash: string) {
  return transaction(db, async (tx) => {
    await requireEmailPassword(tx, scope);
    const userId = randomUUID(); const now = Date.now();
    await tx.query('INSERT INTO ea_users (app_id, user_id, created_at) VALUES ($1, $2, $3)', [scope.appId, userId, now]);
    await tx.query(`INSERT INTO ea_login_methods (app_id, method_id, primary_user_id, recipe_id, email, created_at)
                    VALUES ($1, $2, $2, 'emailpassword', $3, $4)`, [scope.appId, userId, email, now]);
    await tx.query('INSERT INTO ea_password_credentials (app_id, method_id, password_hash, updated_at) VALUES ($1, $2, $3, $4)',
      [scope.appId, userId, passwordHash, now]);
    const inserted = await tx.query(
      `INSERT INTO ea_tenant_methods (app_id, tenant_id, method_id, recipe_id, email) VALUES ($1, $2, $3, 'emailpassword', $4)
       ON CONFLICT DO NOTHING`, [scope.appId, scope.tenantId, userId, email]);
    // Throwing rolls back the user, method and credential rows inserted above.
    if (inserted.rowCount !== 1) throw new EmailTaken();
    return { status: 'OK' as const, userId };
  }).catch((error) => {
    if (error instanceof EmailTaken) return { status: 'EMAIL_ALREADY_EXISTS_ERROR' as const };
    throw error;
  });
}

export async function signUp(db: Db, config: Config, scope: Scope, input: { email?: unknown; password?: unknown }) {
  const email = normaliseEmail(input.email);
  if (!passwordAcceptable(input.password)) throw badRequest("Field name 'password' is invalid in JSON input");
  await requireEmailPassword(db, scope);
  const exists = await findMethod(db, scope, email);
  if (exists) return { status: 'EMAIL_ALREADY_EXISTS_ERROR' as const };
  const created = await createPasswordUser(db, scope, email, await hashPassword(input.password, config.argon2));
  if (created.status !== 'OK') return created;
  return { status: 'OK' as const, user: await userJson(db, scope.appId, created.userId), recipeUserId: created.userId };
}

async function findMethod(db: Db | Tx, scope: Scope, email: string) {
  const row = await db.query(
    `SELECT m.method_id, m.primary_user_id, c.password_hash FROM ea_tenant_methods t
       JOIN ea_login_methods m ON m.app_id = t.app_id AND m.method_id = t.method_id
       JOIN ea_password_credentials c ON c.app_id = m.app_id AND c.method_id = m.method_id
      WHERE t.app_id = $1 AND t.tenant_id = $2 AND t.recipe_id = 'emailpassword' AND t.email = $3`,
    [scope.appId, scope.tenantId, email]);
  return row.rowCount === 1 ? { methodId: row.rows[0].method_id as string, userId: row.rows[0].primary_user_id as string,
    hash: row.rows[0].password_hash as string } : null;
}

/**
 * Verifies a password and, when the stored hash is outdated or imported, replaces it inside a
 * locked compare-and-swap. The rehash never decides acceptance; verification does.
 */
export async function checkPassword(db: Db, config: Config, scope: Scope, email: string, password: string) {
  const method = await findMethod(db, scope, email);
  if (!method) {
    await burnVerification(password, config.argon2);
    return null;
  }
  if (!(await verifyPassword(password, method.hash))) return null;
  if (needsRehash(method.hash, config.argon2)) {
    const replacement = await hashPassword(password, config.argon2);
    await db.query(`UPDATE ea_password_credentials SET password_hash = $3, updated_at = $4
                     WHERE app_id = $1 AND method_id = $2 AND password_hash = $5`,
      [scope.appId, method.methodId, replacement, Date.now(), method.hash]);
  }
  return method;
}

export async function signIn(db: Db, config: Config, scope: Scope, input: { email?: unknown; password?: unknown }) {
  const email = normaliseEmail(input.email);
  if (!passwordAcceptable(input.password)) throw badRequest("Field name 'password' is invalid in JSON input");
  await requireEmailPassword(db, scope);
  const method = await checkPassword(db, config, scope, email, input.password);
  if (!method) return { status: 'WRONG_CREDENTIALS_ERROR' as const };
  return { status: 'OK' as const, user: await userJson(db, scope.appId, method.userId), recipeUserId: method.methodId };
}

export async function importPasswordHash(db: Db, scope: Scope, input: { email?: unknown; passwordHash?: unknown }) {
  const email = normaliseEmail(input.email);
  if (typeof input.passwordHash !== 'string' || !importableHash(input.passwordHash)) {
    throw badRequest('Password hash is malformed, unsupported or exceeds import cost bounds');
  }
  await requireEmailPassword(db, scope);
  const existing = await findMethod(db, scope, email);
  if (existing) {
    await db.query('UPDATE ea_password_credentials SET password_hash = $3, updated_at = $4 WHERE app_id = $1 AND method_id = $2',
      [scope.appId, existing.methodId, input.passwordHash, Date.now()]);
    return { status: 'OK' as const, didUserAlreadyExist: true, user: await userJson(db, scope.appId, existing.userId) };
  }
  const created = await createPasswordUser(db, scope, email, input.passwordHash);
  if (created.status !== 'OK') throw new HttpError(409, 'Concurrent import for the same email');
  return { status: 'OK' as const, didUserAlreadyExist: false, user: await userJson(db, scope.appId, created.userId) };
}

/** Explicit sharing: associate an existing login method with another tenant of the same app. */
export async function associateWithTenant(db: Db, scope: Scope, recipeUserId: unknown) {
  if (typeof recipeUserId !== 'string' || !/^[0-9a-f-]{36}$/.test(recipeUserId)) throw badRequest('Invalid recipeUserId');
  return transaction(db, async (tx) => {
    await requireTenant(tx, scope);
    const method = await tx.query('SELECT recipe_id, email FROM ea_login_methods WHERE app_id = $1 AND method_id = $2 FOR UPDATE',
      [scope.appId, recipeUserId]);
    if (method.rowCount !== 1) return { status: 'UNKNOWN_USER_ID_ERROR' as const };
    // No conflict target: covers both the membership key and the tenant-scoped email index
    // without aborting the transaction.
    const inserted = await tx.query(
      `INSERT INTO ea_tenant_methods (app_id, tenant_id, method_id, recipe_id, email) VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT DO NOTHING`,
      [scope.appId, scope.tenantId, recipeUserId, method.rows[0].recipe_id, method.rows[0].email]);
    if (inserted.rowCount === 1) return { status: 'OK' as const, wasAlreadyAssociated: false };
    const member = await tx.query('SELECT 1 FROM ea_tenant_methods WHERE app_id = $1 AND tenant_id = $2 AND method_id = $3',
      [scope.appId, scope.tenantId, recipeUserId]);
    if (member.rowCount === 1) return { status: 'OK' as const, wasAlreadyAssociated: true };
    return { status: 'EMAIL_ALREADY_EXISTS_ERROR' as const };
  });
}

export async function disassociateFromTenant(db: Db, scope: Scope, recipeUserId: unknown) {
  if (typeof recipeUserId !== 'string' || !/^[0-9a-f-]{36}$/.test(recipeUserId)) throw badRequest('Invalid recipeUserId');
  const removed = await db.query('DELETE FROM ea_tenant_methods WHERE app_id = $1 AND tenant_id = $2 AND method_id = $3',
    [scope.appId, scope.tenantId, recipeUserId]);
  return { status: 'OK' as const, wasAssociated: removed.rowCount === 1 };
}
