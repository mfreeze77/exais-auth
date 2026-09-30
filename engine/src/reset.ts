// Password reset: one-time challenge lifecycle. Consumption, password replacement and session
// revocation commit together; a token can never be consumed twice.
import type { Config } from './config.ts';
import { randomToken, sha256 } from './crypto.ts';
import { type Db, transaction } from './db.ts';
import { badRequest } from './errors.ts';
import { normaliseEmail, requireTenant, type Scope } from './identity.ts';
import { hashPassword, passwordAcceptable } from './passwords.ts';

const TOKEN = /^[A-Za-z0-9_-]{64}$/;

export async function createResetToken(db: Db, config: Config, scope: Scope, input: { userId?: unknown; email?: unknown }) {
  if (typeof input.userId !== 'string' || !/^[0-9a-f-]{36}$/.test(input.userId)) return { status: 'UNKNOWN_USER_ID_ERROR' as const };
  const email = normaliseEmail(input.email);
  await requireTenant(db, scope);
  const method = await db.query(
    `SELECT 1 FROM ea_tenant_methods WHERE app_id = $1 AND tenant_id = $2 AND method_id = $3 AND recipe_id = 'emailpassword' AND email = $4`,
    [scope.appId, scope.tenantId, input.userId, email]);
  if (method.rowCount !== 1) return { status: 'UNKNOWN_USER_ID_ERROR' as const };
  const token = randomToken(48);
  await db.query(`INSERT INTO ea_reset_tokens (app_id, token_hash, tenant_id, method_id, email, expires_at)
                  VALUES ($1, $2, $3, $4, $5, $6)`,
    [scope.appId, sha256(token), scope.tenantId, input.userId, email, Date.now() + config.resetTokenSeconds * 1000]);
  return { status: 'OK' as const, token };
}

async function consumeLocked(tx: import('./db.ts').Tx, scope: Scope, token: unknown) {
  if (typeof token !== 'string' || !TOKEN.test(token)) return null;
  const row = await tx.query(
    'SELECT method_id, email, expires_at FROM ea_reset_tokens WHERE app_id = $1 AND token_hash = $2 AND tenant_id = $3 FOR UPDATE',
    [scope.appId, sha256(token), scope.tenantId]);
  if (row.rowCount !== 1) return null;
  const { method_id: methodId, email, expires_at: expiresAt } = row.rows[0];
  if (Number(expiresAt) <= Date.now()) {
    await tx.query('DELETE FROM ea_reset_tokens WHERE app_id = $1 AND token_hash = $2', [scope.appId, sha256(token)]);
    return null;
  }
  // Every outstanding token for the method is spent by one successful consumption.
  await tx.query('DELETE FROM ea_reset_tokens WHERE app_id = $1 AND method_id = $2', [scope.appId, methodId]);
  // The identity must still own that email in this tenant.
  const member = await tx.query(
    `SELECT m.primary_user_id FROM ea_tenant_methods t JOIN ea_login_methods m ON m.app_id = t.app_id AND m.method_id = t.method_id
      WHERE t.app_id = $1 AND t.tenant_id = $2 AND t.method_id = $3 AND t.email = $4`, [scope.appId, scope.tenantId, methodId, email]);
  if (member.rowCount !== 1) return null;
  return { methodId: methodId as string, email: email as string, userId: member.rows[0].primary_user_id as string };
}

/** Reference two-step flow: consume only. The application then updates the password separately. */
export async function consumeResetToken(db: Db, scope: Scope, input: { token?: unknown }) {
  await requireTenant(db, scope);
  const consumed = await transaction(db, (tx) => consumeLocked(tx, scope, input.token));
  if (!consumed) return { status: 'RESET_PASSWORD_INVALID_TOKEN_ERROR' as const };
  return { status: 'OK' as const, userId: consumed.methodId, email: consumed.email };
}

/** Atomic flow: consume, replace the password and revoke every session of the user in one commit. */
export async function resetPassword(db: Db, config: Config, scope: Scope, input: { method?: unknown; token?: unknown; newPassword?: unknown }) {
  if (input.method !== undefined && input.method !== 'token') throw badRequest("Field name 'method' is invalid in JSON input");
  if (!passwordAcceptable(input.newPassword)) throw badRequest("Field name 'newPassword' is invalid in JSON input");
  await requireTenant(db, scope);
  const replacement = await hashPassword(input.newPassword, config.argon2); // outside the row lock
  const now = Date.now();
  const result = await transaction(db, async (tx) => {
    const consumed = await consumeLocked(tx, scope, input.token);
    if (!consumed) return null;
    await tx.query('UPDATE ea_password_credentials SET password_hash = $3, updated_at = $4 WHERE app_id = $1 AND method_id = $2',
      [scope.appId, consumed.methodId, replacement, now]);
    await tx.query(`UPDATE ea_sessions SET revoked_at = $4, revoked_reason = 'password-reset'
                     WHERE app_id = $1 AND (user_id = ANY($2::text[]) OR recipe_user_id = $3) AND revoked_at IS NULL`,
      [scope.appId, [consumed.userId, consumed.methodId], consumed.methodId, now]);
    return consumed;
  });
  if (!result) return { status: 'RESET_PASSWORD_INVALID_TOKEN_ERROR' as const };
  return { status: 'OK' as const, userId: result.methodId, email: result.email };
}

/** Direct password update for a login method (application-authorised change). */
export async function updatePassword(db: Db, config: Config, appId: string, input: { recipeUserId?: unknown; password?: unknown }) {
  if (typeof input.recipeUserId !== 'string' || !/^[0-9a-f-]{36}$/.test(input.recipeUserId)) return { status: 'UNKNOWN_USER_ID_ERROR' as const };
  if (!passwordAcceptable(input.password)) throw badRequest("Field name 'password' is invalid in JSON input");
  const replacement = await hashPassword(input.password, config.argon2);
  const updated = await db.query('UPDATE ea_password_credentials SET password_hash = $3, updated_at = $4 WHERE app_id = $1 AND method_id = $2',
    [appId, input.recipeUserId, replacement, Date.now()]);
  return updated.rowCount === 1 ? { status: 'OK' as const } : { status: 'UNKNOWN_USER_ID_ERROR' as const };
}
