// Email verification: one-time, tenant-bound tokens; verified (user, email) pairs are app-scoped.
import type { Config } from './config.ts';
import { randomToken, sha256 } from './crypto.ts';
import { type Db, transaction } from './db.ts';
import { badRequest } from './errors.ts';
import { normaliseEmail, requireTenant, type Scope } from './identity.ts';

const TOKEN = /^[A-Za-z0-9_-]{64}$/;

function userId(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256) throw badRequest("Field name 'userId' is invalid in JSON input");
  return value;
}

export async function isVerified(db: Db, appId: string, input: { userId?: unknown; email?: unknown }) {
  const row = await db.query('SELECT 1 FROM ea_email_verifications WHERE app_id = $1 AND user_id = $2 AND email = $3',
    [appId, userId(input.userId), normaliseEmail(input.email)]);
  return { status: 'OK' as const, isVerified: row.rowCount === 1 };
}

export async function createVerificationToken(db: Db, config: Config, scope: Scope, input: { userId?: unknown; email?: unknown }) {
  const id = userId(input.userId); const email = normaliseEmail(input.email);
  await requireTenant(db, scope);
  if ((await isVerified(db, scope.appId, { userId: id, email })).isVerified) return { status: 'EMAIL_ALREADY_VERIFIED_ERROR' as const };
  const token = randomToken(48);
  await db.query(`INSERT INTO ea_email_verification_tokens (app_id, token_hash, tenant_id, user_id, email, expires_at)
                  VALUES ($1, $2, $3, $4, $5, $6)`,
    [scope.appId, sha256(token), scope.tenantId, id, email, Date.now() + config.emailVerificationTokenSeconds * 1000]);
  return { status: 'OK' as const, token };
}

export async function verifyEmail(db: Db, scope: Scope, input: { method?: unknown; token?: unknown }) {
  if (input.method !== undefined && input.method !== 'token') throw badRequest("Field name 'method' is invalid in JSON input");
  await requireTenant(db, scope);
  const invalid = { status: 'EMAIL_VERIFICATION_INVALID_TOKEN_ERROR' as const };
  if (typeof input.token !== 'string' || !TOKEN.test(input.token)) return invalid;
  const digest = sha256(input.token);
  const verified = await transaction(db, async (tx) => {
    const row = await tx.query(
      'SELECT user_id, email, expires_at FROM ea_email_verification_tokens WHERE app_id = $1 AND token_hash = $2 AND tenant_id = $3 FOR UPDATE',
      [scope.appId, digest, scope.tenantId]);
    if (row.rowCount !== 1) return null;
    const { user_id: id, email, expires_at: expiresAt } = row.rows[0];
    if (Number(expiresAt) <= Date.now()) {
      await tx.query('DELETE FROM ea_email_verification_tokens WHERE app_id = $1 AND token_hash = $2', [scope.appId, digest]);
      return null;
    }
    await tx.query('DELETE FROM ea_email_verification_tokens WHERE app_id = $1 AND user_id = $2 AND email = $3', [scope.appId, id, email]);
    await tx.query(`INSERT INTO ea_email_verifications (app_id, user_id, email, verified_at) VALUES ($1, $2, $3, $4)
                    ON CONFLICT DO NOTHING`, [scope.appId, id, email, Date.now()]);
    return { userId: id as string, email: email as string };
  });
  return verified ? { status: 'OK' as const, ...verified } : invalid;
}

export async function removeVerificationTokens(db: Db, scope: Scope, input: { userId?: unknown; email?: unknown }) {
  await requireTenant(db, scope);
  await db.query('DELETE FROM ea_email_verification_tokens WHERE app_id = $1 AND tenant_id = $2 AND user_id = $3 AND email = $4',
    [scope.appId, scope.tenantId, userId(input.userId), normaliseEmail(input.email)]);
  return { status: 'OK' as const };
}

export async function unverifyEmail(db: Db, appId: string, input: { userId?: unknown; email?: unknown }) {
  await db.query('DELETE FROM ea_email_verifications WHERE app_id = $1 AND user_id = $2 AND email = $3',
    [appId, userId(input.userId), normaliseEmail(input.email)]);
  return { status: 'OK' as const };
}
