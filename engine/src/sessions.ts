// Session and refresh-token state machine. This engine is the single refresh authority.
//
// Refresh tokens are opaque and stored only as SHA-256 digests. A successor is derived
// deterministically, HMAC(refreshSecret, handle | parentDigest), so a racing or retried
// refresh with the immediate parent inside the grace window returns the SAME successor
// instead of forking the family. Presenting any superseded token outside that window is
// treated as theft and revokes the session.
import { randomUUID } from 'node:crypto';
import type { Config } from './config.ts';
import { hmac, randomToken, safeEqual, sha256, signJwt, verifyJwt } from './crypto.ts';
import { type Db, transaction } from './db.ts';
import { badRequest } from './errors.ts';
import { requireTenant, type Scope } from './identity.ts';
import type { KeyStore } from './keys.ts';

const PROTECTED_CLAIMS = new Set(['sub', 'rsub', 'tId', 'sessionHandle', 'refreshTokenHash1', 'parentRefreshTokenHash1',
  'antiCsrfToken', 'iat', 'exp', 'iss']);

interface SessionRow {
  session_handle: string; tenant_id: string; user_id: string; recipe_user_id: string; jwt_data: Record<string, unknown>;
  session_data: Record<string, unknown>; anti_csrf_token: string | null; current_refresh_hash: string;
  previous_refresh_hash: string | null; previous_valid_until: string | null; expires_at: string; revoked_at: string | null;
}

function jsonObject(value: unknown, field: string): Record<string, unknown> {
  if (value === undefined) return {};
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw badRequest(`Field name '${field}' is invalid in JSON input`);
  return value as Record<string, unknown>;
}

function sessionInfo(row: SessionRow) {
  return { handle: row.session_handle, userId: row.user_id, recipeUserId: row.recipe_user_id,
    userDataInJWT: row.jwt_data, tenantId: row.tenant_id };
}

export class Sessions {
  private readonly db: Db;
  private readonly config: Config;
  private readonly keys: KeyStore;

  constructor(db: Db, config: Config, keys: KeyStore) {
    this.db = db;
    this.config = config;
    this.keys = keys;
  }

  private successor(handle: string, parentDigest: string): string {
    return hmac(this.config.refreshSecret, `${handle}|${parentDigest}`);
  }

  private async tokens(appId: string, row: SessionRow, refreshToken: string, now: number) {
    const key = await this.keys.signingKey(appId);
    const expiry = now + this.config.accessTokenSeconds * 1000;
    const claims: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(row.jwt_data)) if (!PROTECTED_CLAIMS.has(k)) claims[k] = v;
    Object.assign(claims, {
      iat: Math.floor(now / 1000), exp: Math.floor(expiry / 1000), iss: this.config.issuer, sub: row.user_id,
      rsub: row.recipe_user_id, tId: row.tenant_id, sessionHandle: row.session_handle,
      refreshTokenHash1: sha256(refreshToken), parentRefreshTokenHash1: null, antiCsrfToken: row.anti_csrf_token,
    });
    return {
      accessToken: { token: signJwt(key, claims), expiry, createdTime: now },
      refreshToken: { token: refreshToken, expiry: Number(row.expires_at), createdTime: now },
      ...(row.anti_csrf_token ? { antiCsrfToken: row.anti_csrf_token } : {}),
    };
  }

  async create(scope: Scope, input: { userId?: unknown; recipeUserId?: unknown; userDataInJWT?: unknown;
      userDataInDatabase?: unknown; enableAntiCsrf?: unknown }) {
    if (typeof input.userId !== 'string' || input.userId.length === 0 || input.userId.length > 256) throw badRequest("Field name 'userId' is invalid in JSON input");
    const recipeUserId = input.recipeUserId === undefined ? input.userId : input.recipeUserId;
    if (typeof recipeUserId !== 'string' || recipeUserId.length === 0 || recipeUserId.length > 256) throw badRequest("Field name 'recipeUserId' is invalid in JSON input");
    const jwtData = jsonObject(input.userDataInJWT, 'userDataInJWT');
    const sessionData = jsonObject(input.userDataInDatabase, 'userDataInDatabase');
    await requireTenant(this.db, scope);
    const now = Date.now();
    const handle = randomUUID();
    const refreshToken = randomToken(48);
    const row = await this.db.query<SessionRow>(
      `INSERT INTO ea_sessions (app_id, session_handle, tenant_id, user_id, recipe_user_id, jwt_data, session_data,
         anti_csrf_token, current_refresh_hash, created_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
      [scope.appId, handle, scope.tenantId, input.userId, recipeUserId, jwtData, sessionData,
        input.enableAntiCsrf === true ? randomToken(24) : null, sha256(refreshToken), now,
        now + this.config.refreshTokenSeconds * 1000]);
    return { status: 'OK' as const, session: sessionInfo(row.rows[0]!), ...(await this.tokens(scope.appId, row.rows[0]!, refreshToken, now)) };
  }

  async refresh(appId: string, input: { refreshToken?: unknown; antiCsrfToken?: unknown }) {
    if (typeof input.refreshToken !== 'string' || input.refreshToken.length === 0 || input.refreshToken.length > 512) {
      throw badRequest("Field name 'refreshToken' is invalid in JSON input");
    }
    const digest = sha256(input.refreshToken);
    const now = Date.now();
    const outcome = await transaction(this.db, async (tx) => {
      const found = await tx.query<SessionRow>(
        `SELECT * FROM ea_sessions WHERE app_id = $1 AND (current_refresh_hash = $2 OR previous_refresh_hash = $2) FOR UPDATE`,
        [appId, digest]);
      let row = found.rows[0];
      if (!row) {
        const used = await tx.query('SELECT session_handle FROM ea_refresh_history WHERE app_id = $1 AND token_hash = $2', [appId, digest]);
        if (used.rowCount !== 1) return { kind: 'unauthorised' as const };
        const theft = await tx.query<SessionRow>('SELECT * FROM ea_sessions WHERE app_id = $1 AND session_handle = $2 FOR UPDATE',
          [appId, used.rows[0].session_handle]);
        row = theft.rows[0]!;
        return this.revokeForTheft(tx, appId, row, now);
      }
      if (row.revoked_at !== null || Number(row.expires_at) <= now) return { kind: 'unauthorised' as const };
      if (row.anti_csrf_token && (typeof input.antiCsrfToken !== 'string' || !safeEqual(input.antiCsrfToken, row.anti_csrf_token))) {
        return { kind: 'unauthorised' as const };
      }
      if (row.current_refresh_hash === digest) {
        const child = this.successor(row.session_handle, digest);
        const expiresAt = now + this.config.refreshTokenSeconds * 1000;
        await tx.query('INSERT INTO ea_refresh_history (app_id, token_hash, session_handle) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
          [appId, digest, row.session_handle]);
        const updated = await tx.query<SessionRow>(
          `UPDATE ea_sessions SET previous_refresh_hash = $3, previous_valid_until = $4, current_refresh_hash = $5,
             generation = generation + 1, expires_at = $6 WHERE app_id = $1 AND session_handle = $2 RETURNING *`,
          [appId, row.session_handle, digest, now + this.config.refreshGraceSeconds * 1000, sha256(child), expiresAt]);
        return { kind: 'ok' as const, row: updated.rows[0]!, child };
      }
      // Immediate parent: a concurrent or retried refresh converges on the same successor inside the grace window.
      if (row.previous_valid_until !== null && now < Number(row.previous_valid_until)) {
        const child = this.successor(row.session_handle, digest);
        if (sha256(child) === row.current_refresh_hash) return { kind: 'ok' as const, row, child };
      }
      return this.revokeForTheft(tx, appId, row, now);
    });
    if (outcome.kind === 'unauthorised') return { status: 'UNAUTHORISED' as const, message: 'Refresh token is invalid, expired or revoked' };
    if (outcome.kind === 'theft') return { status: 'TOKEN_THEFT_DETECTED' as const, session: outcome.session };
    return { status: 'OK' as const, session: sessionInfo(outcome.row), ...(await this.tokens(appId, outcome.row, outcome.child, now)) };
  }

  private async revokeForTheft(tx: import('./db.ts').Tx, appId: string, row: SessionRow, now: number) {
    await tx.query(`UPDATE ea_sessions SET revoked_at = COALESCE(revoked_at, $3), revoked_reason = COALESCE(revoked_reason, 'refresh-token-reuse')
                     WHERE app_id = $1 AND session_handle = $2`, [appId, row.session_handle, now]);
    return { kind: 'theft' as const, session: { handle: row.session_handle, userId: row.user_id, recipeUserId: row.recipe_user_id } };
  }

  async verify(appId: string, input: { accessToken?: unknown; antiCsrfToken?: unknown; doAntiCsrfCheck?: unknown; checkDatabase?: unknown }) {
    if (typeof input.accessToken !== 'string' || input.accessToken.length > 16384) throw badRequest("Field name 'accessToken' is invalid in JSON input");
    const result = verifyJwt(input.accessToken, await this.keys.publicKeys(appId));
    const tryRefresh = { status: 'TRY_REFRESH_TOKEN' as const, message: 'Access token is invalid or expired' };
    if (!result.ok) return tryRefresh;
    const c = result.claims;
    if (c.iss !== this.config.issuer || typeof c.exp !== 'number' || c.exp * 1000 <= Date.now() ||
        typeof c.sessionHandle !== 'string' || typeof c.sub !== 'string' || typeof c.tId !== 'string') return tryRefresh;
    if (input.doAntiCsrfCheck === true && typeof c.antiCsrfToken === 'string' &&
        (typeof input.antiCsrfToken !== 'string' || !safeEqual(input.antiCsrfToken, c.antiCsrfToken))) return tryRefresh;
    if (input.checkDatabase === true) {
      const row = await this.db.query('SELECT revoked_at, expires_at FROM ea_sessions WHERE app_id = $1 AND session_handle = $2',
        [appId, c.sessionHandle]);
      if (row.rowCount !== 1 || row.rows[0].revoked_at !== null || Number(row.rows[0].expires_at) <= Date.now()) {
        return { status: 'UNAUTHORISED' as const, message: 'Session does not exist or was revoked' };
      }
    }
    const userDataInJWT: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(c)) if (!PROTECTED_CLAIMS.has(k)) userDataInJWT[k] = v;
    return { status: 'OK' as const, session: { handle: c.sessionHandle, userId: c.sub,
      recipeUserId: typeof c.rsub === 'string' ? c.rsub : c.sub, userDataInJWT, tenantId: c.tId } };
  }

  /** Revokes by handle list or by user; returns the handles that were active and are now revoked. */
  async revoke(appId: string, input: { sessionHandles?: unknown; userId?: unknown }, reason = 'revoked') {
    const now = Date.now();
    if (Array.isArray(input.sessionHandles)) {
      const handles = input.sessionHandles.filter((h): h is string => typeof h === 'string' && /^[0-9a-f-]{36}$/.test(h));
      if (handles.length !== input.sessionHandles.length) throw badRequest("Field name 'sessionHandles' is invalid in JSON input");
      const rows = await this.db.query(`UPDATE ea_sessions SET revoked_at = $3, revoked_reason = $4
          WHERE app_id = $1 AND session_handle = ANY($2::uuid[]) AND revoked_at IS NULL RETURNING session_handle`,
        [appId, handles, now, reason]);
      return { status: 'OK' as const, sessionHandlesRevoked: rows.rows.map((r) => r.session_handle) };
    }
    if (typeof input.userId === 'string' && input.userId.length > 0) {
      const rows = await this.db.query(`UPDATE ea_sessions SET revoked_at = $3, revoked_reason = $4
          WHERE app_id = $1 AND (user_id = $2 OR recipe_user_id = $2) AND revoked_at IS NULL RETURNING session_handle`,
        [appId, input.userId, now, reason]);
      return { status: 'OK' as const, sessionHandlesRevoked: rows.rows.map((r) => r.session_handle) };
    }
    throw badRequest("Either 'sessionHandles' or 'userId' is required");
  }

  async info(appId: string, handle: unknown) {
    if (typeof handle !== 'string' || !/^[0-9a-f-]{36}$/.test(handle)) throw badRequest("Field name 'sessionHandle' is invalid");
    const row = await this.db.query<SessionRow & { created_at: string }>(
      'SELECT * FROM ea_sessions WHERE app_id = $1 AND session_handle = $2 AND revoked_at IS NULL AND expires_at > $3',
      [appId, handle, Date.now()]);
    if (row.rowCount !== 1) return { status: 'UNAUTHORISED' as const, message: 'Session does not exist or was revoked' };
    const r = row.rows[0]!;
    return { status: 'OK' as const, sessionHandle: r.session_handle, userId: r.user_id, recipeUserId: r.recipe_user_id,
      tenantId: r.tenant_id, userDataInJWT: r.jwt_data, userDataInDatabase: r.session_data,
      expiry: Number(r.expires_at), timeCreated: Number(r.created_at) };
  }
}
