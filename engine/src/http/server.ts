// CDI-style HTTP surface: /appid-<appId>/<tenantId>/<route>. Paths and response shapes follow the
// published reference contracts (contracts/api-contracts.json); the implementation is independent.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { Config } from '../config.ts';
import { safeEqual } from '../crypto.ts';
import type { Db } from '../db.ts';
import { badRequest, HttpError } from '../errors.ts';
import * as identity from '../identity.ts';
import * as linking from '../linking.ts';
import type { KeyStore } from '../keys.ts';
import * as reset from '../reset.ts';
import type { Sessions } from '../sessions.ts';

export const CDI_VERSIONS = ['5.4'];
const MAX_BODY = 64 * 1024;
const ROUTE_ROOTS = new Set(['recipe', 'hello', 'apiversion', '.well-known', '']);

interface Context { appId: string; tenantId: string; body: Record<string, unknown>; query: URLSearchParams }
interface Route { tenant: boolean; auth: boolean; publicAppOnly?: boolean; handle: (ctx: Context) => Promise<unknown> }

export interface Engine { db: Db; config: Config; keys: KeyStore; sessions: Sessions }

function routes(engine: Engine): Map<string, Route> {
  const { db, config, keys, sessions } = engine;
  const scope = (c: Context) => ({ appId: c.appId, tenantId: c.tenantId });
  const table: Array<[string, Route]> = [
    ['GET /hello', { tenant: true, auth: false, handle: async () => 'Hello' }],
    ['GET /apiversion', { tenant: false, auth: true, handle: async () => ({ versions: CDI_VERSIONS }) }],
    ['GET /.well-known/jwks.json', { tenant: false, auth: false, handle: async (c) => ({ keys: await keys.publicKeys(c.appId) }) }],
    ['GET /recipe/jwt/jwks', { tenant: false, auth: true, handle: async (c) => ({ status: 'OK', keys: await keys.publicKeys(c.appId) }) }],
    // Multi-tenancy: native to the engine.
    ['PUT /recipe/multitenancy/app/v2', { tenant: false, auth: true, publicAppOnly: true,
      handle: async (c) => ({ status: 'OK', ...(await identity.upsertApp(db, c.body.appId)) }) }],
    ['PUT /recipe/multitenancy/tenant/v2', { tenant: false, auth: true,
      handle: async (c) => ({ status: 'OK', ...(await identity.upsertTenant(db, c.appId, c.body)) }) }],
    ['GET /recipe/multitenancy/tenant/list/v2', { tenant: false, auth: true,
      handle: async (c) => ({ status: 'OK', tenants: await identity.listTenants(db, c.appId) }) }],
    ['POST /recipe/multitenancy/tenant/user', { tenant: true, auth: true,
      handle: async (c) => identity.associateWithTenant(db, scope(c), c.body.recipeUserId) }],
    ['POST /recipe/multitenancy/tenant/user/remove', { tenant: true, auth: true,
      handle: async (c) => identity.disassociateFromTenant(db, scope(c), c.body.recipeUserId) }],
    // Account linking.
    ['GET /recipe/accountlinking/user/primary/check', { tenant: false, auth: true,
      handle: async (c) => linking.createPrimaryUser(db, c.appId, { recipeUserId: c.query.get('recipeUserId') }, true) }],
    ['POST /recipe/accountlinking/user/primary', { tenant: false, auth: true, handle: async (c) => linking.createPrimaryUser(db, c.appId, c.body) }],
    ['GET /recipe/accountlinking/user/link/check', { tenant: false, auth: true, handle: async (c) =>
      linking.linkAccounts(db, c.appId, { recipeUserId: c.query.get('recipeUserId'), primaryUserId: c.query.get('primaryUserId') }, true) }],
    ['POST /recipe/accountlinking/user/link', { tenant: false, auth: true, handle: async (c) => linking.linkAccounts(db, c.appId, c.body) }],
    ['POST /recipe/accountlinking/user/unlink', { tenant: false, auth: true, handle: async (c) => linking.unlinkAccount(db, c.appId, c.body) }],
    // Email/password.
    ['POST /recipe/signup', { tenant: true, auth: true, handle: async (c) => identity.signUp(db, config, scope(c), c.body) }],
    ['POST /recipe/signin', { tenant: true, auth: true, handle: async (c) => identity.signIn(db, config, scope(c), c.body) }],
    ['POST /recipe/user/passwordhash/import', { tenant: true, auth: true, handle: async (c) => identity.importPasswordHash(db, scope(c), c.body) }],
    ['GET /recipe/user', { tenant: false, auth: true, handle: async (c) => {
      const user = /^[0-9a-f-]{36}$/.test(c.query.get('userId') ?? '') ? await identity.userJson(db, c.appId, c.query.get('userId')!) : null;
      return user ? { status: 'OK', user } : { status: 'UNKNOWN_USER_ID_ERROR' };
    } }],
    ['PUT /recipe/user', { tenant: false, auth: true, handle: async (c) => reset.updatePassword(db, config, c.appId, c.body) }],
    ['POST /recipe/user/password/reset/token', { tenant: true, auth: true, handle: async (c) => reset.createResetToken(db, config, scope(c), c.body) }],
    ['POST /recipe/user/password/reset/token/consume', { tenant: true, auth: true, handle: async (c) => reset.consumeResetToken(db, scope(c), c.body) }],
    ['POST /recipe/user/password/reset', { tenant: true, auth: true, handle: async (c) => reset.resetPassword(db, config, scope(c), c.body) }],
    // Sessions.
    ['POST /recipe/session', { tenant: true, auth: true, handle: async (c) => sessions.create(scope(c), c.body) }],
    ['POST /recipe/session/refresh', { tenant: false, auth: true, handle: async (c) => sessions.refresh(c.appId, c.body) }],
    ['POST /recipe/session/verify', { tenant: false, auth: true, handle: async (c) => sessions.verify(c.appId, c.body) }],
    ['POST /recipe/session/remove', { tenant: true, auth: true, handle: async (c) => sessions.revoke(c.appId, c.body) }],
    ['GET /recipe/session', { tenant: false, auth: true, handle: async (c) => sessions.info(c.appId, c.query.get('sessionHandle')) }],
  ];
  return new Map(table);
}

/** Splits /appid-<app>/<tenant>/<route> into its parts; tenant and app default to 'public'. */
export function parsePath(pathname: string): { appId: string; tenantId: string; route: string; explicitTenant: boolean } | null {
  const parts = pathname.split('/').slice(1);
  let appId = 'public';
  if (parts[0]?.startsWith('appid-')) {
    appId = parts.shift()!.slice('appid-'.length);
    if (!/^[a-z0-9-]{1,64}$/.test(appId)) return null;
  }
  let tenantId = 'public'; let explicitTenant = false;
  if (parts.length > 1 && !ROUTE_ROOTS.has(parts[0]!)) {
    tenantId = parts.shift()!;
    explicitTenant = true;
    if (!/^[a-z0-9-]{1,64}$/.test(tenantId)) return null;
  }
  return { appId, tenantId, route: '/' + parts.join('/'), explicitTenant };
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = []; let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new HttpError(413, 'Request body too large');
    chunks.push(chunk as Buffer);
  }
  if (size === 0) return {};
  let parsed: unknown;
  try {
    // Always UTF-8, regardless of any declared charset: passwords must never depend on transport defaults.
    parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
  } catch {
    throw badRequest('Invalid Json Input');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw badRequest('Invalid Json Input');
  return parsed as Record<string, unknown>;
}

function send(res: ServerResponse, status: number, body: unknown) {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, { 'content-type': typeof body === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
    'cache-control': 'no-store', 'content-length': Buffer.byteLength(text) });
  res.end(text);
}

export function createEngineServer(engine: Engine): Server {
  const table = routes(engine);
  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://engine.invalid');
      const parsed = parsePath(url.pathname);
      if (!parsed) throw new HttpError(404, 'Not found');
      const route = table.get(`${req.method} ${parsed.route === '/' ? '/hello' : parsed.route}`);
      if (!route || (parsed.explicitTenant && !route.tenant)) throw new HttpError(404, 'Not found');
      if (route.auth) {
        const key = req.headers['api-key'];
        if (typeof key !== 'string' || !engine.config.apiKeys.some((k) => safeEqual(k, key))) throw new HttpError(401, 'Invalid API key');
      }
      const cdi = req.headers['cdi-version'];
      if (typeof cdi === 'string' && !CDI_VERSIONS.includes(cdi)) throw badRequest(`cdi-version ${cdi} not supported`);
      if (route.publicAppOnly && parsed.appId !== 'public') throw badRequest('Only the public app can manage apps');
      const app = await engine.db.query('SELECT 1 FROM ea_apps WHERE app_id = $1', [parsed.appId]);
      if (app.rowCount !== 1) throw badRequest('AppId or tenantId not found => App not found');
      const body = req.method === 'GET' ? {} : await readJson(req);
      send(res, 200, await route.handle({ appId: parsed.appId, tenantId: parsed.tenantId, body, query: url.searchParams }));
    } catch (error) {
      if (error instanceof HttpError) return send(res, error.status, error.message);
      // Never serialise internal errors; they may contain SQL or secrets.
      console.error('[expertauth] internal error', error instanceof Error ? error.stack : error);
      send(res, 500, 'Internal Error');
    }
  });
}
