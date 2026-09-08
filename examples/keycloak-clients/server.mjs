import express from 'express';
import cookieParser from 'cookie-parser';
import { doubleCsrf } from 'csrf-csrf';
import { CookieJar } from 'tough-cookie';
import * as oidc from 'openid-client';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { randomBytes, timingSafeEqual } from 'node:crypto';

const ORIGIN = process.env.APP_ORIGIN || 'http://expertauth-kc-clients-node:3000';
const ISSUER = process.env.KC_ISSUER || 'http://kc-headless.example.test:8080/realms/expertauth-headless-proof';
const CLIENT = process.env.KC_CLIENT_ID || 'expertauth-node-candidate';
const AUDIENCE = 'expertauth-candidate-api';
const TENANT = 'alpha';
const CALLBACK = `${ORIGIN}/candidate/callback`;
const secure = new URL(ORIGIN).protocol === 'https:';
const localProof = process.env.EXPERTAUTH_LOCAL_PROOF === 'true';
if ((!secure || new URL(ISSUER).protocol !== 'https:') && !localProof) throw new Error('TLS required outside explicit local proof');
const csrfSecret = process.env.CSRF_SECRET || (localProof ? randomBytes(32).toString('hex') : undefined);
if (!csrfSecret || csrfSecret.length < 32) throw new Error('CSRF_SECRET must have at least 32 characters');
const config = await oidc.discovery(new URL(ISSUER), CLIENT, undefined, oidc.None(),
  localProof ? { execute: [oidc.allowInsecureRequests] } : undefined);
const metadata = config.serverMetadata();
const engineOrigin = new URL(ISSUER).origin;
for (const endpoint of ['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'revocation_endpoint']) {
  if (new URL(metadata[endpoint]).origin !== engineOrigin) throw new Error('Unexpected engine metadata origin');
}
const jwks = createRemoteJWKSet(new URL(metadata.jwks_uri));
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '8kb', strict: true }));
app.use(cookieParser());
const cookies = { httpOnly: true, secure, sameSite: 'strict', path: '/candidate' };
const bindingName = secure ? '__Secure-ea-proof-binding' : 'ea-proof-binding';
const accessName = secure ? '__Secure-ea-proof-access' : 'ea-proof-access';
const refreshName = secure ? '__Secure-ea-proof-refresh' : 'ea-proof-refresh';
const transactions = new Map(); // Only short-lived OAuth/preauthentication correlation, not authenticated sessions.
const MAX_TRANSACTIONS = 500;
const TTL = 180_000;
const random = () => randomBytes(32).toString('base64url');
const equal = (a, b) => typeof a === 'string' && typeof b === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) &&
  timingSafeEqual(Buffer.from(a), Buffer.from(b));
const fail = (status, code) => Object.assign(new Error(code), { status, publicCode: code });
const prune = () => { for (const [id, tx] of transactions) if (tx.expires < Date.now()) transactions.delete(id); };
setInterval(prune, 30_000).unref();
const csrf = doubleCsrf({
  getSecret: () => csrfSecret,
  getSessionIdentifier: req => req.cookies[bindingName] || '',
  cookieName: secure ? '__Secure-ea-proof-csrf' : 'ea-proof-csrf',
  cookieOptions: cookies,
  getCsrfTokenFromRequest: req => req.headers['x-csrf-token'],
});

app.use((req, res, next) => {
  res.set({ 'Cache-Control': 'no-store', 'Pragma': 'no-cache', 'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" });
  if (req.headers.origin && req.headers.origin !== ORIGIN) return next(fail(403, 'ORIGIN_REJECTED'));
  if (req.method === 'OPTIONS') return res.sendStatus(403);
  if (req.path.startsWith('/candidate') && !['GET', 'HEAD'].includes(req.method)) {
    if (req.headers.origin !== ORIGIN || !req.is('application/json')) return next(fail(403, 'ORIGIN_OR_CONTENT_TYPE_REJECTED'));
  }
  next();
});

function rotateBinding(req, res) {
  req.cookies[bindingName] = random();
  res.cookie(bindingName, req.cookies[bindingName], { ...cookies, maxAge: 3600_000 });
  return csrf.generateCsrfToken(req, res, { overwrite: true });
}
function requireKeys(body, allowed) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(k => !allowed.includes(k))) {
    throw fail(400, 'INVALID_REQUEST_FIELDS');
  }
}
function currentTransaction(req) {
  const tx = transactions.get(req.body.transactionId);
  if (!tx || tx.expires < Date.now() || !equal(tx.binding, req.cookies[bindingName])) throw fail(409, 'TRANSACTION_EXPIRED_OR_UNBOUND');
  if (tx.locked || !equal(tx.actionToken, req.body.actionToken)) throw fail(409, 'ACTION_REPLAY_OR_CONCURRENT_REQUEST');
  tx.locked = true;
  tx.actionToken = null; // Consume before awaiting any upstream call.
  return tx;
}
function checkedAction(value) {
  const action = new URL(value);
  const realmPath = new URL(ISSUER).pathname;
  if (action.origin !== engineOrigin || action.pathname !== `${realmPath}/login-actions/authenticate` ||
      action.username || action.password || action.hash || action.searchParams.get('client_id') !== CLIENT ||
      !action.searchParams.get('session_code') || !action.searchParams.get('tab_id')) throw fail(502, 'ENGINE_ACTION_REJECTED');
  return action;
}
async function engineRequest(tx, url, data) {
  const headers = { Accept: 'application/json' };
  const jarCookie = await tx.jar.getCookieString(url.href);
  if (jarCookie) headers.Cookie = jarCookie;
  if (data) headers['Content-Type'] = 'application/x-www-form-urlencoded';
  const response = await fetch(url, { method: data ? 'POST' : 'GET', headers,
    body: data ? new URLSearchParams(data) : undefined, redirect: 'manual', signal: AbortSignal.timeout(10_000) });
  for (const cookie of response.headers.getSetCookie()) await tx.jar.setCookie(cookie, url.href);
  if (response.status === 302) {
    const target = new URL(response.headers.get('location'), engineOrigin);
    if (target.origin + target.pathname !== CALLBACK || target.username || target.password || target.hash) {
      throw fail(409, 'ENGINE_RESTART_REQUIRED');
    }
    if (tx.step !== 'totp') throw fail(502, 'ENGINE_SKIPPED_REQUIRED_FACTOR');
    const tokens = await oidc.authorizationCodeGrant(config, target, {
      pkceCodeVerifier: tx.verifier, expectedState: tx.state, expectedNonce: tx.nonce, idTokenExpected: true,
    });
    const identity = await verifyAccess(tokens.access_token);
    if (!tokens.refresh_token) throw fail(502, 'ENGINE_REFRESH_TOKEN_MISSING');
    return { kind: 'authenticated', tokens, identity };
  }
  if (![200, 401].includes(response.status) || !response.headers.get('content-type')?.startsWith('application/json')) {
    throw fail(409, 'ENGINE_RESTART_REQUIRED');
  }
  const challenge = await response.json();
  if (challenge.status !== 'CHALLENGE' || challenge.authenticated !== false || challenge.method !== 'POST' ||
      challenge.contentType !== 'application/x-www-form-urlencoded' || !['password', 'totp'].includes(challenge.step)) {
    throw fail(502, 'ENGINE_CHALLENGE_REJECTED');
  }
  const expectedFields = challenge.step === 'password' ? ['username', 'password'] : ['otp'];
  if (JSON.stringify(challenge.fields) !== JSON.stringify(expectedFields)) throw fail(502, 'ENGINE_CHALLENGE_FIELDS_REJECTED');
  if (tx.step === 'totp' && challenge.step !== 'totp') throw fail(409, 'ENGINE_RESTART_REQUIRED');
  tx.action = checkedAction(challenge.action);
  tx.step = challenge.step;
  tx.actionToken = random();
  tx.locked = false;
  return { kind: 'challenge', step: tx.step, error: response.status === 401 ? 'AUTHENTICATION_FAILED' : null };
}
async function verifyAccess(access) {
  if (!access || typeof access !== 'string') throw fail(401, 'AUTHENTICATION_REQUIRED');
  const { payload } = await jwtVerify(access, jwks, { issuer: ISSUER, audience: AUDIENCE,
    algorithms: ['RS256'], requiredClaims: ['sub', 'exp', 'iat', 'azp'] });
  // Keycloak 26.7.3 built-in organization mapper defaults to multivalued String claims.
  // Validate this configured signed shape exactly; do not infer membership from caller input.
  if (payload.azp !== CLIENT || !Array.isArray(payload.organization) ||
      !payload.organization.every(value => typeof value === 'string') || !payload.organization.includes(TENANT)) {
    throw fail(403, 'TENANT_OR_CLIENT_REJECTED');
  }
  return { subject: payload.sub, tenant: TENANT, expiresAt: payload.exp, issuer: payload.iss, audience: AUDIENCE };
}
function tokenCookies(res, tokens) {
  res.cookie(accessName, tokens.access_token, { ...cookies, maxAge: Math.max(1000, Number(tokens.expires_in) * 1000) });
  res.cookie(refreshName, tokens.refresh_token, { ...cookies, maxAge: Math.max(1000, Number(tokens.refresh_expires_in || 1800) * 1000) });
}

app.get('/healthz', (_req, res) => res.json({ ready: true, profile: 'keycloak-candidate-json-password-totp' }));
app.get('/candidate/csrf', (req, res) => {
  if (!req.cookies[bindingName]) {
    const csrfToken = rotateBinding(req, res);
    return res.json({ csrfToken });
  }
  res.json({ csrfToken: csrf.generateCsrfToken(req, res) });
});
app.use('/candidate', csrf.doubleCsrfProtection);
app.post('/candidate/start', async (req, res) => {
  requireKeys(req.body, ['tenant']);
  if (req.body.tenant !== TENANT) throw fail(403, 'TENANT_REJECTED');
  prune();
  if (transactions.size >= MAX_TRANSACTIONS) throw fail(429, 'PREAUTH_CAPACITY_EXCEEDED');
  const transactionId = random();
  const tx = { binding: req.cookies[bindingName], jar: new CookieJar(), state: oidc.randomState(), nonce: oidc.randomNonce(),
    verifier: oidc.randomPKCECodeVerifier(), expires: Date.now() + TTL, step: 'password', locked: false };
  transactions.set(transactionId, tx);
  const url = oidc.buildAuthorizationUrl(config, { redirect_uri: CALLBACK, scope: `openid organization:${TENANT}`,
    state: tx.state, nonce: tx.nonce, code_challenge: await oidc.calculatePKCECodeChallenge(tx.verifier), code_challenge_method: 'S256' });
  try {
    const result = await engineRequest(tx, url);
    if (result.kind !== 'challenge' || result.step !== 'password') throw fail(502, 'ENGINE_INITIAL_STATE_REJECTED');
    res.json({ status: 'CHALLENGE', step: result.step, authenticated: false, transactionId, actionToken: tx.actionToken });
  } catch (error) {
    transactions.delete(transactionId);
    throw error;
  }
});
app.post('/candidate/step', async (req, res) => {
  requireKeys(req.body, ['transactionId', 'actionToken', 'username', 'password', 'otp']);
  const tx = currentTransaction(req);
  const allowed = tx.step === 'password' ? ['username', 'password'] : ['otp'];
  if (Object.keys(req.body).some(k => !['transactionId', 'actionToken', ...allowed].includes(k))) {
    transactions.delete(req.body.transactionId);
    throw fail(400, 'INVALID_CREDENTIAL_FIELDS');
  }
  const data = {};
  for (const field of allowed) {
    if (typeof req.body[field] !== 'string' || req.body[field].length < 1 || req.body[field].length > 512) {
      transactions.delete(req.body.transactionId);
      throw fail(400, 'INVALID_CREDENTIAL_FIELDS');
    }
    data[field] = req.body[field];
  }
  if (tx.step === 'totp' && !/^\d{6}$/.test(data.otp)) {
    transactions.delete(req.body.transactionId);
    throw fail(400, 'INVALID_OTP_FORMAT');
  }
  try {
    const result = await engineRequest(tx, tx.action, data);
    if (result.kind === 'challenge') return res.status(result.error ? 401 : 200).json({ status: 'CHALLENGE', step: result.step,
      authenticated: false, transactionId: req.body.transactionId, actionToken: tx.actionToken, error: result.error });
    transactions.delete(req.body.transactionId);
    tokenCookies(res, result.tokens);
    const csrfToken = rotateBinding(req, res);
    res.json({ status: 'AUTHENTICATED', authenticated: true, identity: result.identity, csrfToken });
  } catch (error) {
    transactions.delete(req.body.transactionId);
    throw error;
  }
});
app.get('/candidate/resource', async (req, res) => {
  const bearer = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : undefined;
  const identity = await verifyAccess(bearer || req.cookies[accessName]);
  if (req.query.tenant !== identity.tenant) throw fail(403, 'TENANT_REJECTED');
  res.json({ authenticated: true, identity, message: 'Private candidate resource authorized by Keycloak-issued claims.' });
});
app.post('/candidate/refresh', async (req, res) => {
  requireKeys(req.body, []);
  const refresh = req.cookies[refreshName];
  if (!refresh) throw fail(401, 'AUTHENTICATION_REQUIRED');
  const tokens = await oidc.refreshTokenGrant(config, refresh);
  const identity = await verifyAccess(tokens.access_token);
  tokenCookies(res, { ...tokens, refresh_token: tokens.refresh_token || refresh });
  res.json({ status: 'AUTHENTICATED', authenticated: true, identity });
});
app.post('/candidate/logout', async (req, res) => {
  requireKeys(req.body, []);
  const refresh = req.cookies[refreshName];
  if (refresh) await oidc.tokenRevocation(config, refresh, { token_type_hint: 'refresh_token' });
  res.clearCookie(accessName, cookies);
  res.clearCookie(refreshName, cookies);
  for (const [id, tx] of transactions) if (equal(tx.binding, req.cookies[bindingName])) transactions.delete(id);
  res.json({ authenticated: false, csrfToken: rotateBinding(req, res) });
});
// The final OAuth redirect is consumed privately, never accepted from an arbitrary client URL.
app.all('/candidate/callback', (_req, _res, next) => next(fail(400, 'PUBLIC_CALLBACK_NOT_ACCEPTED')));
app.use(express.static('public', { etag: false }));
app.use((error, _req, res, _next) => {
  const status = error.publicCode ? error.status : error.code === 'EBADCSRFTOKEN' ? 403 :
    ['JWTExpired', 'JWTClaimValidationFailed', 'JWSSignatureVerificationFailed', 'JWSInvalid', 'JOSENotSupported', 'JOSEAlgNotAllowed', 'JWKSNoMatchingKey', 'ResponseBodyError'].includes(error.name) ? 401 :
    error.type === 'entity.parse.failed' ? 400 : 502;
  // Do not serialize/log upstream requests, JWTs, authorization URLs, credentials or raw library errors.
  if (!error.publicCode && error.code !== 'EBADCSRFTOKEN') console.error(JSON.stringify({ event: 'request_rejected',
    type: /^[A-Za-z]+$/.test(error.name) ? error.name : 'Error',
    code: /^[A-Z_]+$/.test(error.code || '') ? error.code : 'UNSPECIFIED',
    claim: ['iss', 'aud', 'sub', 'exp', 'iat', 'nonce', 'azp'].includes(error.claim) ? error.claim : undefined }));
  res.status(status).json({ authenticated: false, error: error.publicCode || (status === 403 ? 'CSRF_REJECTED' : status === 401 ? 'AUTHENTICATION_REJECTED' : 'REQUEST_FAILED') });
});
app.listen(3000, '0.0.0.0', () => console.log('ExpertAuth Keycloak candidate backend ready; bounded proof profile.'));
