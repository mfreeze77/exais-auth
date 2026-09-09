import express from 'express';
import supertokens from 'supertokens-node';
import EmailPassword from 'supertokens-node/recipe/emailpassword/index.js';
import Session from 'supertokens-node/recipe/session/index.js';
import { middleware, errorHandler } from 'supertokens-node/framework/express/index.js';
import { verifySession } from 'supertokens-node/recipe/session/framework/express/index.js';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { AsyncLocalStorage } from 'node:async_hooks';
import { createRemoteJWKSet, customFetch, jwtVerify } from 'jose';
import { createPasswordResetEmailDelivery, PasswordResetDeliveryError } from './email-delivery.js';

const origin = new URL(process.env.EXPERTAUTH_PUBLIC_ORIGIN || 'http://localhost:7300').origin;
const coreURL = process.env.EXPERTAUTH_CORE_URL || 'http://core-a:3567';
const apiKey = process.env.EXPERTAUTH_CORE_API_KEY;
if (!apiKey || apiKey.length < 20) throw new Error('A private Core API key is required');
if (process.env.NODE_ENV === 'production' && !origin.startsWith('https://') && process.env.EXPERTAUTH_LOCAL_PROBE !== 'true') {
  throw new Error('Production public origin must use HTTPS');
}
const passwordResetDelivery = createPasswordResetEmailDelivery(process.env, origin);
const resetPolicy = process.env.EXPERTAUTH_RESET_POLICY || 'upstream';
if (!['upstream', 'atomic-v1'].includes(resetPolicy)) throw new Error('Unsupported reset policy');
const atomicReset = resetPolicy === 'atomic-v1';
const sessionPolicy = process.env.EXPERTAUTH_SESSION_POLICY || 'upstream';
if (!['upstream', 'core-cdi56-grace-v1'].includes(sessionPolicy)) throw new Error('Unsupported session policy');
const refreshAtCommit = sessionPolicy === 'core-cdi56-grace-v1';
if (refreshAtCommit && !atomicReset) throw new Error('The CDI5.6 candidate requires atomic-v1 password/session creation');
const atomicPolicy = 'EXPERTAUTH-ATOMIC-RESET-1';
const passwordSessionPolicy = 'EXPERTAUTH-PASSWORD-SESSION-1';
const credentialScope = new AsyncLocalStorage();
const coreConnection = new URL(coreURL);
if (atomicReset && (coreConnection.username || coreConnection.password || coreConnection.search || coreConnection.hash ||
    !['http:', 'https:'].includes(coreConnection.protocol))) throw new Error('Invalid private Core URL');

async function atomicCore(path, tenantId, input, timeout = 15000) {
  const tenant = tenantId ?? 'public';
  if (typeof tenant !== 'string' || !tenant || tenant === '.' || tenant === '..' || /[\\/\u0000-\u0020\u007f]/.test(tenant)) {
    throw new Error('Invalid reset tenant');
  }
  const base = new URL(coreConnection);
  base.pathname = base.pathname.replace(/\/$/, '') + '/' + encodeURIComponent(tenant) + '/expertauth/password/reset' + path;
  const response = await fetch(base, {method:'POST', redirect:'error', signal:AbortSignal.timeout(timeout),
    headers:{'api-key':apiKey,'cdi-version':'5.4',rid:'emailpassword','content-type':'application/json'}, body:JSON.stringify(input)});
  if (!response.body) throw new Error('Atomic reset response missing');
  const reader = response.body.getReader(), chunks = []; let length = 0;
  try {
    while (true) {
      const {done, value} = await reader.read(); if (done) break;
      length += value.byteLength;
      if (length > 65536) { await reader.cancel(); throw new Error('Atomic reset response exceeds bound'); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  let result;
  try { result = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new Error('Invalid atomic reset response'); }
  if (!response.ok || !result || typeof result.status !== 'string') throw new Error('Atomic reset operation failed');
  if (result.status === 'OK' && result.policy !== atomicPolicy) throw new Error('Atomic reset policy unavailable');
  return result;
}

async function passwordSessionCapability() {
  const url = new URL(coreConnection);
  url.pathname = url.pathname.replace(/\/$/,'') + '/public/expertauth/password/session';
  const response = await fetch(url, {redirect:'error', signal:AbortSignal.timeout(2000),
    headers:{'api-key':apiKey,'cdi-version':'5.4',rid:'session'}});
  if (!response.ok || !response.body) throw new Error('Password session capability unavailable');
  const reader = response.body.getReader(), chunks = []; let length = 0;
  try {
    while (true) {
      const {done, value} = await reader.read(); if (done) break;
      length += value.byteLength;
      if (length > 4096) { await reader.cancel(); throw new Error('Capability response exceeds bound'); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const capability = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (capability?.status !== 'OK' || capability.policy !== passwordSessionPolicy) {
    throw new Error('Password session storage unavailable');
  }
  if (refreshAtCommit && (capability.sessionPolicy?.refreshTokenRotationGracePeriodSeconds !== 5 ||
      capability.sessionPolicy?.recentTokenReuseBehaviour !== 'TOKEN_THEFT')) {
    throw new Error('Effective Core session policy mismatch');
  }
}

async function requireSessionPolicy(_req, res, next) {
  if (!refreshAtCommit) return next();
  try {
    // Do not cache a healthy answer across requests. Core remains authoritative.
    // Deployments must keep every replica's configuration consistent; this
    // preflight is not an atomic policy/configuration lock across a load balancer.
    await passwordSessionCapability();
    next();
  } catch { res.status(503).json({error:'SESSION_POLICY_UNAVAILABLE'}); }
}

function passwordFlow(original) {
  if (!original) return original;
  return async input => {
    const email = input.formFields.find(field => field.id === 'email')?.value;
    const password = input.formFields.find(field => field.id === 'password')?.value;
    if (typeof email !== 'string' || typeof password !== 'string') throw new Error('Validated credentials missing');
    const proof = {email, password, tenantId:input.tenantId ?? 'public'};
    // Request-scoped memory only. No credentials enter userContext, logs or a
    // second store; concurrent requests cannot read each other's scope.
    return credentialScope.run(proof, async () => {
      try { return await original(input); }
      finally { delete proof.email; delete proof.password; }
    });
  };
}

function sessionInterceptor(request) {
  const proof = credentialScope.getStore();
  if (!proof || request.method !== 'post' || !new URL(request.url).pathname.endsWith('/recipe/session')) return request;
  const url = new URL(request.url);
  const prefix = coreConnection.pathname.replace(/\/$/,'');
  const expected = prefix + '/' + encodeURIComponent(proof.tenantId) + '/recipe/session';
  if (typeof proof.email !== 'string' || typeof proof.password !== 'string' || url.origin !== coreConnection.origin ||
      url.search || url.hash || (url.pathname !== expected && !(proof.tenantId === 'public' && url.pathname === prefix + '/recipe/session'))) {
    throw new Error('Password session context mismatch');
  }
  url.pathname = url.pathname.replace(/\/recipe\/session$/, '/expertauth/password/session');
  return {...request, url:url.toString(), body:{...request.body, email:proof.email, password:proof.password}};
}

function coreInterceptor(input) {
  const request = atomicReset ? sessionInterceptor(input) : input;
  if (!refreshAtCommit || request.method !== 'post') return request;
  const url = new URL(request.url), prefix = coreConnection.pathname.replace(/\/$/,'');
  const path = url.pathname.slice(prefix.length);
  if (!/\/recipe\/session\/(refresh|verify)$/.test(url.pathname)) return request;
  if (!url.pathname.startsWith(prefix) || !/^\/(?:public\/)?recipe\/session\/(refresh|verify)$/.test(path) ||
      url.origin !== coreConnection.origin || url.search || url.hash || request.headers['cdi-version'] !== '5.4') {
    throw new Error('Session protocol adaptation context mismatch');
  }
  // Explicit ExpertAuth adaptation of these two private operations only. The
  // dependency still declares CDI5.4; this does not claim unmodified SDK5.6 support.
  // Core owns rotation, grace and revocation. No adapter token/family store exists.
  return {...request, headers:{...request.headers, 'cdi-version':'5.6'}};
}

supertokens.init({
  framework: 'express',
  supertokens: { connectionURI: coreURL, apiKey, ...(atomicReset ? {networkInterceptor:coreInterceptor} : {}) },
  appInfo: { appName: 'ExpertAuth foundation', apiDomain: origin, websiteDomain: origin, apiBasePath: '/auth', websiteBasePath: '/auth' },
  telemetry: false,
  recipeList: [
    EmailPassword.init({
      emailDelivery: passwordResetDelivery || { service: { async sendEmail() { throw new Error('Local recovery delivery is not configured'); } } },
      override: {
        functions: original => atomicReset ? {...original,
          createResetPasswordToken: async ({userId, email, tenantId}) => {
            const result = await atomicCore('/token', tenantId, {userId, email});
            if (result.status !== 'OK' || typeof result.token !== 'string') throw new Error('Atomic token issue failed');
            return {status:'OK', token:result.token};
          },
        } : original,
        apis: original => {
        // The maintained override proxy requires its original receiver (_call).
        const passwordAPIs = atomicReset ? {signInPOST:passwordFlow(input => original.signInPOST(input)), signUpPOST:passwordFlow(input => original.signUpPOST(input))} : {};
        if (!passwordResetDelivery) return { ...original, ...passwordAPIs, generatePasswordResetTokenPOST: undefined, passwordResetPOST: undefined };
        return { ...original, ...passwordAPIs,
          generatePasswordResetTokenPOST: async input => {
            try { return await original.generatePasswordResetTokenPOST(input); }
            catch (error) {
              // SMTP failure must not distinguish an existing address from an
              // unknown one. The delivery adapter records a fixed private error.
              // There is no durable delivery queue yet; callers can request again.
              if (error instanceof PasswordResetDeliveryError) return { status: 'OK' };
              throw error;
            }
          },
          passwordResetPOST: async input => {
            if (atomicReset) {
              // SDK form validation precedes this override. Core consumes the
              // context-bound token, changes the password and deletes existing
              // sessions in one transaction. Never fall back to separate calls.
              const password = input.formFields.find(field => field.id === 'password')?.value;
              if (typeof password !== 'string') throw new Error('Validated password missing');
              const result = await atomicCore('', input.tenantId, {token:input.token, newPassword:password});
              if (result.status === 'RESET_PASSWORD_INVALID_TOKEN_ERROR') return {status:result.status};
              if (result.status !== 'OK' || typeof result.userId !== 'string' || typeof result.email !== 'string' ||
                  typeof result.recipeUserId !== 'string') throw new Error('Atomic reset failed');
              const user = await supertokens.getUser(result.userId, input.userContext);
              if (!user || user.id !== result.userId || !user.loginMethods.some(method =>
                  method.recipeId === 'emailpassword' && method.recipeUserId.getAsString() === result.recipeUserId &&
                  method.email === result.email)) throw new Error('Reset identity changed after commit');
              return {status:'OK', user, email:result.email};
            }
            const result = await original.passwordResetPOST(input);
            if (result.status === 'OK') {
              // The engine owns both operations. Success is returned only after
              // online revocation. This is not one atomic reset/revoke transaction;
              // crash recovery between these calls remains unqualified.
              await Session.revokeAllSessionsForUser(result.user.id, true, undefined, input.userContext);
            }
            return result;
          },
        };
      } },
    }),
    Session.init({ cookieSecure: origin.startsWith('https://'), cookieSameSite: 'lax', antiCsrf: 'VIA_CUSTOM_HEADER',
      override: { functions: original => ({ ...original, createNewSession: input => original.createNewSession({
        ...input, accessTokenPayload: {...input.accessTokenPayload, iss: origin, aud: `${origin}/api`},
      }) }) },
    }),
  ],
});

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', false);
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'no-referrer');
  res.set('Cache-Control', 'no-store');
  const requestOrigin = req.headers.origin;
  if (requestOrigin && requestOrigin !== origin) return res.status(403).json({ error: 'ORIGIN_NOT_ALLOWED' });
  // No reflected credentialed CORS. This example deliberately uses one origin.
  next();
});
app.use(express.json({ limit: '32kb' }));
app.get('/health/live', (_req, res) => res.json({ status: 'alive' }));
app.get('/health/ready', async (_req, res) => {
  try {
    // users/count performs storage work; hello is not used as DB readiness proof.
    const response = await fetch(new URL('/users/count', coreURL), {
      headers: { 'api-key': apiKey, 'cdi-version': '5.3' }, signal: AbortSignal.timeout(2000),
    });
    const body = await response.json();
    if (!response.ok || body.status !== 'OK' || typeof body.count !== 'number') throw new Error('storage unavailable');
    if (refreshAtCommit) {
      const advertised = await fetch(new URL('/apiversion', coreURL), {redirect:'error',
        headers:{'api-key':apiKey}, signal:AbortSignal.timeout(2000)});
      const versions = await advertised.json();
      if (!advertised.ok || !Array.isArray(versions.versions) || !versions.versions.includes('5.6')) {
        throw new Error('CDI5.6 session capability unavailable');
      }
    }
    if (atomicReset) {
      // An intentionally malformed token exits before hashing or storage writes.
      // Storage readiness alone cannot prove that this Core has the required API.
      const capability = await atomicCore('', 'public', {token:'readiness-invalid-token', newPassword:'unused'}, 2000);
      if (capability.status !== 'RESET_PASSWORD_INVALID_TOKEN_ERROR') throw new Error('atomic reset unavailable');
      await passwordSessionCapability();
    }
    res.json({ status: 'ready' });
  } catch { res.status(503).json({ status: 'not-ready' }); }
});
app.use('/auth', requireSessionPolicy);
app.get(['/api/session','/api/session/online','/api/tenants/:tenantId/session'], requireSessionPolicy);
app.use(middleware());
const keys = createRemoteJWKSet(new URL('/.well-known/jwks.json',coreURL), {
  [customFetch]: (url, options) => fetch(url, {...options, redirect:'error', headers: {...options.headers, 'api-key': apiKey}}),
});
app.get('/api/session/offline', async (req,res) => {
  try {
    const authorization = req.headers.authorization;
    if (!authorization?.startsWith('Bearer ')) return res.status(401).json({error:'SESSION_REQUIRED'});
    const { payload } = await jwtVerify(authorization.slice(7),keys,{issuer:origin,audience:`${origin}/api`,algorithms:['RS256'],requiredClaims:['sub','exp','iat','tId','sessionHandle']});
    if (payload.tId !== 'public') return res.status(403).json({error:'TENANT_MISMATCH'});
    // Signature/claims only. Revocation is deliberately NOT promised by this profile.
    res.json({userId:payload.sub,tenantId:payload.tId,verification:'offline-jwt'});
  } catch { res.status(401).json({error:'INVALID_SESSION_TOKEN'}); }
});
const validateApplicationClaims = (req,res,next) => {
  const payload = req.session.getAccessTokenPayload();
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (payload.iss !== origin || !audiences.includes(`${origin}/api`)) return res.status(401).json({error:'APPLICATION_TOKEN_MISMATCH'});
  next();
};
app.get('/api/session', verifySession(), validateApplicationClaims, async (req, res) => {
  res.json({ userId: req.session.getUserId(), tenantId: req.session.getTenantId(), verification: 'sdk-hybrid' });
});
app.get('/api/session/online', verifySession({ checkDatabase: true }), validateApplicationClaims, async (req, res) => {
  res.json({ userId: req.session.getUserId(), tenantId: req.session.getTenantId(), verification: 'online-session' });
});
app.get('/api/tenants/:tenantId/session', verifySession({ checkDatabase: true }), validateApplicationClaims, (req, res) => {
  if (req.params.tenantId !== req.session.getTenantId()) return res.status(403).json({ error: 'TENANT_MISMATCH' });
  res.json({ userId: req.session.getUserId(), tenantId: req.session.getTenantId() });
});
app.use(errorHandler());
app.use((err, _req, res, _next) => {
  const status = err?.status === 413 ? 413 : 500;
  // Never serialize SDK/provider errors, request bodies, tokens or credentials.
  res.status(status).json({ error: status === 413 ? 'PAYLOAD_TOO_LARGE' : 'AUTHENTICATION_SERVICE_ERROR' });
});
const publicDir = join(dirname(fileURLToPath(import.meta.url)), 'public');
app.use(express.static(publicDir, { etag: false }));
app.get(['/','/auth','/auth/*path'], (_req, res) => res.sendFile(join(publicDir, 'index.html')));
app.listen(3000, '0.0.0.0', () => process.stdout.write('ExpertAuth foundation client listening on port 3000\n'));
