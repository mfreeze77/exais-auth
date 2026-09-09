import express from 'express';
import supertokens from 'supertokens-node';
import EmailPassword from 'supertokens-node/recipe/emailpassword/index.js';
import Session from 'supertokens-node/recipe/session/index.js';
import { middleware, errorHandler } from 'supertokens-node/framework/express/index.js';
import { verifySession } from 'supertokens-node/recipe/session/framework/express/index.js';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
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

supertokens.init({
  framework: 'express',
  supertokens: { connectionURI: coreURL, apiKey },
  appInfo: { appName: 'ExpertAuth foundation', apiDomain: origin, websiteDomain: origin, apiBasePath: '/auth', websiteBasePath: '/auth' },
  telemetry: false,
  recipeList: [
    EmailPassword.init({
      emailDelivery: passwordResetDelivery || { service: { async sendEmail() { throw new Error('Local recovery delivery is not configured'); } } },
      override: { apis: original => {
        if (!passwordResetDelivery) return { ...original, generatePasswordResetTokenPOST: undefined, passwordResetPOST: undefined };
        return { ...original,
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
    res.json({ status: 'ready' });
  } catch { res.status(503).json({ status: 'not-ready' }); }
});
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
