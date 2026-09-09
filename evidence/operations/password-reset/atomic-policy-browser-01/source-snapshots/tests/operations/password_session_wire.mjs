/** Test-only observation of actual Core responses. Never alters request/response bytes. */
import { appendFileSync } from 'node:fs';
const destination = process.env.RESET_WIRE_FILE;
const coreOrigin = new URL(process.env.EXPERTAUTH_CORE_URL).origin;
if (!destination || !/^\/wire\/[a-z-]+\.jsonl$/.test(destination)) throw new Error('Bounded wire destination required');
const original = globalThis.fetch;
let records = 0;
globalThis.fetch = async (input, init) => {
  const response = await original(input, init);
  const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
  const method = (init?.method || input?.method || 'GET').toUpperCase();
  const path = url.pathname.endsWith('/expertauth/password/session') ? '/expertauth/password/session' :
    url.pathname.endsWith('/recipe/session') ? '/recipe/session' : null;
  if (url.origin === coreOrigin && method === 'POST' && path) {
    if (++records > 1000) throw new Error('Wire observation limit exceeded');
    let body; try { body = await response.clone().json(); } catch { body = {}; }
    appendFileSync(destination, JSON.stringify({path, http:response.status,
      status:['OK','PASSWORD_SESSION_REJECTED'].includes(body.status) ? body.status : 'OTHER',
      policy:body.policy === 'EXPERTAUTH-PASSWORD-SESSION-1' ? body.policy : 'OTHER'}) + '\n');
  }
  return response;
};
