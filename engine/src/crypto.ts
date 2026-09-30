// Token, digest, key-encryption and JWT primitives over node:crypto. No custom cryptography.
import { createCipheriv, createDecipheriv, createHash, createHmac, createPublicKey, createSign, createVerify,
  generateKeyPairSync, randomBytes, timingSafeEqual, type KeyObject } from 'node:crypto';

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function hmac(key: Buffer, value: string): string {
  return createHmac('sha256', key).update(value, 'utf8').digest('base64url');
}

/** Constant-time string comparison that does not leak length through early exit. */
export function safeEqual(a: string, b: string): boolean {
  const left = createHash('sha256').update(a).digest();
  const right = createHash('sha256').update(b).digest();
  return timingSafeEqual(left, right) && a.length === b.length;
}

export function encrypt(key: Buffer, plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key.subarray(0, 32), iv);
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return ['v1', iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), body.toString('base64url')].join('.');
}

export function decrypt(key: Buffer, sealed: string): string {
  const [version, iv, tag, body] = sealed.split('.');
  if (version !== 'v1' || !iv || !tag || !body) throw new Error('Unsupported sealed value');
  const decipher = createDecipheriv('aes-256-gcm', key.subarray(0, 32), Buffer.from(iv, 'base64url'));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(body, 'base64url')), decipher.final()]).toString('utf8');
}

export interface SigningKey { keyId: string; privatePem: string; publicJwk: Record<string, string> }

export function generateSigningKey(): SigningKey {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = publicKey.export({ format: 'jwk' }) as Record<string, string>;
  const keyId = 'ea-rs256-' + randomToken(9);
  return {
    keyId,
    privatePem: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    publicJwk: { kty: jwk.kty!, n: jwk.n!, e: jwk.e!, kid: keyId, alg: 'RS256', use: 'sig' },
  };
}

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

export function signJwt(key: SigningKey, claims: Record<string, unknown>): string {
  const input = `${b64({ alg: 'RS256', typ: 'JWT', kid: key.keyId, version: '5' })}.${b64(claims)}`;
  const signature = createSign('RSA-SHA256').update(input).sign(key.privatePem).toString('base64url');
  return `${input}.${signature}`;
}

export type JwtResult = { ok: true; header: Record<string, unknown>; claims: Record<string, unknown> } | { ok: false };

/** Verifies an RS256 JWT against the given public JWKs. Algorithm is pinned; `none`/HS* are refused. */
export function verifyJwt(token: string, keys: Array<Record<string, string>>): JwtResult {
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) return { ok: false };
  try {
    const header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString('utf8'));
    if (header.alg !== 'RS256' || typeof header.kid !== 'string') return { ok: false };
    const jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk) return { ok: false };
    const publicKey: KeyObject = createPublicKey({ key: { kty: jwk.kty, n: jwk.n, e: jwk.e }, format: 'jwk' });
    const valid = createVerify('RSA-SHA256').update(`${parts[0]}.${parts[1]}`)
      .verify(publicKey, Buffer.from(parts[2]!, 'base64url'));
    if (!valid) return { ok: false };
    const claims = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'));
    if (typeof claims !== 'object' || claims === null || Array.isArray(claims)) return { ok: false };
    return { ok: true, header, claims };
  } catch {
    return { ok: false };
  }
}
