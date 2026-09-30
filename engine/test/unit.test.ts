import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';
import { ConfigError, loadConfig } from '../src/config.ts';
import { decrypt, encrypt, safeEqual } from '../src/crypto.ts';
import { parsePath } from '../src/http/server.ts';
import { importableHash, needsRehash } from '../src/passwords.ts';

const secret = () => randomBytes(32).toString('base64');
const base = { EXPERTAUTH_DATABASE_URL: 'postgresql://x', EXPERTAUTH_API_KEYS: 'k'.repeat(24),
  EXPERTAUTH_KEY_ENCRYPTION_KEY: secret(), EXPERTAUTH_REFRESH_SECRET: secret() };

describe('config fails closed', () => {
  it('uses production-grade defaults', () => {
    const c = loadConfig(base);
    assert.deepEqual(c.argon2, { memoryKiB: 19456, iterations: 2, parallelism: 1 });
    assert.equal(c.refreshGraceSeconds, 5);
    assert.equal(c.host, '127.0.0.1');
  });
  for (const [name, env] of Object.entries({
    'no database': { ...base, EXPERTAUTH_DATABASE_URL: '' },
    'no API keys': { ...base, EXPERTAUTH_API_KEYS: '' },
    'short API key': { ...base, EXPERTAUTH_API_KEYS: 'short' },
    'missing key-encryption key': { ...base, EXPERTAUTH_KEY_ENCRYPTION_KEY: '' },
    'short refresh secret': { ...base, EXPERTAUTH_REFRESH_SECRET: Buffer.alloc(16).toString('base64') },
    'non-integer lifetime': { ...base, EXPERTAUTH_ACCESS_TOKEN_SECONDS: '1h' },
    'argon2 memory too low': { ...base, EXPERTAUTH_ARGON2_MEMORY_KIB: '1024' },
    'grace above 60s': { ...base, EXPERTAUTH_REFRESH_GRACE_SECONDS: '600' },
  })) it(`refuses ${name}`, () => assert.throws(() => loadConfig(env), ConfigError));
});

describe('routing', () => {
  it('parses app, tenant and route', () => {
    assert.deepEqual(parsePath('/recipe/signin'), { appId: 'public', tenantId: 'public', route: '/recipe/signin', explicitTenant: false });
    assert.deepEqual(parsePath('/appid-acme/east/recipe/signin'), { appId: 'acme', tenantId: 'east', route: '/recipe/signin', explicitTenant: true });
    assert.deepEqual(parsePath('/appid-acme/recipe/session/refresh'), { appId: 'acme', tenantId: 'public', route: '/recipe/session/refresh', explicitTenant: false });
    assert.equal(parsePath('/appid-ACME/recipe/signin'), null);
    assert.equal(parsePath('/appid-a/../recipe/signin'), null);
    assert.equal(parsePath('/appid-a/Bad_Tenant/recipe/signin'), null);
    assert.equal(parsePath('/.well-known/jwks.json')!.route, '/.well-known/jwks.json');
  });
});

describe('primitives', () => {
  it('seals and opens key material, refusing tampering', () => {
    const key = randomBytes(32);
    const sealed = encrypt(key, 'private-key-material');
    assert.equal(decrypt(key, sealed), 'private-key-material');
    const parts = sealed.split('.'); parts[3] = Buffer.from('tampered').toString('base64url');
    assert.throws(() => decrypt(key, parts.join('.')));
    assert.throws(() => decrypt(randomBytes(32), sealed));
  });
  it('compares secrets without length shortcuts', () => {
    assert.equal(safeEqual('abc', 'abc'), true);
    assert.equal(safeEqual('abc', 'abd'), false);
    assert.equal(safeEqual('abc', 'abcd'), false);
  });
  it('decides rehash and import bounds', () => {
    const policy = { memoryKiB: 19456, iterations: 2, parallelism: 1 };
    assert.equal(needsRehash('$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA', policy), false);
    assert.equal(needsRehash('$argon2id$v=19$m=65536,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA', policy), true);
    assert.equal(needsRehash('$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA', policy), true);
    assert.equal(needsRehash('$2b$10$' + 'a'.repeat(53), policy), true);
    assert.equal(importableHash('$2b$10$' + 'a'.repeat(53)), true);
    assert.equal(importableHash('$2b$03$' + 'a'.repeat(53)), false);
    assert.equal(importableHash('$2b$17$' + 'a'.repeat(53)), false);
    assert.equal(importableHash('$argon2id$v=19$m=7,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA'), false);
    assert.equal(importableHash('$argon2id$v=19$m=19456,t=0,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA'), false);
  });
});
