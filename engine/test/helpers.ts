// Real-PostgreSQL test harness: one fresh database and engine per test file, dropped afterwards.
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { startEngine } from '../src/main.ts';

export const API_KEY = 'test-api-key-' + randomBytes(12).toString('hex');

export interface Harness {
  base: string;
  db: pg.Pool;
  call: (method: string, path: string, body?: unknown, headers?: Record<string, string>) => Promise<{ status: number; body: any; text: string }>;
  close: () => Promise<void>;
}

export async function startHarness(env: Record<string, string> = {}): Promise<Harness> {
  const admin = process.env.EXPERTAUTH_TEST_ADMIN_URL;
  if (!admin) throw new Error('Set EXPERTAUTH_TEST_ADMIN_URL to a PostgreSQL superuser URL for integration tests');
  const name = 'ea_test_' + randomBytes(6).toString('hex');
  const adminPool = new pg.Pool({ connectionString: admin, max: 1 });
  await adminPool.query(`CREATE DATABASE ${name}`);
  const url = new URL(admin); url.pathname = '/' + name;
  const running = await startEngine({
    EXPERTAUTH_DATABASE_URL: url.toString(), EXPERTAUTH_PORT: '0', EXPERTAUTH_API_KEYS: API_KEY,
    EXPERTAUTH_KEY_ENCRYPTION_KEY: randomBytes(32).toString('base64'), EXPERTAUTH_REFRESH_SECRET: randomBytes(32).toString('base64'),
    // Low-cost argon2 keeps the suite fast; production defaults are enforced by config tests.
    EXPERTAUTH_ARGON2_MEMORY_KIB: '8192', EXPERTAUTH_ARGON2_ITERATIONS: '1', ...env,
  });
  const base = `http://127.0.0.1:${running.port}`;
  const call: Harness['call'] = async (method, path, body, headers = {}) => {
    const response = await fetch(base + path, {
      method, headers: { 'api-key': API_KEY, 'cdi-version': '5.4', 'content-type': 'application/json', ...headers },
      body: body === undefined ? undefined : typeof body === 'string' || body instanceof Uint8Array ? body as any : JSON.stringify(body),
    });
    const text = await response.text();
    let parsed: any = text;
    try { parsed = JSON.parse(text); } catch { /* plain-text error */ }
    return { status: response.status, body: parsed, text };
  };
  return {
    base, db: running.engine.db, call,
    async close() {
      await running.close();
      await adminPool.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      await adminPool.end();
    },
  };
}

export const email = (label: string) => `${label}-${randomBytes(4).toString('hex')}@example.test`;
export const UNICODE_PASSWORD = 'pässwörd-密码-\u{1F511}';
