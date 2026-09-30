// Engine configuration from the environment. Security-relevant settings fail closed.

export interface Argon2Policy { memoryKiB: number; iterations: number; parallelism: number }

export interface Config {
  databaseUrl: string;
  host: string;
  port: number;
  apiKeys: string[];
  /** 32+ byte secret used to encrypt signing keys at rest (AES-256-GCM). */
  keyEncryptionKey: Buffer;
  /** 32+ byte secret used to derive deterministic refresh successors (HMAC-SHA-256). */
  refreshSecret: Buffer;
  accessTokenSeconds: number;
  refreshTokenSeconds: number;
  /** Window in which the immediate parent refresh token still yields the same successor. */
  refreshGraceSeconds: number;
  resetTokenSeconds: number;
  emailVerificationTokenSeconds: number;
  argon2: Argon2Policy;
  issuer: string;
}

export class ConfigError extends Error {}

function integer(env: NodeJS.ProcessEnv, name: string, fallback: number, min: number, max: number): number {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  if (!/^\d+$/.test(raw)) throw new ConfigError(`${name} must be an integer`);
  const value = Number(raw);
  if (value < min || value > max) throw new ConfigError(`${name} must be between ${min} and ${max}`);
  return value;
}

function secret(env: NodeJS.ProcessEnv, name: string): Buffer {
  const raw = env[name];
  if (!raw) throw new ConfigError(`${name} is required (base64, at least 32 bytes)`);
  const value = Buffer.from(raw, 'base64');
  if (value.length < 32) throw new ConfigError(`${name} must decode to at least 32 bytes`);
  return value;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const databaseUrl = env.EXPERTAUTH_DATABASE_URL;
  if (!databaseUrl) throw new ConfigError('EXPERTAUTH_DATABASE_URL is required');
  const apiKeys = (env.EXPERTAUTH_API_KEYS ?? '').split(',').map((k) => k.trim()).filter(Boolean);
  if (apiKeys.length === 0) throw new ConfigError('EXPERTAUTH_API_KEYS is required; the engine API is never unauthenticated');
  if (apiKeys.some((k) => k.length < 20 || !/^[A-Za-z0-9=_-]+$/.test(k))) {
    throw new ConfigError('Each API key needs at least 20 characters from [A-Za-z0-9=_-]');
  }
  return {
    databaseUrl,
    host: env.EXPERTAUTH_HOST ?? '127.0.0.1',
    port: integer(env, 'EXPERTAUTH_PORT', 3567, 0, 65535),
    apiKeys,
    keyEncryptionKey: secret(env, 'EXPERTAUTH_KEY_ENCRYPTION_KEY'),
    refreshSecret: secret(env, 'EXPERTAUTH_REFRESH_SECRET'),
    accessTokenSeconds: integer(env, 'EXPERTAUTH_ACCESS_TOKEN_SECONDS', 3600, 1, 86400),
    refreshTokenSeconds: integer(env, 'EXPERTAUTH_REFRESH_TOKEN_SECONDS', 144000 * 60, 60, 365 * 86400),
    refreshGraceSeconds: integer(env, 'EXPERTAUTH_REFRESH_GRACE_SECONDS', 5, 0, 60),
    resetTokenSeconds: integer(env, 'EXPERTAUTH_RESET_TOKEN_SECONDS', 3600, 60, 86400),
    emailVerificationTokenSeconds: integer(env, 'EXPERTAUTH_EMAIL_VERIFICATION_TOKEN_SECONDS', 86400, 60, 7 * 86400),
    argon2: {
      memoryKiB: integer(env, 'EXPERTAUTH_ARGON2_MEMORY_KIB', 19456, 8192, 1048576),
      iterations: integer(env, 'EXPERTAUTH_ARGON2_ITERATIONS', 2, 1, 100),
      parallelism: integer(env, 'EXPERTAUTH_ARGON2_PARALLELISM', 1, 1, 64),
    },
    issuer: env.EXPERTAUTH_ISSUER ?? 'expertauth',
  };
}
