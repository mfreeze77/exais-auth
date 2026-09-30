// Password verifiers: argon2id for new credentials; bcrypt/argon2 accepted for imports and rehashed on login.
import { hash as argon2Hash, verify as argon2Verify } from '@node-rs/argon2';
import bcrypt from 'bcryptjs';
import type { Argon2Policy } from './config.ts';

export const MAX_PASSWORD_BYTES = 4096;

// Import bounds: prefix-only acceptance creates accounts that can never sign in, and unbounded
// costs make every login attempt on an imported account a CPU/memory sink.
const BCRYPT = /^\$2[abxy]\$(\d{2})\$[./A-Za-z0-9]{53}$/;
const ARGON2 = /^\$argon2(id|i|d)\$v=(16|19)\$m=(\d{1,10}),t=(\d{1,10}),p=(\d{1,10})\$[A-Za-z0-9+/]{11,}\$[A-Za-z0-9+/]{16,}$/;
export const IMPORT_BOUNDS = { bcryptMinCost: 4, bcryptMaxCost: 16, argon2MaxMemoryKiB: 1048576, argon2MaxIterations: 100, argon2MaxParallelism: 64 };

export function passwordAcceptable(password: unknown): password is string {
  return typeof password === 'string' && password.length > 0 && Buffer.byteLength(password, 'utf8') <= MAX_PASSWORD_BYTES;
}

/** Full structural check with resource bounds for importable hash strings. */
export function importableHash(hash: string): boolean {
  const b = BCRYPT.exec(hash);
  if (b) {
    const cost = Number(b[1]);
    return cost >= IMPORT_BOUNDS.bcryptMinCost && cost <= IMPORT_BOUNDS.bcryptMaxCost;
  }
  const a = ARGON2.exec(hash);
  if (a) {
    const memory = Number(a[3]), iterations = Number(a[4]), parallelism = Number(a[5]);
    return parallelism >= 1 && parallelism <= IMPORT_BOUNDS.argon2MaxParallelism && memory >= 8 * parallelism &&
      memory <= IMPORT_BOUNDS.argon2MaxMemoryKiB && iterations >= 1 && iterations <= IMPORT_BOUNDS.argon2MaxIterations;
  }
  return false;
}

export async function hashPassword(password: string, policy: Argon2Policy): Promise<string> {
  // @node-rs/argon2 exports Algorithm as an ambient const enum; Argon2id = 2 in its index.d.ts.
  return argon2Hash(password, { algorithm: 2, memoryCost: policy.memoryKiB,
    timeCost: policy.iterations, parallelism: policy.parallelism, outputLen: 32 });
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    if (BCRYPT.test(hash)) return await bcrypt.compare(password, hash);
    if (ARGON2.test(hash)) return await argon2Verify(hash, password);
  } catch {
    return false;
  }
  return false;
}

/** True when a verified hash is not already argon2id with exactly the configured parameters. */
export function needsRehash(hash: string, policy: Argon2Policy): boolean {
  const a = ARGON2.exec(hash);
  return !a || a[1] !== 'id' || a[2] !== '19' || Number(a[3]) !== policy.memoryKiB ||
    Number(a[4]) !== policy.iterations || Number(a[5]) !== policy.parallelism;
}

let dummy: Promise<string> | undefined;
/** Equalises work for unknown accounts so response time does not reveal whether an email exists. */
export async function burnVerification(password: string, policy: Argon2Policy): Promise<void> {
  dummy ??= hashPassword('expertauth-timing-equaliser', policy);
  await verifyPassword(password, await dummy);
}
