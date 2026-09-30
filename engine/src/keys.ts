// Per-app RS256 signing keys. Created once per app under an advisory lock; private keys encrypted at rest.
import type { Config } from './config.ts';
import { decrypt, encrypt, generateSigningKey, type SigningKey } from './crypto.ts';
import { type Db, transaction } from './db.ts';

export class KeyStore {
  private readonly signing = new Map<string, SigningKey>();
  private readonly config: Config;
  private readonly db: Db;

  constructor(db: Db, config: Config) {
    this.db = db;
    this.config = config;
  }

  async signingKey(appId: string): Promise<SigningKey> {
    const cached = this.signing.get(appId);
    if (cached) return cached;
    const key = await transaction(this.db, async (tx) => {
      await tx.query('SELECT pg_advisory_xact_lock(727274002, hashtext($1))', [appId]);
      const row = await tx.query(
        'SELECT key_id, public_jwk, private_enc FROM ea_signing_keys WHERE app_id = $1 ORDER BY created_at DESC LIMIT 1', [appId]);
      if (row.rowCount === 1) {
        return { keyId: row.rows[0].key_id, publicJwk: row.rows[0].public_jwk,
          privatePem: decrypt(this.config.keyEncryptionKey, row.rows[0].private_enc) } as SigningKey;
      }
      const created = generateSigningKey();
      await tx.query(
        `INSERT INTO ea_signing_keys (app_id, key_id, algorithm, public_jwk, private_enc, created_at)
         VALUES ($1, $2, 'RS256', $3, $4, $5)`,
        [appId, created.keyId, created.publicJwk, encrypt(this.config.keyEncryptionKey, created.privatePem), Date.now()]);
      return created;
    });
    this.signing.set(appId, key);
    return key;
  }

  /** Public verification keys for an app (JWKS). Never includes private material. */
  async publicKeys(appId: string): Promise<Array<Record<string, string>>> {
    const rows = await this.db.query('SELECT public_jwk FROM ea_signing_keys WHERE app_id = $1 ORDER BY created_at DESC', [appId]);
    return rows.rows.map((r) => r.public_jwk);
  }
}
