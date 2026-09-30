import { readFileSync } from 'node:fs';
import pg from 'pg';

export type Db = pg.Pool;
export type Tx = pg.PoolClient;

const SCHEMA_VERSION = 1;

export function createPool(url: string): Db {
  const pool = new pg.Pool({ connectionString: url, max: 20 });
  // An idle client dropped by the server (restart, failover, admin termination) must not crash
  // the engine; pg discards the client and the next query opens a fresh connection.
  pool.on('error', (error) => console.error('[expertauth] idle database connection lost:', error.message));
  return pool;
}

/** Runs fn in one READ COMMITTED transaction; row locks (SELECT ... FOR UPDATE) provide ordering. */
export async function transaction<T>(db: Db, fn: (tx: Tx) => Promise<T>): Promise<T> {
  const tx = await db.connect();
  try {
    await tx.query('BEGIN');
    const result = await fn(tx);
    await tx.query('COMMIT');
    return result;
  } catch (error) {
    await tx.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    tx.release();
  }
}

/** Idempotent schema install under an advisory lock so concurrent replicas cannot race. */
export async function migrate(db: Db): Promise<void> {
  const schema = readFileSync(new URL('./schema.sql', import.meta.url), 'utf8');
  await transaction(db, async (tx) => {
    await tx.query('SELECT pg_advisory_xact_lock(727274001)');
    await tx.query(schema);
    await tx.query('INSERT INTO ea_schema_version (version) VALUES ($1) ON CONFLICT DO NOTHING', [SCHEMA_VERSION]);
    const now = Date.now();
    await tx.query("INSERT INTO ea_apps (app_id, created_at) VALUES ('public', $1) ON CONFLICT DO NOTHING", [now]);
    await tx.query("INSERT INTO ea_tenants (app_id, tenant_id, created_at) VALUES ('public', 'public', $1) ON CONFLICT DO NOTHING", [now]);
  });
}
