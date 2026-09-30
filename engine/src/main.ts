import { loadConfig } from './config.ts';
import { createPool, migrate } from './db.ts';
import { createEngineServer, type Engine } from './http/server.ts';
import { KeyStore } from './keys.ts';
import { Sessions } from './sessions.ts';

export async function startEngine(env: NodeJS.ProcessEnv = process.env) {
  const config = loadConfig(env);
  const db = createPool(config.databaseUrl);
  await migrate(db);
  const keys = new KeyStore(db, config);
  const engine: Engine = { db, config, keys, sessions: new Sessions(db, config, keys) };
  const server = createEngineServer(engine);
  await new Promise<void>((resolve) => server.listen(config.port, config.host, resolve));
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : config.port;
  return {
    engine, port,
    async close() {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await db.end();
    },
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const running = await startEngine();
  console.log(`[expertauth] engine listening on ${running.port}`);
  for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => void running.close().then(() => process.exit(0)));
}
