import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import pg from 'pg';

/** Minimal query interface, satisfied by pg.Pool and by PGlite (tests). */
export interface Db {
  query<T = any>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
}

export function createPgDb(url: string): Db & { end(): Promise<void> } {
  // Respect the managed connection string's TLS configuration; never disable
  // certificate validation for external databases.
  const pool = new pg.Pool({ connectionString: url, max: 10 });
  // BIGINT comes back as string; keep it that way and convert explicitly.
  return pool as unknown as Db & { end(): Promise<void> };
}

const here = dirname(fileURLToPath(import.meta.url));
export async function migrate(db: Db & { exec?: (sql: string) => Promise<unknown> }) {
  const dir = join(here, '..', 'sql');
  for (const name of readdirSync(dir).filter(n => /^\d+_.*\.sql$/.test(n)).sort()) {
    const sql = readFileSync(join(dir, name), 'utf8');
    if (db.exec) await db.exec(sql);
    else await db.query(sql);
  }
}
