// The Windows app's own database: PostgreSQL compiled to WebAssembly (PGlite), stored in the app's data folder.
// It offers the one call the shared API code (../api/index.js) uses from @neondatabase/serverless:
// sql`...${value}...` tagged templates that return the result rows. Nothing here talks to the network.
import { PGlite } from '@electric-sql/pglite';

let pg = null;
export function open(dir) {
  pg ??= (async () => { const db = new PGlite(dir); await db.waitReady; return db; })().catch(e => { pg = null; throw e; });
  return pg;
}
export async function close() { if (pg) { const db = await pg.catch(() => null); pg = null; if (db) await db.close(); } }

export function neon() {
  return async (strings, ...values) => {
    let text = strings[0];
    values.forEach((_, i) => { text += '$' + (i + 1) + strings[i + 1]; });
    if (!pg) throw new Error('The local database is not open.');
    return (await (await pg).query(text, values)).rows;
  };
}
