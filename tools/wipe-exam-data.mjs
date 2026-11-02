// Deletes ALL exam data from the database: exams (with their shifts, subjects and colours), rolls, final-iteration draws,
// audit logs uploaded by Randomization PCs, PC sync records and sync conflicts.
// Kept: logins (Admin / Randomizer / Approver), sign-up requests, settings and logo, and the server audit log,
// where the wipe itself is recorded. Randomization PCs that still hold data from before the wipe are refused at
// sync until someone uses "Clear this PC" on them.
//
// Usage (asks you to type DELETE first):   DATABASE_URL=postgres://... node tools/wipe-exam-data.mjs
import { neon } from '@neondatabase/serverless';
import crypto from 'node:crypto';
import readline from 'node:readline/promises';
import { pathToFileURL } from 'node:url';

const stable = v => v === null || typeof v !== 'object' ? JSON.stringify(v) : Array.isArray(v) ? '[' + v.map(stable).join(',') + ']'
  : '{' + Object.keys(v).sort().filter(k => v[k] !== undefined).map(k => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}';
const sha256 = s => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const istTime = ts => new Date(ts).toLocaleString('en-GB', { timeZone: 'Asia/Kolkata', hour12: false }).replace(',', '');

export async function counts(sql) {
  const n = async q => (await q)[0].n;
  return {
    exams: await n(sql`select count(*)::int n from exams`),
    rolls: await n(sql`select count(*)::int n from draws`),
    finalIterations: await n(sql`select count(*)::int n from final_choices`),
    pcAuditEntries: await n(sql`select count(*)::int n from client_audit`),
    pcSyncRecords: await n(sql`select count(*)::int n from sync_status`),
    syncConflicts: await n(sql`select count(*)::int n from sync_conflicts`)
  };
}

/* Same entry format and hash chain as adminLog() in api/index.js */
async function auditLog(sql, actor, event, details) {
  for (let i = 0; i < 8; i++) {
    const [last] = await sql`select seq, hash from admin_audit order by seq desc limit 1`;
    const ts = Date.now();
    const entry = { seq: last ? last.seq + 1 : 1, ts, time: new Date(ts).toISOString(), localTime: istTime(ts), actor, console: 'admin', event, details, prevHash: last ? last.hash : 'GENESIS' };
    entry.hash = sha256(stable(entry));
    try { await sql`insert into admin_audit (seq, ts, entry, hash) values (${entry.seq}, ${ts}, ${JSON.stringify(entry)}::jsonb, ${entry.hash})`; return entry; }
    catch (e) { if (e.code !== '23505') throw e; await new Promise(r => setTimeout(r, 100)); }
  }
  throw new Error('Audit log busy; the data was deleted but the wipe could not be recorded.');
}

export async function wipe(sql, actor) {
  const before = await counts(sql);
  await sql`truncate table draws, final_choices, client_audit, sync_status, sync_conflicts, exams restart identity`;   // one statement: all or nothing
  const at = Date.now();
  await sql`insert into settings (key, value, updated_at) values ('data_reset', ${JSON.stringify({ at, by: actor, deleted: before })}::jsonb, now())
    on conflict (key) do update set value = excluded.value, updated_at = now()`;
  const entry = await auditLog(sql, actor, 'EXAM_DATA_WIPED', { deleted: before, kept: 'logins, sign-up requests, settings and logo, server audit log',
    note: 'Randomization PCs holding data from before this wipe are refused at sync until "Clear this PC" is used on them' });
  return { before, after: await counts(sql), at, entry };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (!process.env.DATABASE_URL) { console.error('Set DATABASE_URL first.'); process.exit(1); }
  const sql = neon(process.env.DATABASE_URL);
  const c = await counts(sql);
  console.log('\nThis will permanently delete from the live database:');
  for (const [k, v] of Object.entries(c)) console.log(`  ${k.padEnd(16)} ${v}`);
  console.log('\nKept: all logins, sign-up requests, settings and logo, and the server audit log.');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ans = (await rl.question('\nType DELETE to go ahead (anything else cancels): ')).trim(); rl.close();
  if (ans !== 'DELETE') { console.log('Cancelled. Nothing was deleted.'); process.exit(0); }
  const r = await wipe(sql, process.env.WIPE_ACTOR || 'maintenance script');
  console.log('\nDone. Left in the database:', JSON.stringify(r.after));
  console.log(`Recorded in the server audit log as entry #${r.entry.seq} (EXAM_DATA_WIPED).`);
}
