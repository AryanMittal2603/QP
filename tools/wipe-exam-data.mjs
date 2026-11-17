// Deletes ALL exam data from the database: exams (with their shifts, subjects and colours), rolls, final-iteration draws,
// audit logs uploaded by Randomization PCs, PC sync records and sync conflicts.
// Kept: logins (Admin / Randomizer / Approver), sign-up requests, settings and logo, and the server audit log,
// where the wipe itself is recorded. Randomization PCs that still hold data from before the wipe are refused at
// sync until someone uses "Clear this PC" on them.
//
// With --logins it also deletes every login (Admins, Controller of Examinations, Chairman, and the old mobile-number,
// Approver and shared logins) and puts back only the built-in Verifier (upessc_verifier / upessc@2026, which must be
// changed at the first sign-in).
//
// Usage (asks you to type DELETE first):   DATABASE_URL=postgres://... node tools/wipe-exam-data.mjs [--logins]
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

const tableExists = async (sql, t) => (await sql`select to_regclass(${'public.' + t}) as r`)[0].r !== null;
/* Every login goes; only the built-in Verifier comes back (same defaults as api/index.js) */
export async function wipeLogins(sql) {
  const gone = {};
  // the old mobile-number / OTP / Approver / username tables are no longer used
  if (await tableExists(sql, 'users')) { gone.users = (await sql`select count(*)::int n from users`)[0].n; await sql`drop table users`; }
  if (await tableExists(sql, 'access_requests')) { gone.access_requests = (await sql`select count(*)::int n from access_requests`)[0].n; await sql`drop table access_requests`; }
  if (await tableExists(sql, 'otps')) { gone.otps = (await sql`select count(*)::int n from otps`)[0].n; await sql`drop table otps`; }
  if (await tableExists(sql, 'admins')) { gone.admins = (await sql`select count(*)::int n from admins`)[0].n; await sql`drop table admins`; }
  await sql`create table if not exists accounts (username text primary key, role text not null, name text, designation text, salt text, hash text, status text not null default 'active',
    must_change boolean not null default false, created_at timestamptz default now(), created_by text, updated_at timestamptz, last_login timestamptz)`;
  gone.accounts = (await sql`select count(*)::int n from accounts`)[0].n;
  await sql`truncate table accounts`;
  await sql`delete from settings where key in ('client_cred', 'verifiers')`;
  const salt = crypto.randomBytes(16).toString('base64'), hash = crypto.pbkdf2Sync('upessc@2026', Buffer.from(salt, 'base64'), 150000, 32, 'sha256').toString('base64');
  await sql`insert into accounts (username, role, name, designation, salt, hash, status, must_change, created_by) values ('upessc_verifier', 'verifier', 'Verifier', '', ${salt}, ${hash}, 'active', true, 'built-in')`;
  return gone;
}

export async function wipe(sql, actor, { logins = false } = {}) {
  const before = await counts(sql);
  await sql`truncate table draws, final_choices, client_audit, sync_status, sync_conflicts, exams restart identity`;   // one statement: all or nothing
  const at = Date.now();
  await sql`insert into settings (key, value, updated_at) values ('data_reset', ${JSON.stringify({ at, by: actor, deleted: before })}::jsonb, now())
    on conflict (key) do update set value = excluded.value, updated_at = now()`;
  const loginsDeleted = logins ? await wipeLogins(sql) : null;
  const entry = await auditLog(sql, actor, 'EXAM_DATA_WIPED', { deleted: before, ...(logins ? { loginsDeleted, loginsNow: 'only the built-in Verifier (default password, must be changed)' } : {}),
    kept: logins ? 'settings and logo, server audit log' : 'logins, settings and logo, server audit log',
    note: 'Randomization PCs holding data from before this wipe are refused at sync until "Clear this PC" is used on them' });
  return { before, after: await counts(sql), at, entry };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (!process.env.DATABASE_URL) { console.error('Set DATABASE_URL first.'); process.exit(1); }
  const sql = neon(process.env.DATABASE_URL);
  const logins = process.argv.includes('--logins');
  const c = await counts(sql);
  console.log('\nThis will permanently delete from the live database:');
  for (const [k, v] of Object.entries(c)) console.log(`  ${k.padEnd(16)} ${v}`);
  if (logins) console.log('  and EVERY login. Only the built-in Verifier remains: upessc_verifier / upessc@2026 (must be changed at the first sign-in).');
  console.log(logins ? '\nKept: settings and logo, and the server audit log.' : '\nKept: all logins, settings and logo, and the server audit log.');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ans = (await rl.question('\nType DELETE to go ahead (anything else cancels): ')).trim(); rl.close();
  if (ans !== 'DELETE') { console.log('Cancelled. Nothing was deleted.'); process.exit(0); }
  const r = await wipe(sql, process.env.WIPE_ACTOR || 'maintenance script', { logins });
  console.log('\nDone. Left in the database:', JSON.stringify(r.after));
  console.log(`Recorded in the server audit log as entry #${r.entry.seq} (EXAM_DATA_WIPED).`);
}
