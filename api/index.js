// UPESSC QP Randomization — single API function (all routes), backed by Neon Postgres.
import { neon } from '@neondatabase/serverless';
import crypto from 'node:crypto';

const sql = neon(process.env.DATABASE_URL);
const SECRET = process.env.AUTH_SECRET;
const ITER = 150000;
const MAX_ATTEMPTS = 7;   // Mode A uses 5; Mode B lets the client lock 3–7 for the whole exam
const FINAL_MODES = new Set(['fixed5', 'client']);

/* ---------------- helpers ---------------- */
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const fail = (status, msg) => { throw new HttpError(status, msg); };

function stable(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']';
  return '{' + Object.keys(v).sort().filter(k => v[k] !== undefined).map(k => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}';
}
const sha256 = s => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const hashPw = (pw, saltB64) => crypto.pbkdf2Sync(pw, Buffer.from(saltB64, 'base64'), ITER, 32, 'sha256').toString('base64');
function makeCred(username, pw) { const salt = crypto.randomBytes(16).toString('base64'); return { username, salt, hash: hashPw(pw, salt) }; }
function checkPw(cred, pw) {
  if (!cred || typeof pw !== 'string') return false;
  const a = Buffer.from(hashPw(pw, cred.salt)), b = Buffer.from(cred.hash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const istTime = ts => new Date(ts).toLocaleString('en-GB', { timeZone: 'Asia/Kolkata', hour12: false }).replace(',', '');

const b64u = b => Buffer.from(b).toString('base64url');
function sign(payload) { const body = b64u(JSON.stringify(payload)); return body + '.' + crypto.createHmac('sha256', SECRET).update(body).digest('base64url'); }
function verifyToken(tok) {
  if (!tok || !tok.includes('.')) return null;
  const [body, sig] = tok.split('.');
  const exp = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (sig.length !== exp.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(exp))) return null;
  const p = JSON.parse(Buffer.from(body, 'base64url').toString());
  return p.exp > Date.now() ? p : null;
}
function auth(req, role) {
  const p = verifyToken((req.headers.authorization || '').replace(/^Bearer /, ''));
  if (!p || p.role !== role) fail(401, 'Session expired. Please log in again.');
  return p;
}
const str = (v, max = 200) => typeof v === 'string' && v.trim() && v.length <= max ? v.trim() : null;

/* ---------------- schema ---------------- */
let schemaReady;
function ensureSchema() {
  schemaReady ??= (async () => {
    await sql`create table if not exists admins (username text primary key, salt text not null, hash text not null, created_at timestamptz default now())`;
    await sql`create table if not exists settings (key text primary key, value jsonb not null, updated_at timestamptz default now())`;
    await sql`create table if not exists exams (id text primary key, doc jsonb not null, published_version int not null default 0, published_doc jsonb, published_at timestamptz, deleted boolean not null default false, updated_at timestamptz default now())`;
    await sql`create table if not exists admin_audit (seq int primary key, ts bigint not null, entry jsonb not null, hash text not null)`;
    await sql`create table if not exists client_audit (install_id text not null, seq int not null, entry jsonb not null, hash text not null, received_at timestamptz default now(), primary key (install_id, seq))`;
    await sql`create table if not exists draws (key text primary key, install_id text not null, exam_id text not null, shift_id text not null, subject_id text not null, attempt int not null, draw jsonb not null, log_hash text not null, received_at timestamptz default now())`;
    await sql`create table if not exists sync_status (install_id text primary key, actor text, last_sync timestamptz, entries int, chain_ok boolean, issues jsonb, head text)`;
    await sql`create table if not exists final_choices (exam_id text primary key, install_id text not null, final_attempt int not null, log_hash text not null, choice jsonb not null, received_at timestamptz default now())`;
    await sql`create table if not exists sync_conflicts (id serial primary key, install_id text, kind text, detail jsonb, created_at timestamptz default now())`;
  })().catch(e => { schemaReady = null; throw e; });
  return schemaReady;
}

/* ---------------- server-side hash-chained admin audit ---------------- */
async function adminLog(actor, event, details = {}) {
  for (let i = 0; i < 8; i++) {
    const [last] = await sql`select seq, hash from admin_audit order by seq desc limit 1`;
    const ts = Date.now();
    const entry = { seq: last ? last.seq + 1 : 1, ts, time: new Date(ts).toISOString(), localTime: istTime(ts), actor, console: 'admin', event,
      details: JSON.parse(JSON.stringify(details)), prevHash: last ? last.hash : 'GENESIS' };
    entry.hash = sha256(stable(entry));
    try { await sql`insert into admin_audit (seq, ts, entry, hash) values (${entry.seq}, ${ts}, ${JSON.stringify(entry)}::jsonb, ${entry.hash})`; return entry; }
    catch (e) { if (e.code !== '23505') throw e; await new Promise(r => setTimeout(r, 30 + Math.random() * 120)); }
  }
  fail(503, 'Audit log busy, retry.');
}
function verifyEntries(entries) {
  const issues = []; let prev = 'GENESIS';
  entries.forEach((e, i) => {
    if (e.seq !== i + 1) issues.push(`Sequence gap at entry #${e.seq}`);
    if (e.prevHash !== prev) issues.push(`Broken chain link at entry #${e.seq}`);
    const { hash, ...rest } = e;
    if (sha256(stable(rest)) !== hash) issues.push(`Entry #${e.seq} has been altered`);
    prev = hash;
  });
  return { ok: !issues.length, issues, head: prev };
}

/* ---------------- validation ---------------- */
function validateExam(doc) {
  if (!doc || !str(doc.id, 64) || !str(doc.name) || !str(doc.code, 60) || !Array.isArray(doc.shifts)) fail(400, 'Invalid exam document.');
  if (doc.finalMode !== undefined && !FINAL_MODES.has(doc.finalMode)) fail(400, 'Invalid final selection mode.');
  for (const s of doc.shifts) {
    if (!str(s.id, 64) || !str(s.name) || !/^\d{4}-\d{2}-\d{2}$/.test(s.date) || !/^\d{2}:\d{2}$/.test(s.start) || !/^\d{2}:\d{2}$/.test(s.end) || s.end <= s.start || !Array.isArray(s.subjects)) fail(400, `Invalid shift "${s.name}".`);
    for (const b of s.subjects) {
      if (!str(b.id, 64) || !str(b.name) || !Array.isArray(b.colours)) fail(400, `Invalid subject in "${s.name}".`);
      if (b.colours.some(c => !str(c.name, 60) || !/^#[0-9a-fA-F]{6}$/.test(c.hex))) fail(400, `Invalid colour set in "${b.name}".`);
    }
  }
  if (JSON.stringify(doc).length > 500000) fail(413, 'Exam document too large.');
}
function publishProblems(doc) {
  const p = [];
  if (!doc.shifts.length) p.push('Add at least one shift.');
  doc.shifts.forEach(s => { if (!s.subjects.length) p.push(`${s.name}: add at least one subject.`); s.subjects.forEach(b => { if (b.colours.length < 2) p.push(`${s.name} / ${b.name}: needs at least 2 colour sets.`); }); });
  return p;
}
const EXAM_EVENTS = new Set(['EXAM_CREATED', 'EXAM_UPDATED', 'SHIFT_CREATED', 'SHIFT_UPDATED', 'SHIFT_DUPLICATED', 'SHIFT_DELETED', 'SUBJECT_CREATED', 'SUBJECT_UPDATED', 'SUBJECT_DELETED']);
const getSetting = async k => (await sql`select value from settings where key = ${k}`)[0]?.value ?? null;
const putSetting = (k, v) => sql`insert into settings (key, value, updated_at) values (${k}, ${JSON.stringify(v)}::jsonb, now()) on conflict (key) do update set value = excluded.value, updated_at = now()`;

/* ---------------- routes ---------------- */
const routes = {
  'GET status': async () => ({ adminExists: (await sql`select count(*)::int n from admins`)[0].n > 0, serverTime: Date.now() }),

  'POST setup': async ({ body }) => {
    if (!process.env.SETUP_KEY || body.setupKey !== process.env.SETUP_KEY) fail(403, 'Invalid setup key.');
    if ((await sql`select count(*)::int n from admins`)[0].n > 0) fail(409, 'An administrator already exists.');
    const u = str(body.username, 60); if (!u || typeof body.password !== 'string' || body.password.length < 8) fail(400, 'Username and a password of at least 8 characters are required.');
    const c = makeCred(u, body.password);
    await sql`insert into admins (username, salt, hash) values (${u}, ${c.salt}, ${c.hash})`;
    await adminLog(u, 'ADMIN_ACCOUNT_CREATED', { username: u });
    return { ok: true };
  },

  'POST admin/login': async ({ body }) => {
    const u = str(body.username, 60) || '';
    const [a] = await sql`select * from admins where username = ${u}`;
    if (!a || !checkPw(a, body.password)) { await adminLog(u || 'unknown', 'ADMIN_LOGIN_FAILED', { attemptedUsername: u }); fail(401, 'Invalid username or password.'); }
    await adminLog(u, 'ADMIN_LOGIN', { clientClock: body.clientClock || null });
    return { token: sign({ sub: u, role: 'admin', exp: Date.now() + 12 * 3600e3 }), user: u };
  },
  'POST admin/logout': async ({ user }) => { await adminLog(user, 'LOGOUT', {}); return { ok: true }; },

  'GET admin/exams': async () => {
    const rows = await sql`select doc, published_version, published_at, (published_doc is not null and published_doc <> doc) as changed from exams where not deleted order by updated_at desc`;
    return rows.map(r => ({ ...r.doc, publishedVersion: r.published_version, publishedAt: r.published_at ? new Date(r.published_at).getTime() : null, changedSincePublish: !!r.changed }));
  },
  'PUT admin/exams': async ({ body, user }) => {
    const { exam, event, details } = body;
    if (!EXAM_EVENTS.has(event)) fail(400, 'Unknown event.');
    const { publishedVersion, publishedAt, changedSincePublish, ...doc } = exam || {};
    doc.updatedAt = Date.now();
    validateExam(doc);
    const [ex] = await sql`select deleted, doc from exams where id = ${doc.id}`;
    if (ex && ex.deleted) fail(410, 'Exam was deleted.');
    if (ex && (ex.doc.finalMode || 'fixed5') !== (doc.finalMode || 'fixed5')) {
      const [{ n }] = await sql`select (select count(*) from draws where exam_id = ${doc.id}) + (select count(*) from final_choices where exam_id = ${doc.id}) as n`;
      if (Number(n) > 0) fail(409, 'The final selection mode cannot be changed after randomization has started for this exam.');
    }
    await sql`insert into exams (id, doc, updated_at) values (${doc.id}, ${JSON.stringify(doc)}::jsonb, now()) on conflict (id) do update set doc = excluded.doc, updated_at = now()`;
    await adminLog(user, event, { examId: doc.id, examCode: doc.code, ...(details || {}) });
    return { ok: true };
  },
  'DELETE admin/exams': async ({ query, user }) => {
    const [ex] = await sql`update exams set deleted = true, updated_at = now() where id = ${query.id} returning doc`;
    if (!ex) fail(404, 'Exam not found.');
    await adminLog(user, 'EXAM_DELETED', { examId: query.id, name: ex.doc.name, code: ex.doc.code });
    return { ok: true };
  },
  'POST admin/publish': async ({ body, user }) => {
    const [ex] = await sql`select * from exams where id = ${body.id} and not deleted`;
    if (!ex) fail(404, 'Exam not found.');
    const p = publishProblems(ex.doc); if (p.length) fail(400, p.join('\n'));
    if (!(await getSetting('client_cred'))) fail(400, 'Set the Randomization Console login in Settings first.');
    const v = ex.published_version + 1;
    await sql`update exams set published_version = ${v}, published_doc = doc, published_at = now() where id = ${body.id}`;
    await adminLog(user, 'EXAM_PUBLISHED', { examId: ex.id, examCode: ex.doc.code, publishedVersion: v, docSha256: sha256(stable(ex.doc)),
      shifts: ex.doc.shifts.map(s => ({ id: s.id, name: s.name, date: s.date, window: `${s.start}-${s.end}`, subjects: s.subjects.length })) });
    return { publishedVersion: v };
  },
  'POST admin/unpublish': async ({ body, user }) => {
    const [ex] = await sql`update exams set published_doc = null, published_at = null where id = ${body.id} returning doc, published_version`;
    if (!ex) fail(404, 'Exam not found.');
    await adminLog(user, 'EXAM_UNPUBLISHED', { examId: body.id, examCode: ex.doc.code });
    return { ok: true };
  },
  'POST admin/package-logged': async ({ body, user }) => {
    await adminLog(user, 'OFFLINE_PACKAGE_EXPORTED', { examId: str(body.examId, 64), examCode: str(body.examCode, 60), packageVersion: body.packageVersion, packageSha256: str(body.packageSha256, 64) });
    return { ok: true };
  },

  'GET admin/settings': async () => {
    const cred = await getSetting('client_cred');
    return { clientCred: cred, logo: await getSetting('logo') };
  },
  'POST admin/client-cred': async ({ body, user }) => {
    const u = str(body.username, 60); if (!u || typeof body.password !== 'string' || body.password.length < 8) fail(400, 'Username and a password of at least 8 characters are required.');
    await putSetting('client_cred', makeCred(u, body.password));
    await adminLog(user, 'CLIENT_CREDENTIALS_SET', { username: u });
    return { ok: true };
  },
  'POST admin/logo': async ({ body, user }) => {
    if (body.logo === null) { await sql`delete from settings where key = 'logo'`; await adminLog(user, 'LOGO_REMOVED', {}); return { ok: true }; }
    if (typeof body.logo !== 'string' || !/^data:image\/(png|jpeg|svg\+xml);base64,/.test(body.logo) || body.logo.length > 700000) fail(400, 'Logo must be a PNG/JPG/SVG of 500 KB or less.');
    await putSetting('logo', body.logo);
    await adminLog(user, 'LOGO_UPDATED', { sha256: sha256(body.logo), bytes: body.logo.length });
    return { ok: true };
  },
  'POST admin/password': async ({ body, user }) => {
    const [a] = await sql`select * from admins where username = ${user}`;
    if (!checkPw(a, body.old)) fail(400, 'Current password is incorrect.');
    if (typeof body.password !== 'string' || body.password.length < 8) fail(400, 'Password must be at least 8 characters.');
    const c = makeCred(user, body.password);
    await sql`update admins set salt = ${c.salt}, hash = ${c.hash} where username = ${user}`;
    await adminLog(user, 'ADMIN_PASSWORD_CHANGED', {});
    return { ok: true };
  },
  'GET admin/audit': async () => {
    const entries = (await sql`select entry from admin_audit order by seq`).map(r => r.entry);
    return { entries, verification: verifyEntries(entries) };
  },
  'GET admin/results': async () => ({
    draws: (await sql`select key, install_id, draw, received_at from draws order by received_at`).map(r => ({ ...r.draw, installId: r.install_id, receivedAt: new Date(r.received_at).getTime() })),
    syncs: await sql`select install_id, actor, last_sync, entries, chain_ok, issues, head from sync_status order by last_sync desc`,
    conflicts: await sql`select id, install_id, kind, detail, created_at from sync_conflicts order by id desc limit 200`,
    exams: (await sql`select doc from exams where not deleted`).map(r => r.doc),
    choices: await sql`select exam_id, install_id, final_attempt, choice, received_at from final_choices`,
  }),
  'GET admin/client-audit': async ({ query }) => {
    const entries = (await sql`select entry from client_audit where install_id = ${query.installId} order by seq`).map(r => r.entry);
    return { entries, verification: verifyEntries(entries) };
  },

  /* ----- Randomization console ----- */
  'POST client/login': async ({ body }) => {
    const cred = await getSetting('client_cred');
    const u = str(body.username, 60) || '';
    if (!cred || u !== cred.username || !checkPw(cred, body.password)) { await adminLog(u || 'unknown', 'CLIENT_ONLINE_LOGIN_FAILED', { attemptedUsername: u, installId: str(body.installId, 64) }); fail(401, 'Invalid username or password.'); }
    const exams = (await sql`select published_doc, published_version, published_at from exams where not deleted and published_doc is not null`)
      .map(r => ({ ...r.published_doc, packageVersion: r.published_version, exportedAt: new Date(r.published_at).toISOString() }));
    await adminLog(u, 'CLIENT_ONLINE_LOGIN', { installId: str(body.installId, 64), examsDownloaded: exams.map(e => ({ code: e.code, version: e.packageVersion })), clientClock: body.clientClock || null });
    return { token: sign({ sub: u, role: 'client', exp: Date.now() + 14 * 86400e3 }), cred, exams, logo: await getSetting('logo'), serverTime: Date.now() };
  },
  'POST client/sync': async ({ body, user }) => {
    const installId = str(body.installId, 64); if (!installId) fail(400, 'Missing install id.');
    const entries = Array.isArray(body.entries) ? body.entries.sort((a, b) => a.seq - b.seq) : [];
    const draws = Array.isArray(body.draws) ? body.draws : [];
    const choices = Array.isArray(body.choices) ? body.choices : [];
    if (entries.length > 20000) fail(413, 'Too many entries.');
    const v = verifyEntries(entries);
    const conflicts = [];
    if (!v.ok) {
      // A broken chain is never stored; the attempt itself is recorded for the admin.
      await sql`insert into sync_conflicts (install_id, kind, detail) values (${installId}, 'CHAIN_INVALID_UPLOAD_REJECTED', ${JSON.stringify({ issues: v.issues.slice(0, 50), actor: user })}::jsonb)`;
      return { ok: false, chainOk: false, issues: v.issues, conflicts: [{ kind: 'CHAIN_INVALID_UPLOAD_REJECTED' }], entries: 0, draws: 0, syncedAt: Date.now() };
    }
    if (entries.length) {
      await sql`insert into client_audit (install_id, seq, entry, hash) select ${installId}, (e->>'seq')::int, e, e->>'hash' from jsonb_array_elements(${JSON.stringify(entries)}::jsonb) e on conflict do nothing`;
      const stored = new Map((await sql`select seq, hash from client_audit where install_id = ${installId}`).map(r => [r.seq, r.hash]));
      entries.forEach(e => { if (stored.get(e.seq) !== e.hash) conflicts.push({ kind: 'AUDIT_ENTRY_CHANGED', detail: { seq: e.seq, serverHash: stored.get(e.seq), clientHash: e.hash } }); });
    }
    // Draws are only accepted if they are backed by a matching, verified audit entry.
    const bySeq = new Map(entries.map(e => [e.seq, e]));
    const valid = draws.filter(d => { const e = bySeq.get(d.logSeq); return e && e.event === 'RANDOMIZATION_DRAW' && e.hash === d.logHash && e.details.key === d.key && e.details.colourIndex === d.colourIndex && d.attempt >= 1 && d.attempt <= MAX_ATTEMPTS; });
    if (valid.length !== draws.length) conflicts.push({ kind: 'UNVERIFIED_DRAWS_REJECTED', detail: { count: draws.length - valid.length } });
    if (valid.length) {
      await sql`insert into draws (key, install_id, exam_id, shift_id, subject_id, attempt, draw, log_hash)
        select d->>'key', ${installId}, d->>'examId', d->>'shiftId', d->>'subjectId', (d->>'attempt')::int, d, d->>'logHash' from jsonb_array_elements(${JSON.stringify(valid)}::jsonb) d on conflict (key) do nothing`;
      const stored = new Map((await sql`select key, install_id, log_hash from draws where key = any(${valid.map(d => d.key)})`).map(r => [r.key, r]));
      valid.forEach(d => { const s = stored.get(d.key); if (s.install_id !== installId || s.log_hash !== d.logHash) conflicts.push({ kind: 'DUPLICATE_DRAW_CONFLICT', detail: { key: d.key, subject: d.subjectName, attempt: d.attempt, acceptedFrom: s.install_id, rejectedFrom: installId } }); });
    }
    // Final-iteration choices (Mode B) are accepted only when backed by a matching audit entry.
    const okChoices = choices.filter(c => { const e = bySeq.get(c.logSeq); return e && e.event === 'FINAL_ITERATION_CHOSEN' && e.hash === c.logHash && e.details.examId === c.examId && e.details.finalAttempt === c.finalAttempt && c.finalAttempt >= 3 && c.finalAttempt <= MAX_ATTEMPTS; });
    if (okChoices.length !== choices.length) conflicts.push({ kind: 'UNVERIFIED_CHOICES_REJECTED', detail: { count: choices.length - okChoices.length } });
    for (const c of okChoices) {
      await sql`insert into final_choices (exam_id, install_id, final_attempt, log_hash, choice) values (${c.examId}, ${installId}, ${c.finalAttempt}, ${c.logHash}, ${JSON.stringify(c)}::jsonb) on conflict (exam_id) do nothing`;
      const [st] = await sql`select install_id, final_attempt, log_hash from final_choices where exam_id = ${c.examId}`;
      if (st.log_hash !== c.logHash) conflicts.push({ kind: 'FINAL_CHOICE_CONFLICT', detail: { examId: c.examId, accepted: st.final_attempt, acceptedFrom: st.install_id, rejected: c.finalAttempt, rejectedFrom: installId } });
    }
    for (const c of conflicts) await sql`insert into sync_conflicts (install_id, kind, detail) values (${installId}, ${c.kind}, ${JSON.stringify(c.detail)}::jsonb)`;
    await sql`insert into sync_status (install_id, actor, last_sync, entries, chain_ok, issues, head) values (${installId}, ${user}, now(), ${entries.length}, ${v.ok}, ${JSON.stringify(v.issues)}::jsonb, ${v.head})
      on conflict (install_id) do update set actor = excluded.actor, last_sync = now(), entries = excluded.entries, chain_ok = excluded.chain_ok, issues = excluded.issues, head = excluded.head`;
    return { ok: v.ok && !conflicts.length, chainOk: v.ok, issues: v.issues, conflicts, entries: entries.length, draws: valid.length, choices: okChoices.length, syncedAt: Date.now() };
  },
};

export default async function handler(req, res) {
  try {
    if (!SECRET || !process.env.DATABASE_URL) fail(500, 'Server is not configured.');
    await ensureSchema();
    const path = String(req.query.path || '').replace(/^\/+|\/+$/g, '');
    const fn = routes[`${req.method} ${path}`];
    if (!fn) fail(404, 'Not found.');
    const ctx = { body: req.body || {}, query: req.query || {} };
    if (path.startsWith('admin/') && path !== 'admin/login') ctx.user = auth(req, 'admin').sub;
    if (path === 'client/sync') ctx.user = auth(req, 'client').sub;
    res.status(200).json(await fn(ctx));
  } catch (e) {
    const status = e.status || 500;
    if (status === 500) console.error(e);
    res.status(status).json({ error: status === 500 ? 'Server error.' : e.message });
  }
}
