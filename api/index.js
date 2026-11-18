// UPESSC QP Randomization — single API function (all routes), backed by Neon Postgres online,
// or by a local database inside the Windows app (QPR_LOCAL=1, see desktop/main.js).
import { neon } from '@neondatabase/serverless';
import crypto from 'node:crypto';

const sql = neon(process.env.DATABASE_URL);
const SECRET = process.env.AUTH_SECRET;
const ITER = 150000;
const MAX_ATTEMPTS = 7;   // Mode A uses 5; Mode B draws 3–7 at random on the Randomization PC for the whole exam
const FINAL_MODES = new Set(['fixed5', 'client', 'best5']);   // 'client' = final iteration drawn at random on the PC; 'best5' = most frequent colour of 5 spins
const FINAL_EVENTS = new Set(['FINAL_ITERATION_RANDOMIZED', 'FINAL_ITERATION_CHOSEN']);   // CHOSEN = older manual choice, still accepted

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
  if (!sig || sig.length !== exp.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(exp))) return null;
  let p; try { p = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch { return null; }
  return p.exp > Date.now() ? p : null;
}
/* Session check. The account behind every token is re-checked on each request, so a disabled login stops working at once,
   a changed or reset password ends the sessions opened with the old one, and a login that still has to change its
   default password can do nothing else first. */
async function auth(req, role, path) {
  const p = verifyToken((req.headers.authorization || '').replace(/^Bearer /, ''));
  if (!p || (role !== 'any' && p.role !== role)) fail(401, 'Session expired. Please log in again.');
  const a = await getAccount(p.sub);
  if (!a || a.role !== TOKEN_ACCOUNT_ROLE[p.role] || a.status !== 'active') fail(401, 'Your login is no longer active. Please contact the Verifier.');
  if (p.pv !== passwordVersion(a)) fail(401, 'The password of this login was changed. Please log in again.');
  if (p.role === 'client') {   // Randomizer: the Chairman's login must still be active with the same password too
    const c = await getAccount('chairman');
    if (!c || c.role !== 'chairman' || c.status !== 'active') fail(401, 'The Chairman login is no longer active. Please contact the Verifier.');
    if (p.pv2 !== passwordVersion(c)) fail(401, 'A committee password was changed. The Controller of Examinations and the Chairman must sign in again.');
  }
  if (a.must_change && path !== 'auth/password') fail(403, 'Please change the default password first.');
  return p;
}
const str = (v, max = 200) => typeof v === 'string' && v.trim() && v.length <= max ? v.trim() : null;

/* ---------------- accounts: username + password, all created by the Verifier ----------------
   verifier  : one built-in login (upessc_verifier). Its default password must be changed at the first sign-in.
               Creates Admin logins and sets the two committee posts.
   admin     : sets up exams, publishes, sees results.
   coe       : Controller of Examinations: step 1 of the Randomizer sign-in (password only). The Randomizer page opens
               after step 2, with no Verifier login.
   chairman  : Chairman: step 2 of the Randomizer sign-in (password only).
   Accounts are re-checked on every request, so a disabled login or a changed password takes effect at once. */
const DEFAULT_VERIFIER = { username: 'upessc_verifier', password: 'upessc@2026' };
const POSTS = {
  coe: { label: 'Controller of Examinations', name: 'Shri Devendra Pratap Singh', designation: 'Controller of Examination, UPESSC, Prayagraj' },
  chairman: { label: 'Chairman', name: 'Dr. Prashant Kumar', designation: 'Honorable Chairman, UPESSC, Prayagraj' } };
const OLD_COE_DESIGNATION = 'Examination Controller, UPESSC, Prayagraj';   // before 3.0.2; saved copies of this default are updated
const ROLE_LABEL = { verifier: 'Verifier', admin: 'Admin', coe: POSTS.coe.label, chairman: POSTS.chairman.label };
const TOKEN_ACCOUNT_ROLE = { verifier: 'verifier', admin: 'admin', client: 'coe' };   // the Randomizer session belongs to the COE and the Chairman together (both re-checked)
const USERNAME_RE = /^[a-z0-9._-]{3,40}$/;
const getAccount = async username => (await sql`select * from accounts where username = ${String(username || '').toLowerCase()}`)[0] || null;
const publicAccount = a => ({ username: a.username, role: a.role, name: a.name, designation: a.designation || '', status: a.status, mustChange: !!a.must_change, hasPassword: !!a.hash,
  createdAt: a.created_at ? new Date(a.created_at).getTime() : null, createdBy: a.created_by || null, lastLogin: a.last_login ? new Date(a.last_login).getTime() : null });
const checkPassword = pw => { if (typeof pw !== 'string' || pw.length < 8 || pw.length > 200) fail(400, 'Password must be at least 8 characters.'); return pw; };
/* The built-in Verifier exists whenever there is no Verifier at all (fresh database, or after a full reset) */
async function ensureVerifier() {
  if ((await sql`select count(*)::int n from accounts where role = 'verifier'`)[0].n) return;
  const c = makeCred(DEFAULT_VERIFIER.username, DEFAULT_VERIFIER.password);
  await sql`insert into accounts (username, role, name, designation, salt, hash, status, must_change, created_by) values (${DEFAULT_VERIFIER.username}, 'verifier', 'Verifier', '', ${c.salt}, ${c.hash}, 'active', true, 'built-in') on conflict (username) do nothing`;
}
const committeeReady = async () => (await sql`select count(*)::int n from accounts where role in ('coe', 'chairman') and status = 'active' and hash is not null`)[0].n === 2;
const committeeInfo = async () => (await sql`select username, role, name, designation from accounts where role in ('coe', 'chairman') and status = 'active' and hash is not null`)
  .map(a => ({ post: a.role, label: POSTS[a.role].label, name: a.name, designation: a.designation || '' }));
const officerOf = (a, at) => ({ post: a.role, label: POSTS[a.role].label, name: a.name, designation: a.designation || '', at });
/* Randomizer sign-in step: the post's own password (one login per post) */
async function officerCheck(post, password, info, event) {
  if (process.env.QPR_LOCAL !== '1' && isDesktop(info) && verLess(info.device.appVersion, '3.0.0')) {
    await adminLog(post, `${event}_FAILED`, { reason: 'old Windows app', ...logInfo(info) });
    fail(403, 'This version of the Windows app no longer connects to the server. Install the new Windows app, which works on its own on one computer, or use the website.');
  }
  await ensureVerifier();
  const a = await getAccount(post), label = POSTS[post].label;
  if (!a || a.role !== post || !a.hash) fail(409, `The ${label} login is not set up yet. The Verifier sets it up (Other users → Verifier → Logins).`);
  if (a.status !== 'active') { await adminLog(post, `${event}_FAILED`, { reason: 'login disabled', ...logInfo(info) }); fail(403, `The ${label} login has been disabled by the Verifier.`); }
  if (typeof password !== 'string' || !checkPw(a, password)) { await adminLog(post, `${event}_FAILED`, { post: label, ...logInfo(info) }); fail(403, `Wrong password for the ${label}.`); }
  await sql`update accounts set last_login = now() where username = ${post}`;
  return a;
}
/* Username + password for one role; failures are logged and answered without saying which part was wrong */
async function accountLogin(roles, username, password, info, event) {
  // Windows apps before 3.0 talked to this server; 3.0 and later keep everything on their own computer
  if (process.env.QPR_LOCAL !== '1' && isDesktop(info) && verLess(info.device.appVersion, '3.0.0')) {
    await adminLog(String(username ?? '').trim().toLowerCase().slice(0, 60) || 'unknown', `${event}_FAILED`, { reason: 'old Windows app', ...logInfo(info) });
    fail(403, 'This version of the Windows app no longer connects to the server. Install the new Windows app (version 3.0), which works on its own on one computer, or use the website.');
  }
  await ensureVerifier();
  const id = String(username ?? '').trim().toLowerCase().slice(0, 60), a = id && await getAccount(id);
  if (!a || !roles.includes(a.role) || !a.hash || !checkPw(a, password)) {
    await adminLog(id || 'unknown', `${event}_FAILED`, { attempted: id, ...(a && !roles.includes(a.role) ? { reason: 'wrong login type' } : {}), ...logInfo(info) });
    fail(401, 'Invalid username or password.');
  }
  if (a.status !== 'active') { await adminLog(id, `${event}_FAILED`, { reason: 'login disabled', ...logInfo(info) }); fail(403, 'This login has been disabled by the Verifier.'); }
  await sql`update accounts set last_login = now() where username = ${id}`;
  return a;
}
const passwordVersion = a => sha256('pv:' + (a.hash || '')).slice(0, 16);   // changes whenever the password does
const accountToken = (a, role, hours) => sign({ sub: a.username, role, name: a.name, pv: passwordVersion(a), exp: Date.now() + hours * 3600e3 });

/* Where a request came from: IP and location as seen by Vercel, plus what the browser reported about itself */
function clientNet(req) {
  const h = req.headers || {}, dec = v => { try { return v ? decodeURIComponent(String(v)) : null; } catch { return String(v); } };
  return { ip: String(h['x-forwarded-for'] || h['x-real-ip'] || '').split(',')[0].trim() || null, city: dec(h['x-vercel-ip-city']), region: dec(h['x-vercel-ip-country-region']),
    country: h['x-vercel-ip-country'] || null, ipTimezone: h['x-vercel-ip-timezone'] || null, userAgent: String(h['user-agent'] || '').slice(0, 400) || null };
}
function requestInfo(req, body) {
  let device = body.device && typeof body.device === 'object' && !Array.isArray(body.device) ? body.device : {};
  if (JSON.stringify(device).length > 4000) device = { note: 'device details too large, dropped' };
  const serverTime = Date.now();
  return { device, network: clientNet(req), serverTime, clockOffsetSeconds: Number.isFinite(device.clientTimeMs) ? Math.round((device.clientTimeMs - serverTime) / 1000) : null };
}
const logInfo = info => ({ ip: info.network.ip, location: [info.network.city, info.network.region, info.network.country].filter(Boolean).join(', ') || null,
  appVersion: info.device.appVersion || null, appKind: info.device.appKind || null, buildHash: info.device.buildHash || null,
  ...(info.device.exeHash ? { exeHash: info.device.exeHash, buildHashMatches: info.device.buildHashMatches ?? null, computer: info.device.computer || null } : {}),
  timezone: info.device.timezone || null, installId: info.device.installId || null });
/* The Windows app stays signed in until the person logs out, so its sessions last longer than a browser tab's.
   Mobile-number logins are still re-checked on every request (auth), so disabling one takes effect at once. */
const isDesktop = info => info.device.desktop === true && info.device.appKind === 'windows-app';
const sessionHours = (role, info) => isDesktop(info) || process.env.QPR_LOCAL === '1' ? (role === 'randomizer' ? 60 * 24 : 30 * 24) : (role === 'randomizer' ? 14 * 24 : 12);

/* ---------------- schema ---------------- */
let schemaReady;
function ensureSchema() {
  schemaReady ??= (async () => {
    await sql`create table if not exists settings (key text primary key, value jsonb not null, updated_at timestamptz default now())`;
    await sql`create table if not exists exams (id text primary key, doc jsonb not null, published_version int not null default 0, published_doc jsonb, published_at timestamptz, deleted boolean not null default false, updated_at timestamptz default now())`;
    await sql`alter table exams add column if not exists archived_at timestamptz`;   // archived: read-only, off the Randomizer page, results kept
    await sql`alter table exams add column if not exists archived_by text`;
    await sql`create table if not exists admin_audit (seq int primary key, ts bigint not null, entry jsonb not null, hash text not null)`;
    await sql`create table if not exists client_audit (install_id text not null, seq int not null, entry jsonb not null, hash text not null, received_at timestamptz default now(), primary key (install_id, seq))`;
    await sql`create table if not exists draws (key text primary key, install_id text not null, exam_id text not null, shift_id text not null, subject_id text not null, attempt int not null, draw jsonb not null, log_hash text not null, received_at timestamptz default now())`;
    await sql`create table if not exists sync_status (install_id text primary key, actor text, last_sync timestamptz, entries int, chain_ok boolean, issues jsonb, head text)`;
    await sql`create table if not exists final_choices (exam_id text primary key, install_id text not null, final_attempt int not null, log_hash text not null, choice jsonb not null, received_at timestamptz default now())`;
    await sql`create table if not exists sync_conflicts (id serial primary key, install_id text, kind text, detail jsonb, created_at timestamptz default now())`;
    // Logins (see "accounts" above). status: active | disabled. must_change: the built-in Verifier until its default password is changed.
    await sql`create table if not exists accounts (username text primary key, role text not null, name text, designation text, salt text, hash text, status text not null default 'active',
      must_change boolean not null default false, created_at timestamptz default now(), created_by text, updated_at timestamptz, last_login timestamptz)`;
    await sql`update accounts set designation = ${POSTS.coe.designation} where username = 'coe' and designation = ${OLD_COE_DESIGNATION}`;   // 3.0.2: new COE designation
    await ensureVerifier();
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
      if (b.colours.some(c => !str(c.name, 60) || !/^#[0-9a-fA-F]{6}$/.test(c.hex))) fail(400, `Invalid colour in "${b.name}".`);
    }
  }
  if (JSON.stringify(doc).length > 500000) fail(413, 'Exam document too large.');
}
function publishProblems(doc) {
  const p = [];
  if (!doc.shifts.length) p.push('Add at least one shift.');
  doc.shifts.forEach(s => { if (!s.subjects.length) p.push(`${s.name}: add at least one subject.`); s.subjects.forEach(b => { if (b.colours.length < 2) p.push(`${s.name} / ${b.name}: needs at least 2 colours.`); }); });
  return p;
}
/* A question paper is identified by its colour only: each colour keeps just { name, hex } (drops legacy fields) */
function cleanDoc(doc) {
  if (!doc || !Array.isArray(doc.shifts)) return doc;
  return { ...doc, shifts: doc.shifts.map(s => ({ ...s, subjects: (s.subjects || []).map(b => ({ ...b, colours: (b.colours || []).map(c => ({ name: c.name, hex: c.hex })) })) })) };
}
const EXAM_EVENTS = new Set(['EXAM_CREATED', 'EXAM_UPDATED', 'SHIFT_CREATED', 'SHIFT_UPDATED', 'SHIFT_DUPLICATED', 'SHIFT_DELETED', 'SUBJECT_CREATED', 'SUBJECT_UPDATED', 'SUBJECT_DELETED']);
/* QP-Draw certificate: signature blocks printed on every certificate (Admin → Settings).
   Printed two per row in this order; an odd last one spans the full width. */
const DEFAULT_SIGNATORIES = [
  { name: 'Dr. Sanjay Kumar Singh', designation: 'Deputy Secretary, UPESSC, Prayagraj' },
  { name: 'Shri Devendra Pratap Singh', designation: 'Controller of Examination, UPESSC, Prayagraj' },
  { name: 'Shri Manoj Kumar', designation: 'Secretary, UPESSC, Prayagraj' },
  { name: 'Dr. Harendra Kumar Rai', designation: 'Honorable Senior-most Member, UPESSC, Prayagraj' },
  { name: 'Dr. Prashant Kumar', designation: 'Honorable Chairman, UPESSC, Prayagraj' }];
/* A saved list that is still the pre-3.0.2 default (reverse order, old COE designation) becomes the new default */
async function certSettings() {
  const saved = (await getSetting('certificate')) || {};
  let list = Array.isArray(saved.signatories) ? saved.signatories.map(x => x && x.designation === OLD_COE_DESIGNATION ? { ...x, designation: POSTS.coe.designation } : x) : null;
  if (list && JSON.stringify(list.map(x => [x.name, x.designation])) === JSON.stringify([...DEFAULT_SIGNATORIES].reverse().map(x => [x.name, x.designation]))) list = DEFAULT_SIGNATORIES;
  return { ...saved, signatories: list || DEFAULT_SIGNATORIES };
}
/* Best of 5 needs app 2.2.0 or later: an older Randomization PC would run it as "5th attempt is final", so it does not get those exams */
const verLess = (a, b) => { const x = String(a || '0').split('.').map(Number), y = b.split('.').map(Number); for (let i = 0; i < 3; i++) { if ((x[i] || 0) !== y[i]) return (x[i] || 0) < y[i]; } return false; };
const examsFor = (exams, info) => verLess(info.device.appVersion, '2.2.0') ? exams.filter(e => e.finalMode !== 'best5') : exams;
const publishedExams = async () => (await sql`select published_doc, published_version, published_at from exams where not deleted and archived_at is null and published_doc is not null`)
  .map(r => ({ ...cleanDoc(r.published_doc), packageVersion: r.published_version, exportedAt: new Date(r.published_at).toISOString() }));
/* Exams the Randomizer page must take off its list: deleted (removed, unless it already has spins for them) or archived (kept under Results) */
const removedExams = async () => (await sql`select id, doc->>'code' as code, deleted from exams where deleted or archived_at is not null`).map(r => ({ id: r.id, code: r.code, reason: r.deleted ? 'deleted' : 'archived' }));
/* How far randomization has got for an exam, from the draws that reached this database:
   started  = any spin or final-iteration draw;  complete = every subject of every shift has its final colour;
   closed   = complete, or every shift's randomization window is over (IST). */
async function examProgress(ex) {
  const doc = ex.published_doc || ex.doc, shifts = doc.shifts || [];
  const rows = await sql`select shift_id, subject_id, attempt, (draw->>'colourIndex')::int as ci from draws where exam_id = ${ex.id}`;
  const [ch] = await sql`select final_attempt from final_choices where exam_id = ${ex.id}`;
  const mode = doc.finalMode || 'fixed5', T = mode === 'client' ? (ch ? ch.final_attempt : null) : 5;
  const done = (s, b) => {
    const d = new Map(rows.filter(r => r.shift_id === s.id && r.subject_id === b.id).map(r => [r.attempt, r.ci]));
    if (mode !== 'best5') return !!T && d.has(T);
    if (![1, 2, 3, 4, 5].every(a => d.has(a))) return false;
    const c = new Map(); [1, 2, 3, 4, 5].forEach(a => c.set(d.get(a), (c.get(d.get(a)) || 0) + 1));
    const max = Math.max(...c.values());
    return [...c.values()].filter(n => n === max).length === 1 || d.has(6);   // one most frequent colour, or the tie-breaker spin
  };
  const subjects = shifts.flatMap(s => (s.subjects || []).map(b => [s, b]));
  const complete = subjects.length > 0 && subjects.every(([s, b]) => done(s, b));
  const windowsOver = shifts.length > 0 && shifts.every(s => Date.parse(`${s.date}T${s.end}:59.999+05:30`) < Date.now());
  return { started: rows.length > 0 || !!ch, spins: rows.length, complete, closed: complete || windowsOver };
}
const getSetting = async k => (await sql`select value from settings where key = ${k}`)[0]?.value ?? null;
const putSetting = (k, v) => sql`insert into settings (key, value, updated_at) values (${k}, ${JSON.stringify(v)}::jsonb, now()) on conflict (key) do update set value = excluded.value, updated_at = now()`;

/* ---------------- routes ---------------- */
const routes = {
  'GET status': async () => ({ serverTime: Date.now(), local: process.env.QPR_LOCAL === '1' }),
  /* Connectivity check and server time (no database work), and a 128 KB download for measuring internet speed */
  'GET ping': async () => ({ ok: true, serverTime: Date.now() }),
  'GET speedtest': async () => ({ raw: crypto.randomBytes(128 * 1024), type: 'application/octet-stream' }),

  /* ----- sign-in (no OTP: every login is created by the Verifier) ----- */
  'POST admin/login': async ({ body, req }) => {
    const info = requestInfo(req, body), a = await accountLogin(['admin'], body.username, body.password, info, 'ADMIN_LOGIN');
    await adminLog(a.username, 'ADMIN_LOGIN', { name: a.name, ...logInfo(info) });
    return { token: accountToken(a, 'admin', sessionHours('admin', info)), user: a.username, name: a.name, mustChange: !!a.must_change };
  },
  'POST admin/logout': async ({ user }) => { await adminLog(user, 'LOGOUT', {}); return { ok: true }; },
  'POST verifier/login': async ({ body, req }) => {
    const info = requestInfo(req, body), a = await accountLogin(['verifier'], body.username, body.password, info, 'VERIFIER_LOGIN');
    await adminLog(a.username, 'VERIFIER_LOGIN', { name: a.name, ...logInfo(info) });
    return { token: accountToken(a, 'verifier', sessionHours('verifier', info)), user: a.username, name: a.name, mustChange: !!a.must_change };
  },
  'POST verifier/logout': async ({ user }) => { await adminLog(user, 'LOGOUT', { console: 'verifier' }); return { ok: true }; },
  /* Change your own password (any signed-in login). Clears the "change the default password" requirement. */
  'POST auth/password': async ({ body, user, tok }) => {
    const a = await getAccount(user);
    if (!a || !checkPw(a, body.old)) fail(400, 'Current password is incorrect.');
    const pw = checkPassword(body.password);
    if (pw === body.old) fail(400, 'Choose a password different from the current one.');
    if (a.role === 'verifier' && pw === DEFAULT_VERIFIER.password) fail(400, 'Choose a password different from the default one.');
    const c = makeCred(a.username, pw);
    await sql`update accounts set salt = ${c.salt}, hash = ${c.hash}, must_change = false, updated_at = now() where username = ${a.username}`;
    await adminLog(a.username, 'PASSWORD_CHANGED', { role: a.role, wasDefault: !!a.must_change });
    // the session that changed the password carries on with a new token (same expiry); every other session of this login ends
    return { ok: true, token: accountToken(await getAccount(a.username), tok.role, Math.max(0.01, (tok.exp - Date.now()) / 3600e3)) };
  },

  /* ----- Verifier console: the logins ----- */
  'GET verifier/accounts': async () => {
    const rows = await sql`select * from accounts order by case role when 'verifier' then 0 when 'coe' then 1 when 'chairman' then 2 else 3 end, created_at`;
    return { accounts: rows.map(publicAccount), posts: Object.fromEntries(Object.entries(POSTS).map(([k, v]) => [k, v])) };
  },
  'POST verifier/admin': async ({ body, user }) => {
    const username = String(body.username ?? '').trim().toLowerCase(), name = str(body.name, 120);
    if (!USERNAME_RE.test(username)) fail(400, 'Username: 3–40 letters, digits, dot, dash or underscore (no spaces).');
    if (!name) fail(400, 'Enter the name.');
    const c = makeCred(username, checkPassword(body.password));
    const ins = await sql`insert into accounts (username, role, name, designation, salt, hash, status, must_change, created_by) values (${username}, 'admin', ${name}, ${str(body.designation, 160) || ''}, ${c.salt}, ${c.hash}, 'active', false, ${user}) on conflict (username) do nothing returning username`;
    if (!ins.length) fail(409, 'That username is already taken.');
    await adminLog(user, 'ADMIN_LOGIN_CREATED', { username, name });
    return { ok: true };
  },
  /* Controller of Examinations / Chairman: name, designation and password (one login per post) */
  'POST verifier/committee': async ({ body, user }) => {
    const post = body.post; if (!POSTS[post]) fail(400, 'Unknown post.');
    const name = str(body.name, 120), designation = str(body.designation, 160) || '';
    if (!name) fail(400, 'Enter the name.');
    const old = await getAccount(post);
    if (body.password) {
      const c = makeCred(post, checkPassword(body.password));
      await sql`insert into accounts (username, role, name, designation, salt, hash, status, must_change, created_by) values (${post}, ${post}, ${name}, ${designation}, ${c.salt}, ${c.hash}, 'active', false, ${user})
        on conflict (username) do update set name = excluded.name, designation = excluded.designation, salt = excluded.salt, hash = excluded.hash, status = 'active', updated_at = now()`;
    } else {
      if (!old || !old.hash) fail(400, 'Set a password for this post.');
      await sql`update accounts set name = ${name}, designation = ${designation}, updated_at = now() where username = ${post}`;
    }
    await adminLog(user, 'COMMITTEE_LOGIN_SET', { post: POSTS[post].label, name, designation, passwordChanged: !!body.password });
    return { ok: true };
  },
  'POST verifier/account': async ({ body, user }) => {
    const a = await getAccount(body.username); if (!a || a.role === 'verifier') fail(404, 'No such login.');
    const label = `${ROLE_LABEL[a.role]} ${a.username}`;
    if (body.action === 'reset') {
      const c = makeCred(a.username, checkPassword(body.password));
      await sql`update accounts set salt = ${c.salt}, hash = ${c.hash}, updated_at = now() where username = ${a.username}`;
      await adminLog(user, 'PASSWORD_RESET_BY_VERIFIER', { username: a.username, role: a.role });
    } else if (body.action === 'disable' || body.action === 'enable') {
      await sql`update accounts set status = ${body.action === 'disable' ? 'disabled' : 'active'}, updated_at = now() where username = ${a.username}`;
      await adminLog(user, body.action === 'disable' ? 'LOGIN_DISABLED' : 'LOGIN_ENABLED', { username: a.username, role: a.role });
    } else if (body.action === 'delete' && a.role === 'admin') {
      await sql`delete from accounts where username = ${a.username}`;
      await adminLog(user, 'LOGIN_DELETED', { username: a.username, role: a.role });
    } else fail(400, 'Unknown action.');
    return { ok: true, label };
  },
  'GET verifier/audit': async () => {
    const entries = (await sql`select entry from admin_audit order by seq`).map(r => r.entry);
    return { entries, verification: verifyEntries(entries) };
  },

  /* ----- Randomizer page: no Verifier login. Step 1: the Controller of Examinations enters their password;
     step 2: the Chairman enters theirs. The page opens only after both. ----- */
  'POST client/committee': async () => ({ ready: await committeeReady(), committee: await committeeInfo() }),   // names shown on the sign-in card
  'POST client/step': async ({ body, req }) => {
    const info = requestInfo(req, body), a = await officerCheck('coe', body.password, info, 'RANDOMIZER_STEP1'), at = Date.now();
    await adminLog('coe', 'RANDOMIZER_STEP1_OK', { name: a.name, installId: str(body.installId, 64), ...logInfo(info) });
    return { officer: officerOf(a, at), stepToken: sign({ step: 'coe', pv: passwordVersion(a), at, exp: at + 10 * 60e3 }), serverTime: at };
  },
  'POST client/login': async ({ body, req }) => {
    const info = requestInfo(req, body), installId = str(body.installId, 64), st = verifyToken(typeof body.stepToken === 'string' ? body.stepToken : null), coe = await getAccount('coe');
    if (!st || st.step !== 'coe' || !coe || coe.status !== 'active' || st.pv !== passwordVersion(coe)) fail(409, 'Step 1 has expired. The Controller of Examinations must enter their password again.');
    const ch = await officerCheck('chairman', body.password, info, 'RANDOMIZER_STEP2'), at = Date.now();
    const officers = [officerOf(coe, st.at), officerOf(ch, at)], name = `${coe.name} & ${ch.name}`;
    const all = await publishedExams(), exams = examsFor(all, info);
    if (exams.length < all.length) await adminLog('coe+chairman', 'EXAMS_WITHHELD_OLD_APP', { appVersion: info.device.appVersion || null, withheld: all.filter(e => !exams.includes(e)).map(e => e.code), reason: 'Best of 5 needs app 2.2.0 or later', ...logInfo(info) });
    await adminLog('coe+chairman', 'RANDOMIZER_LOGIN', { committee: officers.map(o => ({ post: o.label, name: o.name, signedIn: istTime(o.at) })), installId,
      examsDownloaded: exams.map(e => ({ code: e.code, version: e.packageVersion })), clientClock: body.clientClock || null, clockOffsetSeconds: info.clockOffsetSeconds, ...logInfo(info) });
    return { token: sign({ sub: 'coe', role: 'client', name, pv: passwordVersion(coe), pv2: passwordVersion(ch), exp: at + sessionHours('randomizer', info) * 3600e3 }),
      user: 'coe+chairman', name, officers, exams, logo: await getSetting('logo'), certificate: await certSettings(), committee: await committeeInfo(), committeeReady: true,
      removed: await removedExams(), serverTime: at };
  },

  'GET admin/exams': async () => {
    const rows = await sql`select id, doc, published_doc, published_version, published_at, archived_at, archived_by, (published_doc is not null and published_doc <> doc) as changed from exams where not deleted order by updated_at desc`;
    const out = [];
    for (const r of rows) out.push({ ...cleanDoc(r.doc), publishedVersion: r.published_version, publishedAt: r.published_at ? new Date(r.published_at).getTime() : null, changedSincePublish: !!r.changed,
      archivedAt: r.archived_at ? new Date(r.archived_at).getTime() : null, archivedBy: r.archived_by || null, progress: await examProgress(r) });
    return out;
  },
  'PUT admin/exams': async ({ body, user }) => {
    const { exam, event, details } = body;
    if (!EXAM_EVENTS.has(event)) fail(400, 'Unknown event.');
    const { publishedVersion, publishedAt, changedSincePublish, ...raw } = exam || {};
    validateExam(raw);
    const doc = cleanDoc(raw);
    doc.updatedAt = Date.now();
    const [ex] = await sql`select deleted, doc, archived_at from exams where id = ${doc.id}`;
    if (ex && ex.deleted) fail(410, 'Exam was deleted.');
    if (ex && ex.archived_at) fail(409, 'This exam is archived and read-only. Restore it first.');
    if (ex && (ex.doc.finalMode || 'fixed5') !== (doc.finalMode || 'fixed5')) {
      const [{ n }] = await sql`select (select count(*) from draws where exam_id = ${doc.id}) + (select count(*) from final_choices where exam_id = ${doc.id}) as n`;
      if (Number(n) > 0) fail(409, 'The final selection mode cannot be changed after randomization has started for this exam.');
    }
    await sql`insert into exams (id, doc, updated_at) values (${doc.id}, ${JSON.stringify(doc)}::jsonb, now()) on conflict (id) do update set doc = excluded.doc, updated_at = now()`;
    await adminLog(user, event, { examId: doc.id, examCode: doc.code, ...(details || {}) });
    return { ok: true };
  },
  /* Delete: only before randomization is complete. Spins already made stay in the audit logs and results. */
  'DELETE admin/exams': async ({ query, user }) => {
    const [ex] = await sql`select * from exams where id = ${query.id} and not deleted`;
    if (!ex) fail(404, 'Exam not found.');
    if (ex.archived_at) fail(409, 'This exam is archived. Restore it first.');
    const pr = await examProgress(ex);
    if (pr.complete) fail(409, 'Randomization of this exam is complete, so it cannot be deleted. Archive it instead.');
    await sql`update exams set deleted = true, updated_at = now() where id = ${ex.id}`;
    await adminLog(user, 'EXAM_DELETED', { examId: ex.id, name: ex.doc.name, code: ex.doc.code, randomizationStarted: pr.started, spinsKept: pr.spins });
    return { ok: true };
  },
  /* Archive: once the exam is closed (randomization complete, or every shift's window over). Read-only, off the
     Randomizer page's exam list; results and certificates stay. Restore brings it back. */
  'POST admin/archive': async ({ body, user }) => {
    const [ex] = await sql`select * from exams where id = ${body.id} and not deleted`;
    if (!ex) fail(404, 'Exam not found.');
    if (body.archived === false) {
      if (!ex.archived_at) return { ok: true };
      await sql`update exams set archived_at = null, archived_by = null, updated_at = now() where id = ${ex.id}`;
      await adminLog(user, 'EXAM_RESTORED', { examId: ex.id, code: ex.doc.code, name: ex.doc.name });
      return { ok: true };
    }
    if (ex.archived_at) return { ok: true };
    const pr = await examProgress(ex);
    if (!pr.closed) fail(409, 'An exam can be archived once it is closed: randomization complete, or every shift\'s randomization window over.');
    await sql`update exams set archived_at = now(), archived_by = ${user}, updated_at = now() where id = ${ex.id}`;
    await adminLog(user, 'EXAM_ARCHIVED', { examId: ex.id, code: ex.doc.code, name: ex.doc.name, randomizationComplete: pr.complete, spins: pr.spins });
    return { ok: true };
  },
  'POST admin/publish': async ({ body, user }) => {
    const [ex] = await sql`select * from exams where id = ${body.id} and not deleted`;
    if (!ex) fail(404, 'Exam not found.');
    if (ex.archived_at) fail(409, 'This exam is archived and read-only. Restore it first.');
    const p = publishProblems(ex.doc); if (p.length) fail(400, p.join('\n'));
    const v = ex.published_version + 1;
    await sql`update exams set published_version = ${v}, published_doc = doc, published_at = now() where id = ${body.id}`;
    await adminLog(user, 'EXAM_PUBLISHED', { examId: ex.id, examCode: ex.doc.code, publishedVersion: v, docSha256: sha256(stable(ex.doc)),
      shifts: ex.doc.shifts.map(s => ({ id: s.id, name: s.name, date: s.date, window: `${s.start}-${s.end}`, subjects: s.subjects.length })) });
    return { publishedVersion: v };
  },
  'POST admin/unpublish': async ({ body, user }) => {
    const [ex] = await sql`update exams set published_doc = null, published_at = null where id = ${body.id} and archived_at is null returning doc, published_version`;
    if (!ex) fail(404, 'Exam not found.');
    await adminLog(user, 'EXAM_UNPUBLISHED', { examId: body.id, examCode: ex.doc.code });
    return { ok: true };
  },

  'GET admin/settings': async () => {
    return { logo: await getSetting('logo'), certificate: await certSettings() };
  },
  'POST admin/certificate': async ({ body, user }) => {
    const list = (Array.isArray(body.signatories) ? body.signatories : []).map(x => ({ name: str(x && x.name, 120), designation: str(x && x.designation, 160) || '' })).filter(x => x.name);
    if (list.length > 10) fail(400, 'At most 10 signatories.');
    await putSetting('certificate', { signatories: list });
    await adminLog(user, 'CERTIFICATE_SIGNATORIES_SET', { signatories: list });
    return { ok: true };
  },
  'POST admin/logo': async ({ body, user }) => {
    if (body.logo === null) { await sql`delete from settings where key = 'logo'`; await adminLog(user, 'LOGO_REMOVED', {}); return { ok: true }; }
    if (typeof body.logo !== 'string' || !/^data:image\/(png|jpeg|svg\+xml);base64,/.test(body.logo) || body.logo.length > 700000) fail(400, 'Logo must be a PNG/JPG/SVG of 500 KB or less.');
    await putSetting('logo', body.logo);
    await adminLog(user, 'LOGO_UPDATED', { sha256: sha256(body.logo), bytes: body.logo.length });
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
    exams: (await sql`select doc, archived_at from exams where not deleted`).map(r => ({ ...cleanDoc(r.doc), archivedAt: r.archived_at ? new Date(r.archived_at).getTime() : null })),
    choices: await sql`select exam_id, install_id, final_attempt, choice, received_at from final_choices`,
  }),
  'GET admin/client-audit': async ({ query }) => {
    const entries = (await sql`select entry from client_audit where install_id = ${query.installId} order by seq`).map(r => r.entry);
    return { entries, verification: verifyEntries(entries) };
  },

  /* ----- Randomization console ----- */
  /* "Clear this PC" on a Randomization PC (password already checked with client/login): recorded before the PC wipes itself */
  'POST client/pc-cleared': async ({ body, req, user }) => {
    const info = requestInfo(req, body), n = v => Number.isFinite(Number(v)) ? Number(v) : null;
    const oldId = str(body.installId, 64), newId = str(body.newInstallId, 64);
    if (!oldId || !newId) fail(400, 'Missing install id.');
    await adminLog(user, 'RANDOMIZATION_PC_CLEARED', { oldInstallId: oldId, newInstallId: newId, examsDeleted: n(body.exams), rollsDeleted: n(body.rolls), finalIterationsDeleted: n(body.finalIterations),
      logEntriesDeleted: n(body.logEntries), logHead: str(body.logHead, 80), hadUnsyncedData: body.unsynced === true, ...logInfo(info) });
    return { ok: true };
  },
  /* "Update exams" on the Randomization PC, and automatically whenever its internet comes back */
  'POST client/exams': async ({ body, req, user }) => {
    const info = requestInfo(req, body), all = await publishedExams(), exams = examsFor(all, info);
    if (exams.length < all.length) await adminLog(user, 'EXAMS_WITHHELD_OLD_APP', { appVersion: info.device.appVersion || null, withheld: all.filter(e => !exams.includes(e)).map(e => e.code), reason: 'Best of 5 needs app 2.2.0 or later', ...logInfo(info) });
    await adminLog(user, 'CLIENT_EXAMS_UPDATED', { installId: str(body.installId, 64), examsDownloaded: exams.map(e => ({ code: e.code, version: e.packageVersion })), clockOffsetSeconds: info.clockOffsetSeconds, ...logInfo(info) });
    return { exams, logo: await getSetting('logo'), certificate: await certSettings(), committee: await committeeInfo(), committeeReady: await committeeReady(), removed: await removedExams(), serverTime: Date.now() };
  },
  'POST client/sync': async ({ body, user }) => {
    const installId = str(body.installId, 64); if (!installId) fail(400, 'Missing install id.');
    const entries = Array.isArray(body.entries) ? body.entries.sort((a, b) => a.seq - b.seq) : [];
    const draws = Array.isArray(body.draws) ? body.draws : [];
    const choices = Array.isArray(body.choices) ? body.choices : [];
    if (entries.length > 20000) fail(413, 'Too many entries.');
    // After the exam data was reset on the server, a PC whose log began before the reset is refused (nothing is stored),
    // so old test rolls cannot come back. The PC is told to use "Clear this PC" first.
    const reset = await getSetting('data_reset');
    if (reset && entries.length && Number(entries[0].ts) < reset.at) {
      const [seen] = await sql`select 1 from sync_conflicts where install_id = ${installId} and kind = 'PRE_RESET_DATA_REJECTED' and created_at > to_timestamp(${reset.at / 1000}) limit 1`;
      if (!seen) await sql`insert into sync_conflicts (install_id, kind, detail) values (${installId}, 'PRE_RESET_DATA_REJECTED', ${JSON.stringify({ actor: user, firstEntry: new Date(Number(entries[0].ts)).toISOString(), entries: entries.length, draws: draws.length, resetAt: new Date(reset.at).toISOString() })}::jsonb)`;
      return { ok: false, resetRequired: true, resetAt: reset.at, chainOk: null, issues: [], conflicts: [{ kind: 'PRE_RESET_DATA_REJECTED' }], entries: 0, draws: 0, syncedAt: Date.now() };
    }
    const v = verifyEntries(entries);
    const conflicts = [];
    // A PC clock running ahead of the server shows up as log entries "from the future"
    const latest = entries.reduce((m, e) => Math.max(m, Number(e.ts) || 0), 0);
    if (latest > Date.now() + 120000) conflicts.push({ kind: 'CLIENT_CLOCK_AHEAD', detail: { latestEntry: new Date(latest).toISOString(), serverTime: new Date().toISOString(), aheadSeconds: Math.round((latest - Date.now()) / 1000), actor: user } });
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
      const added = new Set((await sql`insert into draws (key, install_id, exam_id, shift_id, subject_id, attempt, draw, log_hash)
        select d->>'key', ${installId}, d->>'examId', d->>'shiftId', d->>'subjectId', (d->>'attempt')::int, d, d->>'logHash' from jsonb_array_elements(${JSON.stringify(valid)}::jsonb) d on conflict (key) do nothing returning key`).map(r => r.key));
      // Clock evidence, checked once when a draw first arrives: its time must not be in the server's future,
      // and must fall inside the shift's IST window (the PC checks both too; this catches a PC clock that was moved).
      const now = Date.now();
      valid.filter(d => added.has(d.key)).forEach(d => {
        const e = bySeq.get(d.logSeq), x = e.details || {}, [ws, we] = String(x.window || '').split('-');
        const start = Date.parse(`${x.shiftDate}T${ws}:00+05:30`), end = Date.parse(`${x.shiftDate}T${we}:59.999+05:30`);
        const base = { key: d.key, examCode: x.examCode, shift: x.shiftName, subject: d.subjectName, attempt: d.attempt, drawTime: new Date(e.ts).toISOString(), drawTimeIST: istTime(e.ts) };
        if (e.ts > now + 120000) conflicts.push({ kind: 'DRAW_TIME_AHEAD_OF_SERVER', detail: { ...base, serverTime: new Date(now).toISOString(), aheadSeconds: Math.round((e.ts - now) / 1000) } });
        if (Number.isFinite(start) && Number.isFinite(end) && (e.ts < start || e.ts > end)) conflicts.push({ kind: 'DRAW_OUTSIDE_SHIFT_WINDOW', detail: { ...base, window: `${x.shiftDate} ${x.window} IST` } });
      });
      const stored = new Map((await sql`select key, install_id, log_hash from draws where key = any(${valid.map(d => d.key)})`).map(r => [r.key, r]));
      valid.forEach(d => { const s = stored.get(d.key); if (s.install_id !== installId || s.log_hash !== d.logHash) conflicts.push({ kind: 'DUPLICATE_DRAW_CONFLICT', detail: { key: d.key, subject: d.subjectName, attempt: d.attempt, acceptedFrom: s.install_id, rejectedFrom: installId } }); });
    }
    // Final-iteration draws (Mode B) are accepted only when backed by a matching audit entry.
    const okChoices = choices.filter(c => { const e = bySeq.get(c.logSeq); return e && FINAL_EVENTS.has(e.event) && e.hash === c.logHash && e.details.examId === c.examId && e.details.finalAttempt === c.finalAttempt && c.finalAttempt >= 3 && c.finalAttempt <= MAX_ATTEMPTS; });
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
    const path = String(req.query.path || '').replace(/^\/+|\/+$/g, '');
    if (path !== 'ping' && path !== 'speedtest') await ensureSchema();
    const fn = routes[`${req.method} ${path}`];
    if (!fn) fail(404, 'Not found.');
    const ctx = { body: req.body && typeof req.body === 'object' ? req.body : {}, query: req.query || {}, req };
    const PUBLIC = new Set(['status', 'ping', 'speedtest', 'admin/login', 'verifier/login', 'client/committee', 'client/step', 'client/login']);
    const need = PUBLIC.has(path) ? null : path.startsWith('admin/') ? 'admin' : path.startsWith('verifier/') ? 'verifier' : path.startsWith('client/') ? 'client' : path.startsWith('auth/') ? 'any' : 'deny';
    if (need === 'deny') fail(404, 'Not found.');
    if (need) { ctx.tok = await auth(req, need, path); ctx.user = ctx.tok.sub; }
    const out = await fn(ctx);
    if (out && Buffer.isBuffer(out.raw)) { res.setHeader('Content-Type', out.type); res.setHeader('Cache-Control', 'no-store, no-transform'); return res.status(200).send(out.raw); }
    res.status(200).json(out);
  } catch (e) {
    const status = e.status || 500;
    if (status === 500) console.error(e);
    res.status(status).json({ error: status === 500 ? 'Server error.' : e.message });
  }
}
