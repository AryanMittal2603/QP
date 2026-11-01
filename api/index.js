// UPESSC QP Randomization — single API function (all routes), backed by Neon Postgres.
import { neon } from '@neondatabase/serverless';
import crypto from 'node:crypto';

const sql = neon(process.env.DATABASE_URL);
const SECRET = process.env.AUTH_SECRET;
const ITER = 150000;
const MAX_ATTEMPTS = 7;   // Mode A uses 5; Mode B draws 3–7 at random on the Randomization PC for the whole exam
const FINAL_MODES = new Set(['fixed5', 'client']);   // 'client' = final iteration drawn at random on the Randomization PC
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
/* Session check. Mobile-number accounts are re-checked on every request, so a login the approver
   disables stops working immediately rather than when its token expires. */
async function auth(req, role) {
  const p = verifyToken((req.headers.authorization || '').replace(/^Bearer /, ''));
  if (!p || p.role !== role) fail(401, 'Session expired. Please log in again.');
  if (p.acct === 'user') {
    const u = await getUser(p.sub, p.accRole);
    if (!u || u.status !== 'approved') fail(401, 'Your login is no longer active. Please contact the approver.');
  }
  return p;
}
const str = (v, max = 200) => typeof v === 'string' && v.trim() && v.length <= max ? v.trim() : null;

/* ---------------- accounts: mobile number + password, verified by OTP, approved by the approver ---------------- */
const ROLES = new Set(['admin', 'randomizer']);   // roles people can request from the login screens
const ROLE_LABEL = { admin: 'Admin', randomizer: 'Randomizer', approver: 'Approver' };
const TOKEN_ROLE = { admin: 'admin', randomizer: 'client', approver: 'approver' };
const OTP_TTL_MS = 5 * 60e3, OTP_MAX_TRIES = 5, OTP_PER_HOUR = 5, OTP_PER_IP_HOUR = 20;
const OTP_RESEND_MS = (Number(process.env.OTP_RESEND_SECONDS) || 60) * 1000;
const SMS_URL_DEFAULT = 'http://103.234.185.173/api/swsendNK.asp';
const SMS_TEXT_DEFAULT = '{OTP} is your application number for the QP form you registered earlier. Kindly review your application by logging into upessc.org.\n-SESSBA';
const smsConfigured = () => !!(process.env.SMS_USER && process.env.SMS_PASS && process.env.SMS_TEMPLATE_ID);

/* Indian mobile number → 10 digits (accepts +91 / 0 prefixes, spaces, dashes); null if invalid */
function normMobile(v) {
  let d = String(v ?? '').replace(/[\s\-()]/g, '');
  if (!/^\+?\d+$/.test(d)) return null;
  d = d.replace(/^\+/, '');
  if (d.length === 12 && d.startsWith('91')) d = d.slice(2); else if (d.length === 11 && d.startsWith('0')) d = d.slice(1);
  return /^[6-9]\d{9}$/.test(d) ? d : null;
}
const otpHash = (mobile, code) => sha256(`${SECRET}|otp|${mobile}|${code}`);
const sameStr = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const getUser = async (mobile, role) => (await sql`select * from users where mobile = ${mobile} and role = ${role}`)[0] || null;
const approverExists = async () => (await sql`select count(*)::int n from users where role = 'approver'`)[0].n > 0;

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
const sessionHours = (role, info) => isDesktop(info) ? (role === 'randomizer' ? 60 * 24 : 30 * 24) : (role === 'randomizer' ? 14 * 24 : 12);

/* A clear reason for accounts that exist but cannot log in (shown instead of "wrong password") */
function accountBlocked(u) {
  if (u.status === 'pending') return "Your request is waiting for the approver's approval. You can log in once it is approved.";
  if (u.status === 'rejected') return 'Your request was rejected by the approver. You can send a new request with "Create new login".';
  if (u.status === 'disabled') return 'This login has been disabled by the approver.';
  if (!u.hash) return 'The approver has added your number. Use "Create new login" to verify it with an OTP and set your password.';
  return null;
}

/* SMS gateway (DLT template). Credentials come only from environment variables, never from the code. */
async function sendSms(mobile, code) {
  const text = (process.env.SMS_TEXT || SMS_TEXT_DEFAULT).replace(/\\n/g, '\n').replace('{OTP}', code);
  const q = { username: process.env.SMS_USER, pass: process.env.SMS_PASS, sender: process.env.SMS_SENDER || 'SESSBA', sendto: mobile, templateID: process.env.SMS_TEMPLATE_ID, message: text };
  const url = (process.env.SMS_URL || SMS_URL_DEFAULT) + '?' + Object.entries(q).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(10000) });
    return { ok: r.ok, detail: `HTTP ${r.status} ${(await r.text()).trim().slice(0, 300)}` };
  } catch (e) { return { ok: false, detail: e.name === 'TimeoutError' ? 'gateway timed out' : `gateway unreachable (${e.message})` }; }
}

/* What an OTP is for, and whether this number may use it right now */
async function otpTarget(body, mobile) {
  const { purpose, role } = body;
  if (purpose === 'setup') {
    if (role !== 'approver') fail(400, 'Invalid request.');
    if (!process.env.SETUP_KEY || body.setupKey !== process.env.SETUP_KEY) fail(403, 'Invalid setup key.');
    if (await approverExists()) fail(409, 'The approver account already exists. Please log in.');
  } else if (purpose === 'register') {
    if (!ROLES.has(role)) fail(400, 'Unknown login type.');
    const u = await getUser(mobile, role);
    if (u && u.status === 'approved' && u.hash) fail(409, `This number already has an approved ${ROLE_LABEL[role]} login. Log in, or use "Forgot password".`);
    if (u && u.status === 'disabled') fail(403, `This ${ROLE_LABEL[role]} login has been disabled by the approver.`);
  } else if (purpose === 'reset') {
    if (!ROLE_LABEL[role]) fail(400, 'Unknown login type.');
    const u = await getUser(mobile, role);
    if (!u) fail(404, role === 'approver' ? 'There is no approver login for this number.' : `There is no ${ROLE_LABEL[role]} login for this number. Use "Create new login" to request one.`);
    if (u.status !== 'approved') fail(403, accountBlocked(u));
  } else fail(400, 'Invalid request.');
  return { purpose, role };
}
/* Verify and consume the latest OTP for this number + purpose */
async function checkOtp(mobile, role, purpose, code, info) {
  const [o] = await sql`select * from otps where mobile = ${mobile} and role = ${role} and purpose = ${purpose} and sms_ok and not used order by id desc limit 1`;
  if (!o) fail(400, 'No OTP is active for this number. Please request a new OTP.');
  if (new Date(o.expires_at).getTime() < Date.now()) fail(400, 'This OTP has expired. Please request a new one.');
  if (o.tries >= OTP_MAX_TRIES) fail(429, 'Too many wrong attempts for this OTP. Please request a new one.');
  const c = String(code ?? '').trim();
  if (!/^\d{6}$/.test(c) || !sameStr(otpHash(mobile, c), o.code_hash)) {
    await sql`update otps set tries = tries + 1 where id = ${o.id}`;
    const left = OTP_MAX_TRIES - o.tries - 1;
    await adminLog(mobile, 'OTP_VERIFY_FAILED', { mobile, role, purpose, attemptsLeft: left, ...logInfo(info) });
    fail(400, left > 0 ? `Incorrect OTP. ${left} attempt(s) left.` : 'Incorrect OTP. No attempts left — please request a new OTP.');
  }
  if (!(await sql`update otps set used = true where id = ${o.id} and not used returning id`).length) fail(409, 'This OTP has already been used. Please request a new one.');
}
/* Mobile-number login for one role. Returns null when the number has no account for that role. */
async function mobileLogin(role, mobile, password, info, event) {
  const u = await getUser(mobile, role); if (!u) return null;
  if (u.hash && !checkPw(u, password)) { await adminLog(mobile, `${event}_FAILED`, { mobile, account: 'mobile', reason: 'wrong password', ...logInfo(info) }); fail(401, 'Invalid mobile number or password.'); }
  const blocked = accountBlocked(u);
  if (blocked) { await adminLog(mobile, `${event}_FAILED`, { mobile, account: 'mobile', reason: u.status === 'approved' ? 'password not set' : u.status, ...logInfo(info) }); fail(403, blocked); }
  await sql`update users set last_login = now() where mobile = ${mobile} and role = ${role}`;
  return u;
}
const userToken = (u, hours) => sign({ sub: u.mobile, role: TOKEN_ROLE[u.role], acct: 'user', accRole: u.role, name: u.name, exp: Date.now() + hours * 3600e3 });

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
    // Mobile-number accounts. status: pending | approved | rejected | disabled. hash is null until the person sets a password.
    await sql`create table if not exists users (mobile text not null, role text not null, name text not null, status text not null, salt text, hash text, created_at timestamptz default now(), created_by text,
      decided_at timestamptz, decided_by text, last_login timestamptz, primary key (mobile, role))`;
    // Every sign-up attempt (a number may ask more than once), with the device / network details captured at the time.
    await sql`create table if not exists access_requests (id serial primary key, mobile text not null, role text not null, name text, kind text not null, status text not null, info jsonb,
      created_at timestamptz default now(), decided_at timestamptz, decided_by text)`;
    await sql`create table if not exists otps (id serial primary key, mobile text not null, role text not null, purpose text not null, code_hash text not null, created_at timestamptz default now(),
      expires_at timestamptz not null, tries int not null default 0, used boolean not null default false, ip text, sms_ok boolean, sms_resp text)`;
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
const publishedExams = async () => (await sql`select published_doc, published_version, published_at from exams where not deleted and published_doc is not null`)
  .map(r => ({ ...cleanDoc(r.published_doc), packageVersion: r.published_version, exportedAt: new Date(r.published_at).toISOString() }));
const getSetting = async k => (await sql`select value from settings where key = ${k}`)[0]?.value ?? null;
const putSetting = (k, v) => sql`insert into settings (key, value, updated_at) values (${k}, ${JSON.stringify(v)}::jsonb, now()) on conflict (key) do update set value = excluded.value, updated_at = now()`;

/* ---------------- routes ---------------- */
const routes = {
  'GET status': async () => ({ approverExists: await approverExists(), smsReady: smsConfigured(), serverTime: Date.now() }),
  /* Connectivity check and server time (no database work), and a 128 KB download for measuring internet speed */
  'GET ping': async () => ({ ok: true, serverTime: Date.now() }),
  'GET speedtest': async () => ({ raw: crypto.randomBytes(128 * 1024), type: 'application/octet-stream' }),

  /* ----- OTP + sign-up (no login needed) ----- */
  'POST auth/otp': async ({ body, req }) => {
    const mobile = normMobile(body.mobile); if (!mobile) fail(400, 'Enter a valid 10-digit mobile number.');
    if (!smsConfigured()) fail(503, 'OTP SMS is not set up on the server yet. Please contact the administrator.');
    const { purpose, role } = await otpTarget(body, mobile);
    const info = requestInfo(req, body);
    const [{ last, hour }] = await sql`select max(created_at) filter (where sms_ok is not false) as last, count(*) filter (where created_at > now() - interval '1 hour')::int as hour from otps where mobile = ${mobile}`;
    const since = last ? Date.now() - new Date(last).getTime() : Infinity;
    if (since < OTP_RESEND_MS) fail(429, `Please wait ${Math.ceil((OTP_RESEND_MS - since) / 1000)} seconds before requesting another OTP.`);
    if (hour >= OTP_PER_HOUR) fail(429, 'Too many OTPs have been requested for this number. Please try again in an hour.');
    if (info.network.ip && (await sql`select count(*)::int n from otps where ip = ${info.network.ip} and created_at > now() - interval '1 hour'`)[0].n >= OTP_PER_IP_HOUR) fail(429, 'Too many OTP requests from this network. Please try again later.');
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const [row] = await sql`insert into otps (mobile, role, purpose, code_hash, expires_at, ip) values (${mobile}, ${role}, ${purpose}, ${otpHash(mobile, code)}, ${new Date(Date.now() + OTP_TTL_MS).toISOString()}, ${info.network.ip}) returning id`;
    const sent = await sendSms(mobile, code);
    await sql`update otps set sms_ok = ${sent.ok}, sms_resp = ${sent.detail} where id = ${row.id}`;
    await adminLog(mobile, sent.ok ? 'OTP_SENT' : 'OTP_SMS_FAILED', { mobile, role, purpose, gatewayResponse: sent.detail, ...logInfo(info) });
    if (!sent.ok) fail(502, 'The OTP SMS could not be sent. Please try again in a minute.');
    return { ok: true, sentTo: '******' + mobile.slice(-4), expiresInSeconds: OTP_TTL_MS / 1000, resendAfterSeconds: OTP_RESEND_MS / 1000 };
  },
  'POST auth/complete': async ({ body, req }) => {
    const mobile = normMobile(body.mobile); if (!mobile) fail(400, 'Enter a valid 10-digit mobile number.');
    const { purpose, role } = await otpTarget(body, mobile);
    const info = requestInfo(req, body), name = str(body.name, 80);
    if (typeof body.password !== 'string' || body.password.length < 8 || body.password.length > 200) fail(400, 'Password must be at least 8 characters.');
    const existing = await getUser(mobile, role);
    if ((purpose === 'setup' || (purpose === 'register' && !(existing && existing.status === 'approved'))) && !name) fail(400, 'Please enter your name.');
    await checkOtp(mobile, role, purpose, body.otp, info);
    const c = makeCred(mobile, body.password);
    if (purpose === 'setup') {
      if (await approverExists()) fail(409, 'The approver account already exists. Please log in.');
      await sql`insert into users (mobile, role, name, status, salt, hash, created_by, decided_at, decided_by) values (${mobile}, 'approver', ${name}, 'approved', ${c.salt}, ${c.hash}, 'setup-key', now(), 'setup-key')`;
      await adminLog(mobile, 'APPROVER_CREATED', { mobile, name, ...logInfo(info) });
      return { status: 'approved' };
    }
    if (purpose === 'reset') {
      await sql`update users set salt = ${c.salt}, hash = ${c.hash} where mobile = ${mobile} and role = ${role}`;
      await adminLog(mobile, existing.hash ? 'PASSWORD_RESET' : 'ACCOUNT_ACTIVATED', { mobile, role, via: 'forgot password', ...logInfo(info) });
      return { status: 'approved' };
    }
    // register
    if (existing && existing.status === 'approved') {   // added by the approver: the OTP proves the number, so the login is ready now
      await sql`update users set salt = ${c.salt}, hash = ${c.hash}, name = ${name || existing.name} where mobile = ${mobile} and role = ${role}`;
      await sql`insert into access_requests (mobile, role, name, kind, status, info, decided_at, decided_by) values (${mobile}, ${role}, ${name || existing.name}, 'activation', 'approved', ${JSON.stringify(info)}::jsonb, now(), ${existing.decided_by})`;
      await adminLog(mobile, 'ACCOUNT_ACTIVATED', { mobile, role, addedBy: existing.created_by, ...logInfo(info) });
      return { status: 'approved' };
    }
    const up = await sql`insert into users (mobile, role, name, status, salt, hash, created_by) values (${mobile}, ${role}, ${name}, 'pending', ${c.salt}, ${c.hash}, 'self')
      on conflict (mobile, role) do update set name = excluded.name, status = 'pending', salt = excluded.salt, hash = excluded.hash, created_by = 'self', decided_at = null, decided_by = null
      where users.status in ('pending', 'rejected') returning mobile`;
    if (!up.length) fail(409, 'The status of this login changed while you were signing up. Please try logging in.');
    await sql`insert into access_requests (mobile, role, name, kind, status, info) values (${mobile}, ${role}, ${name}, 'signup', 'pending', ${JSON.stringify(info)}::jsonb)`;
    const [{ n }] = await sql`select count(*)::int n from access_requests where mobile = ${mobile} and role = ${role} and status = 'pending'`;
    await adminLog(mobile, 'ACCESS_REQUESTED', { mobile, role, name, pendingRequests: n, ...logInfo(info) });
    return { status: 'pending', pendingRequests: n };
  },

  'POST admin/login': async ({ body, req }) => {
    const id = String(body.username ?? '').trim().slice(0, 60), mobile = normMobile(id), info = requestInfo(req, body);
    const u = mobile && await mobileLogin('admin', mobile, body.password, info, 'ADMIN_LOGIN');
    if (u) { await adminLog(mobile, 'ADMIN_LOGIN', { mobile, name: u.name, account: 'mobile', ...logInfo(info) }); return { token: userToken(u, sessionHours('admin', info)), user: mobile, name: u.name }; }
    // Older username/password admin accounts keep working.
    const [a] = await sql`select * from admins where username = ${id}`;
    if (!a || !checkPw(a, body.password)) { await adminLog(id || 'unknown', 'ADMIN_LOGIN_FAILED', { attempted: id, ...logInfo(info) }); fail(401, mobile ? 'Invalid mobile number or password.' : 'Invalid username or password.'); }
    await adminLog(id, 'ADMIN_LOGIN', { account: 'username', clientClock: body.clientClock || null, ...logInfo(info) });
    return { token: sign({ sub: id, role: 'admin', acct: 'legacy', exp: Date.now() + sessionHours('admin', info) * 3600e3 }), user: id };
  },
  'POST admin/logout': async ({ user }) => { await adminLog(user, 'LOGOUT', {}); return { ok: true }; },

  'GET admin/exams': async () => {
    const rows = await sql`select doc, published_version, published_at, (published_doc is not null and published_doc <> doc) as changed from exams where not deleted order by updated_at desc`;
    return rows.map(r => ({ ...cleanDoc(r.doc), publishedVersion: r.published_version, publishedAt: r.published_at ? new Date(r.published_at).getTime() : null, changedSincePublish: !!r.changed }));
  },
  'PUT admin/exams': async ({ body, user }) => {
    const { exam, event, details } = body;
    if (!EXAM_EVENTS.has(event)) fail(400, 'Unknown event.');
    const { publishedVersion, publishedAt, changedSincePublish, ...raw } = exam || {};
    validateExam(raw);
    const doc = cleanDoc(raw);
    doc.updatedAt = Date.now();
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
  'POST admin/password': async ({ body, user, tok }) => {
    const mob = tok.acct === 'user';
    const a = mob ? await getUser(user, 'admin') : (await sql`select * from admins where username = ${user}`)[0];
    if (!checkPw(a, body.old)) fail(400, 'Current password is incorrect.');
    if (typeof body.password !== 'string' || body.password.length < 8) fail(400, 'Password must be at least 8 characters.');
    const c = makeCred(user, body.password);
    if (mob) await sql`update users set salt = ${c.salt}, hash = ${c.hash} where mobile = ${user} and role = 'admin'`;
    else await sql`update admins set salt = ${c.salt}, hash = ${c.hash} where username = ${user}`;
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
    exams: (await sql`select doc from exams where not deleted`).map(r => cleanDoc(r.doc)),
    choices: await sql`select exam_id, install_id, final_attempt, choice, received_at from final_choices`,
  }),
  'GET admin/client-audit': async ({ query }) => {
    const entries = (await sql`select entry from client_audit where install_id = ${query.installId} order by seq`).map(r => r.entry);
    return { entries, verification: verifyEntries(entries) };
  },

  /* ----- Approver console ----- */
  'POST approver/login': async ({ body, req }) => {
    const mobile = normMobile(body.username), info = requestInfo(req, body);
    if (!mobile) fail(400, 'Enter your 10-digit mobile number.');
    const u = await mobileLogin('approver', mobile, body.password, info, 'APPROVER_LOGIN');
    if (!u) { await adminLog(mobile, 'APPROVER_LOGIN_FAILED', { mobile, reason: 'no approver account', ...logInfo(info) }); fail(401, 'Invalid mobile number or password.'); }
    await adminLog(mobile, 'APPROVER_LOGIN', { mobile, name: u.name, ...logInfo(info) });
    return { token: userToken(u, sessionHours('approver', info)), user: mobile, name: u.name };
  },
  'POST approver/logout': async ({ user }) => { await adminLog(user, 'LOGOUT', { console: 'approver' }); return { ok: true }; },
  'GET approver/requests': async () => {
    const rows = await sql`select r.id, r.mobile, r.role, r.name, r.kind, r.status, r.info, r.created_at, r.decided_at, r.decided_by, u.status as account_status, u.name as account_name
      from access_requests r left join users u on u.mobile = r.mobile and u.role = r.role order by r.created_at desc limit 2000`;
    return rows.map(r => ({ ...r, created_at: new Date(r.created_at).getTime(), decided_at: r.decided_at ? new Date(r.decided_at).getTime() : null }));
  },
  'POST approver/decide': async ({ body, user }) => {
    const mobile = normMobile(body.mobile), role = body.role, decision = body.decision;
    if (!mobile || !ROLES.has(role) || !['approve', 'reject'].includes(decision)) fail(400, 'Invalid request.');
    const status = decision === 'approve' ? 'approved' : 'rejected';
    // Only a still-pending request can be decided: a second approver tab, or a decision already made, gets a clear answer.
    const [u] = await sql`update users set status = ${status}, decided_at = now(), decided_by = ${user} where mobile = ${mobile} and role = ${role} and status = 'pending' returning name`;
    if (!u) { const cur = await getUser(mobile, role); fail(409, cur ? `This request is no longer pending (current status: ${cur.status}). The list has been refreshed.` : 'This request no longer exists.'); }
    const reqs = await sql`update access_requests set status = ${status}, decided_at = now(), decided_by = ${user} where mobile = ${mobile} and role = ${role} and status = 'pending' returning id`;
    await adminLog(user, decision === 'approve' ? 'ACCESS_APPROVED' : 'ACCESS_REJECTED', { mobile, role, name: u.name, requests: reqs.map(r => r.id), note: str(body.note, 300) });
    return { ok: true, status };
  },
  'GET approver/users': async () => (await sql`select mobile, role, name, status, (hash is not null) as has_password, created_at, created_by, decided_at, decided_by, last_login from users order by role, name`)
    .map(u => ({ ...u, created_at: u.created_at && new Date(u.created_at).getTime(), decided_at: u.decided_at && new Date(u.decided_at).getTime(), last_login: u.last_login && new Date(u.last_login).getTime() })),
  'POST approver/users': async ({ body, user }) => {
    const mobile = normMobile(body.mobile), role = body.role, name = str(body.name, 80);
    if (!mobile) fail(400, 'Enter a valid 10-digit mobile number.');
    if (!ROLES.has(role)) fail(400, 'Choose Admin or Randomizer.');
    if (!name) fail(400, 'Please enter the name.');
    const cur = await getUser(mobile, role);
    if (cur && cur.status === 'pending') fail(409, `This number already has a pending ${ROLE_LABEL[role]} request. Approve it from the Requests tab.`);
    if (cur && cur.status === 'approved') fail(409, `This number already has a ${ROLE_LABEL[role]} login.`);
    if (cur && cur.status === 'disabled') fail(409, `This ${ROLE_LABEL[role]} login is disabled. Enable it from the Users tab instead.`);
    // New, or previously rejected: added as approved with no password; the person sets it via OTP on "Create new login".
    await sql`insert into users (mobile, role, name, status, created_by, decided_at, decided_by) values (${mobile}, ${role}, ${name}, 'approved', ${user}, now(), ${user})
      on conflict (mobile, role) do update set name = excluded.name, status = 'approved', salt = null, hash = null, created_by = excluded.created_by, decided_at = now(), decided_by = excluded.decided_by`;
    await adminLog(user, 'USER_ADDED', { mobile, role, name });
    return { ok: true };
  },
  'POST approver/user-status': async ({ body, user }) => {
    const mobile = normMobile(body.mobile), role = body.role, enable = body.status === 'approved';
    if (!mobile || !ROLE_LABEL[role] || !['approved', 'disabled'].includes(body.status)) fail(400, 'Invalid request.');
    if (role === 'approver') fail(400, 'The approver login cannot be disabled here.');
    const r = await sql`update users set status = ${body.status}, decided_at = now(), decided_by = ${user} where mobile = ${mobile} and role = ${role} and status = ${enable ? 'disabled' : 'approved'} returning name`;
    if (!r.length) fail(409, 'This login has changed since the list was loaded. The list has been refreshed.');
    await adminLog(user, enable ? 'USER_ENABLED' : 'USER_DISABLED', { mobile, role, name: r[0].name });
    return { ok: true };
  },
  'GET approver/audit': async () => {
    const entries = (await sql`select entry from admin_audit order by seq`).map(r => r.entry);
    return { entries, verification: verifyEntries(entries) };
  },

  /* ----- Randomization console ----- */
  'POST client/login': async ({ body, req }) => {
    const id = String(body.username ?? '').trim().slice(0, 60), mobile = normMobile(id), info = requestInfo(req, body), installId = str(body.installId, 64);
    let token, name = null, account;
    const u = mobile && await mobileLogin('randomizer', mobile, body.password, info, 'CLIENT_ONLINE_LOGIN');
    if (u) {
      token = userToken(u, sessionHours('randomizer', info)); name = u.name; account = 'mobile';
    } else {
      // The older single shared Randomization login keeps working.
      const shared = await getSetting('client_cred');
      if (!shared || id !== shared.username || !checkPw(shared, body.password)) {
        await adminLog(id || 'unknown', 'CLIENT_ONLINE_LOGIN_FAILED', { attempted: id, installId, ...logInfo(info) });
        fail(401, mobile ? 'Invalid mobile number or password.' : 'Invalid username or password.');
      }
      token = sign({ sub: id, role: 'client', acct: 'legacy', exp: Date.now() + sessionHours('randomizer', info) * 3600e3 }); account = 'shared';
    }
    // Latest published exams, shifts and settings are downloaded at every login (and with "Update exams").
    const exams = await publishedExams();
    await adminLog(mobile && u ? mobile : id, 'CLIENT_ONLINE_LOGIN', { account, name, installId, examsDownloaded: exams.map(e => ({ code: e.code, version: e.packageVersion })), clientClock: body.clientClock || null,
      clockOffsetSeconds: info.clockOffsetSeconds, ...logInfo(info) });
    // No password hash is sent to the PC any more: signing in always needs the internet.
    return { token, account, cred: { username: mobile && u ? mobile : id, name, kind: account }, name, exams, revoked: [], logo: await getSetting('logo'), serverTime: Date.now() };
  },
  /* "Update exams" on the Randomization PC, and automatically whenever its internet comes back */
  'POST client/exams': async ({ body, req, user }) => {
    const info = requestInfo(req, body), exams = await publishedExams();
    await adminLog(user, 'CLIENT_EXAMS_UPDATED', { installId: str(body.installId, 64), examsDownloaded: exams.map(e => ({ code: e.code, version: e.packageVersion })), clockOffsetSeconds: info.clockOffsetSeconds, ...logInfo(info) });
    return { exams, logo: await getSetting('logo'), serverTime: Date.now() };
  },
  'POST client/sync': async ({ body, user }) => {
    const installId = str(body.installId, 64); if (!installId) fail(400, 'Missing install id.');
    const entries = Array.isArray(body.entries) ? body.entries.sort((a, b) => a.seq - b.seq) : [];
    const draws = Array.isArray(body.draws) ? body.draws : [];
    const choices = Array.isArray(body.choices) ? body.choices : [];
    if (entries.length > 20000) fail(413, 'Too many entries.');
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
    const PUBLIC = new Set(['status', 'ping', 'speedtest', 'auth/otp', 'auth/complete', 'admin/login', 'client/login', 'approver/login']);
    const need = PUBLIC.has(path) ? null : path.startsWith('admin/') ? 'admin' : path.startsWith('approver/') ? 'approver' : path.startsWith('client/') ? 'client' : null;
    if (need) { ctx.tok = await auth(req, need); ctx.user = ctx.tok.sub; }
    const out = await fn(ctx);
    if (out && Buffer.isBuffer(out.raw)) { res.setHeader('Content-Type', out.type); res.setHeader('Cache-Control', 'no-store, no-transform'); return res.status(200).send(out.raw); }
    res.status(200).json(out);
  } catch (e) {
    const status = e.status || 500;
    if (status === 500) console.error(e);
    res.status(status).json({ error: status === 500 ? 'Server error.' : e.message });
  }
}
