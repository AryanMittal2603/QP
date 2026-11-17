'use strict';
/* UPESSC QPR — Windows app (3.x). Works on its own, on one computer, with no server and no internet needed.
   It runs the same page as the website (app/index.html, copied from ../index.html at build time) in a locked-down
   window, and answers the page's /api/* calls itself with the same API code as the website (app/api.mjs, copied
   from ../api/index.js), backed by a PostgreSQL database in the app's data folder (local-db.mjs).
   So logins, exams, rolls, results, audit logs and certificates all stay on this computer. The website keeps its
   own, separate data online. */
const { app, BrowserWindow, protocol, ipcMain, powerMonitor, shell, Menu, session, dialog } = require('electron');
const path = require('node:path'), fs = require('node:fs'), os = require('node:os'), crypto = require('node:crypto');
const { pathToFileURL } = require('node:url');

const APP_DIR = path.join(__dirname, 'app');
const PUBLIC_PROBES = 'https://www.gstatic.com https://www.google.com https://1.1.1.1';   // only to tell whether this PC has internet (rolls need it OFF)

/* Data folder: %APPDATA%\UPESSC QPR 3 (QPR_USER_DATA overrides it, for automated tests).
   Version 2.x kept its data (a copy of the online data) in %APPDATA%\UPESSC QPR; 3.0 starts fresh and removes it once. */
const OLD_DATA = path.join(app.getPath('appData'), 'UPESSC QPR');
app.setPath('userData', process.env.QPR_USER_DATA || path.join(app.getPath('appData'), 'UPESSC QPR 3'));
const DATA = app.getPath('userData');
function firstStart() {
  const marker = path.join(DATA, 'first-start.json');
  if (fs.existsSync(marker)) return;
  fs.mkdirSync(DATA, { recursive: true });
  let removedOld = false;
  if (!process.env.QPR_USER_DATA && fs.existsSync(OLD_DATA)) { try { fs.rmSync(OLD_DATA, { recursive: true, force: true }); removedOld = true; } catch {} }
  fs.writeFileSync(marker, JSON.stringify({ version: app.getVersion(), at: new Date().toISOString(), removedVersion2Data: removedOld }, null, 2));
}

/* Secret that signs this computer's sign-in sessions; made once per installation, kept in the data folder */
function authSecret() {
  const f = path.join(DATA, 'auth-secret');
  try { const s = fs.readFileSync(f, 'utf8').trim(); if (/^[0-9a-f]{64}$/.test(s)) return s; } catch {}
  const s = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(f, s, { mode: 0o600 });
  return s;
}

/* The API, run here on the local database. Started once, in the background, as soon as the app opens. */
let apiReady = null, db = null;
function localApi() {
  apiReady ??= (async () => {
    Object.assign(process.env, { QPR_LOCAL: '1', DATABASE_URL: 'local', AUTH_SECRET: authSecret() });
    db = await import(pathToFileURL(path.join(__dirname, 'local-db.mjs')).href);
    await db.open(path.join(DATA, 'database'));
    return (await import(pathToFileURL(path.join(APP_DIR, 'api.mjs')).href)).default;
  })().catch(e => { apiReady = null; throw e; });
  return apiReady;
}
const json = (status, o) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
async function callApi(req, u) {
  let handler;
  try { handler = await localApi(); }
  catch (e) { return json(500, { error: 'The app could not open its database: ' + String(e && e.message || e).slice(0, 300) }); }
  const query = Object.fromEntries(u.searchParams); query.path = u.pathname.replace(/^\/api\/?/, '');
  let body = {};
  if (!['GET', 'HEAD'].includes(req.method)) { const t = await req.text(); if (t) { try { body = JSON.parse(t); } catch { return json(400, { error: 'Bad request.' }); } } }
  const headers = { authorization: req.headers.get('authorization') || '', 'user-agent': req.headers.get('user-agent') || '' };
  return new Promise(resolve => {
    const res = { code: 200, h: {}, status(c) { this.code = c; return this; }, setHeader(k, v) { this.h[String(k).toLowerCase()] = v; return this; },
      json(o) { resolve(json(this.code, o)); }, send(b) { resolve(new Response(b, { status: this.code, headers: { ...this.h, 'cache-control': 'no-store' } })); } };
    Promise.resolve(handler({ method: req.method, headers, query, body }, res)).catch(() => resolve(json(500, { error: 'Local data store error.' })));
  });
}

/* Build identity: SHA-256 of the page actually loaded, and the hash recorded at build time */
let buildJson = {}; try { buildJson = JSON.parse(fs.readFileSync(path.join(APP_DIR, 'build.json'), 'utf8')); } catch {}
const pageHash = (() => { try { return crypto.createHash('sha256').update(fs.readFileSync(path.join(APP_DIR, 'index.html'))).digest('hex'); } catch { return null; } })();

/* Power and network events: the page uses them to tell whether the PC is offline (rolls need it), and to note clock changes */
let win = null, resumeCount = 0, lastResumeAt = null, adapterKey = '';
function adapters() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) if ((addrs || []).some(a => !a.internal)) out.push(name);
  return out.sort();
}
const send = (ch, ...a) => { if (win && !win.isDestroyed()) win.webContents.send(ch, ...a); };

/* QP-Draw certificate: the page hands over the finished certificate HTML; it is rendered in a hidden window with
   scripts off, then saved as a real PDF (Chromium's print engine) or sent to the printer with the system dialog. */
async function renderHidden(html) {
  const file = path.join(app.getPath('temp'), `qpr-certificate-${process.pid}-${Date.now()}.html`);
  fs.writeFileSync(file, html);
  const w = new BrowserWindow({ show: false, width: 900, height: 1200, webPreferences: { javascript: false, sandbox: true, contextIsolation: true, nodeIntegration: false } });
  try { await w.loadFile(file); return w; } finally { try { fs.unlinkSync(file); } catch {} }
}
async function savePdf(html, name) {
  if (typeof html !== 'string' || html.length > 20e6) return { error: 'bad input' };
  const safe = String(name || 'certificate.pdf').replace(/[^\w.-]+/g, '_').slice(0, 140);
  let target = null;
  if (process.env.QPR_TEST_PDF_DIR) target = path.join(process.env.QPR_TEST_PDF_DIR, safe);   // automated tests only
  else { const r = await dialog.showSaveDialog(win, { defaultPath: path.join(app.getPath('documents'), safe), filters: [{ name: 'PDF', extensions: ['pdf'] }] }); if (r.canceled || !r.filePath) return { canceled: true }; target = r.filePath; }
  const w = await renderHidden(html);
  try {
    const buf = await w.webContents.printToPDF({ printBackground: true, preferCSSPageSize: true, pageSize: 'A4', margins: { top: 0, bottom: 0, left: 0, right: 0 } });
    fs.writeFileSync(target, buf); return { saved: target, bytes: buf.length };
  } catch (err) { return { error: String(err.message || err) }; } finally { w.destroy(); }
}
async function printHtml(html) {
  if (typeof html !== 'string' || html.length > 20e6) return { error: 'bad input' };
  const w = await renderHidden(html);
  return new Promise(resolve => w.webContents.print({ silent: false, printBackground: true }, (ok, reason) => { w.destroy(); resolve(ok ? { ok: true } : { ok: false, error: reason && reason !== 'cancelled' ? reason : null }); }));
}

protocol.registerSchemesAsPrivileged([{ scheme: 'app', privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: true, stream: true } }]);
const CSP = `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' ${PUBLIC_PROBES}; frame-src 'self' about: blob: data:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;

async function handle(req) {
  const u = new URL(req.url);
  if (u.host !== 'qpr') return new Response('Not found', { status: 404 });
  if (u.pathname === '/api' || u.pathname.startsWith('/api/')) return callApi(req, u);
  const rel = u.pathname === '/' ? 'index.html' : decodeURIComponent(u.pathname).replace(/^\/+/, '');
  const file = path.join(APP_DIR, rel);
  if (!file.startsWith(APP_DIR + path.sep) || !['index.html', 'build.json'].includes(rel)) return new Response('Not found', { status: 404 });
  try {
    const body = fs.readFileSync(file);
    return new Response(body, { headers: { 'content-type': rel.endsWith('.html') ? 'text/html; charset=utf-8' : 'application/json', 'content-security-policy': CSP, 'cache-control': 'no-store' } });
  } catch { return new Response('Not found', { status: 404 }); }
}

function createWindow() {
  win = new BrowserWindow({
    width: 1366, height: 860, minWidth: 960, minHeight: 620, show: false, backgroundColor: '#DCE3E1', autoHideMenuBar: true,
    title: 'UPESSC Question Paper Randomization', icon: path.join(APP_DIR, 'icon.png'),
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, sandbox: true, nodeIntegration: false, spellcheck: false,
      devTools: !app.isPackaged || process.env.QPR_DEVTOOLS === '1' }
  });
  win.once('ready-to-show', () => { win.maximize(); win.show(); });
  win.loadURL('app://qpr/index.html');
  win.webContents.setWindowOpenHandler(({ url }) => { if (/^https:\/\//.test(url)) shell.openExternal(url); return { action: 'deny' }; });
  win.webContents.on('will-navigate', (e, url) => { if (!url.startsWith('app://qpr/')) e.preventDefault(); });
  // F5 reloads, Ctrl + / Ctrl - / Ctrl 0 zoom (there is no menu bar)
  win.webContents.on('before-input-event', (e, i) => {
    if (i.type !== 'keyDown') return;
    const wc = win.webContents;
    if (i.key === 'F5') { e.preventDefault(); wc.reload(); }
    else if (i.control && (i.key === '=' || i.key === '+')) { e.preventDefault(); wc.setZoomLevel(Math.min(wc.getZoomLevel() + 0.5, 3)); }
    else if (i.control && i.key === '-') { e.preventDefault(); wc.setZoomLevel(Math.max(wc.getZoomLevel() - 0.5, -3)); }
    else if (i.control && i.key === '0') { e.preventDefault(); wc.setZoomLevel(0); }
  });
  // Windows tells every top-level window when the system time is changed (WM_TIMECHANGE); the page notes it in its audit log
  if (process.platform === 'win32') win.hookWindowMessage(0x001E, () => send('qpr:time-changed'));
  win.on('closed', () => { win = null; });
}

if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
  app.setAppUserModelId('in.upessc.qpr');
  Menu.setApplicationMenu(null);
  try { firstStart(); } catch {}
  app.whenReady().then(() => {
    protocol.handle('app', handle);
    localApi().catch(() => {});   // open the database while the window loads
    session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
    session.defaultSession.on('will-download', (_e, item) => item.setSaveDialogOptions({ defaultPath: path.join(app.getPath('documents'), item.getFilename()) }));
    ipcMain.handle('qpr:info', () => ({ appVersion: app.getVersion(), buildHash: pageHash, buildHashExpected: buildJson.buildHash || null, builtAt: buildJson.builtAt || null,
      electron: process.versions.electron, os: `${os.type()} ${os.release()} ${os.arch()}`, computer: os.hostname(), local: true }));
    ipcMain.handle('qpr:network', () => { const a = adapters(); return { link: a.length > 0, adapters: a }; });
    ipcMain.handle('qpr:clock', () => ({ uptimeMs: Math.round(os.uptime() * 1000), resumeCount, lastResumeAt }));
    ipcMain.handle('qpr:save-pdf', (_e, html, name) => savePdf(html, name));
    ipcMain.handle('qpr:print-html', (_e, html) => printHtml(html));
    powerMonitor.on('resume', () => { resumeCount++; lastResumeAt = Date.now(); send('qpr:time-changed'); });
    setInterval(() => { const k = adapters().join('|'); if (k !== adapterKey) { adapterKey = k; send('qpr:network-changed'); } }, 2000);
    adapterKey = adapters().join('|');
    createWindow();
  });
  app.on('window-all-closed', () => app.quit());
  // close the database cleanly before the app exits
  let closing = false;
  app.on('will-quit', e => {
    if (closing || !db) return;
    e.preventDefault(); closing = true;
    db.close().catch(() => {}).finally(() => app.exit(0));
  });
}
