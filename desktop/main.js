'use strict';
/* UPESSC QPR — Windows app.
   Runs the same page as the website (app/index.html, copied from ../index.html at build time) inside a locked-down
   window. Calls to /api/* are relayed to the UPESSC server, so Admin, Randomizer and Approver logins all work against
   the same setup. Everything the page stores (sessions, exams, rolls, audit log) stays in this app's data folder. */
const { app, BrowserWindow, protocol, net, ipcMain, powerMonitor, shell, Menu, session } = require('electron');
const path = require('node:path'), fs = require('node:fs'), os = require('node:os'), crypto = require('node:crypto');
const { execFile } = require('node:child_process');

const DEFAULT_SERVER = 'https://upessc-qpr.vercel.app';
const APP_DIR = path.join(__dirname, 'app');
const PUBLIC_PROBES = 'https://www.gstatic.com https://www.google.com https://1.1.1.1';

/* Data folder: %APPDATA%\UPESSC QPR by default. A folder named "QPR-data" next to the .exe keeps all data with the .exe instead. */
const exePath = process.env.PORTABLE_EXECUTABLE_FILE || process.execPath;
const portableData = path.join(path.dirname(exePath), 'QPR-data');
try { if (fs.statSync(portableData).isDirectory()) app.setPath('userData', portableData); } catch {}

/* Server: the UPESSC deployment, or "server" in config.json in the data folder (https only; http only for localhost testing) */
function serverUrl() {
  const ok = u => typeof u === 'string' && (/^https:\/\/[a-z0-9.-]+(:\d+)?$/i.test(u) || /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(u));
  try { const c = JSON.parse(fs.readFileSync(path.join(app.getPath('userData'), 'config.json'), 'utf8')); if (ok(c.server)) return c.server; } catch {}
  if (ok(process.env.QPR_SERVER)) return process.env.QPR_SERVER;
  return DEFAULT_SERVER;
}

/* Build identity: SHA-256 of the page actually loaded (checked against the hash recorded at build time) and of the .exe */
const sha256File = file => new Promise(resolve => {
  const h = crypto.createHash('sha256'), s = fs.createReadStream(file);
  s.on('data', d => h.update(d)); s.on('end', () => resolve(h.digest('hex'))); s.on('error', () => resolve(null));
});
let buildJson = {}; try { buildJson = JSON.parse(fs.readFileSync(path.join(APP_DIR, 'build.json'), 'utf8')); } catch {}
const pageHash = (() => { try { return crypto.createHash('sha256').update(fs.readFileSync(path.join(APP_DIR, 'index.html'))).digest('hex'); } catch { return null; } })();
const exeHash = app.isPackaged ? sha256File(exePath) : Promise.resolve(null);

/* Power and network events for the page's clock and network checks */
let win = null, resumeCount = 0, lastResumeAt = null, adapterKey = '';
function adapters() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) if ((addrs || []).some(a => !a.internal)) out.push(name);
  return out.sort();
}
const send = (ch, ...a) => { if (win && !win.isDestroyed()) win.webContents.send(ch, ...a); };

/* Clock changes recorded by Windows itself (System log, Microsoft-Windows-Kernel-General event 1), since a given time */
function windowsTimeChanges(sinceIso) {
  if (process.platform !== 'win32') return Promise.resolve({ ok: false, error: 'only on Windows' });
  const since = new Date(sinceIso);
  if (isNaN(since)) return Promise.resolve({ ok: false, error: 'bad date' });
  const q = `*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and (EventID=1) and TimeCreated[@SystemTime>='${since.toISOString()}']]]`;
  return new Promise(resolve => execFile('wevtutil.exe', ['qe', 'System', '/q:' + q, '/f:xml', '/c:50', '/rd:true'], { windowsHide: true, timeout: 10000, maxBuffer: 8 << 20 }, (err, out) => {
    if (err) return resolve({ ok: false, error: String(err.message || err).slice(0, 300) });
    const parseTime = v => Date.parse(String(v).replace(/[^\dTZ:.+-]/g, '').replace(/(\.\d{3})\d+/, '$1'));
    const changes = [];
    for (const ev of String(out).split(/<\/Event>/)) {
      const get = n => { const m = ev.match(new RegExp(`<Data Name=['"]${n}['"]>([^<]*)</Data>`)); return m ? m[1].trim() : null; };
      const n = parseTime(get('NewTime')), o = parseTime(get('OldTime'));
      if (!Number.isFinite(n) || !Number.isFinite(o)) continue;
      changes.push({ recordId: (ev.match(/<EventRecordID>(\d+)<\/EventRecordID>/) || [])[1] || null, newTime: new Date(n).toISOString(), oldTime: new Date(o).toISOString(),
        deltaMs: n - o, reason: get('Reason'), process: get('ProcessName') });
    }
    resolve({ ok: true, changes });
  }));
}

protocol.registerSchemesAsPrivileged([{ scheme: 'app', privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: true, stream: true } }]);
const CSP = `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' ${PUBLIC_PROBES}; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;

async function handle(req) {
  const u = new URL(req.url);
  if (u.host !== 'qpr') return new Response('Not found', { status: 404 });
  if (u.pathname === '/api' || u.pathname.startsWith('/api/')) {
    const headers = { 'x-qpr-app': 'windows/' + app.getVersion() };
    for (const k of ['content-type', 'authorization']) { const v = req.headers.get(k); if (v) headers[k] = v; }
    const init = { method: req.method, headers, cache: 'no-store' };
    if (!['GET', 'HEAD'].includes(req.method)) init.body = Buffer.from(await req.arrayBuffer());
    try {
      const r = await net.fetch(serverUrl() + u.pathname + u.search, init);
      return new Response(r.body, { status: r.status, headers: { 'content-type': r.headers.get('content-type') || 'application/json', 'cache-control': 'no-store' } });
    } catch { return Response.error(); }   // no internet: the page sees a network error, as in a browser
  }
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
  // Windows tells every top-level window when the system time is changed (WM_TIMECHANGE)
  if (process.platform === 'win32') win.hookWindowMessage(0x001E, () => send('qpr:time-changed'));
  win.on('closed', () => { win = null; });
}

if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on('second-instance', () => { if (win) { if (win.isMinimized()) win.restore(); win.focus(); } });
  app.setAppUserModelId('in.upessc.qpr');
  Menu.setApplicationMenu(null);
  app.whenReady().then(() => {
    protocol.handle('app', handle);
    session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
    session.defaultSession.on('will-download', (_e, item) => item.setSaveDialogOptions({ defaultPath: path.join(app.getPath('documents'), item.getFilename()) }));
    ipcMain.handle('qpr:info', async () => ({ appVersion: app.getVersion(), buildHash: pageHash, buildHashExpected: buildJson.buildHash || null, builtAt: buildJson.builtAt || null,
      exeHash: await exeHash, exeName: path.basename(exePath), electron: process.versions.electron, os: `${os.type()} ${os.release()} ${os.arch()}`, computer: os.hostname(), server: serverUrl() }));
    ipcMain.handle('qpr:network', () => { const a = adapters(); return { link: a.length > 0, adapters: a }; });
    ipcMain.handle('qpr:clock', () => ({ uptimeMs: Math.round(os.uptime() * 1000), resumeCount, lastResumeAt }));
    ipcMain.handle('qpr:time-changes', (_e, since) => windowsTimeChanges(since));
    powerMonitor.on('resume', () => { resumeCount++; lastResumeAt = Date.now(); send('qpr:time-changed'); });
    setInterval(() => { const k = adapters().join('|'); if (k !== adapterKey) { adapterKey = k; send('qpr:network-changed'); } }, 2000);
    adapterKey = adapters().join('|');
    createWindow();
  });
  app.on('window-all-closed', () => app.quit());
}
