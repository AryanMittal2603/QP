// Copies the web app (../index.html) and the shared API code (../api/index.js) into app/, and records the page's SHA-256,
// so the Windows app can show and log which build it runs. In the app, the API uses the local database (local-db.mjs)
// instead of the online one.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const root = path.resolve(__dirname, '..'), app = path.join(root, 'app');
fs.mkdirSync(app, { recursive: true });
const html = fs.readFileSync(path.join(root, '..', 'index.html'));
const pkg = require(path.join(root, 'package.json'));
const ver = (String(html).match(/const APP_VERSION = '([^']+)'/) || [])[1];
if (ver !== pkg.version) { console.error(`Version mismatch: index.html says ${ver}, desktop/package.json says ${pkg.version}`); process.exit(1); }
fs.writeFileSync(path.join(app, 'index.html'), html);
fs.copyFileSync(path.join(__dirname, 'icon.png'), path.join(app, 'icon.png'));
const ONLINE = "import { neon } from '@neondatabase/serverless';";
const api = fs.readFileSync(path.join(root, '..', 'api', 'index.js'), 'utf8');
if (api.split(ONLINE).length !== 2) { console.error('api/index.js: database import line not found'); process.exit(1); }
fs.writeFileSync(path.join(app, 'api.mjs'), api.replace(ONLINE, "import { neon } from '../local-db.mjs';   // Windows app: the database on this computer"));
const buildHash = crypto.createHash('sha256').update(html).digest('hex');
fs.writeFileSync(path.join(app, 'build.json'), JSON.stringify({ version: pkg.version, buildHash, builtAt: new Date().toISOString() }, null, 2));
console.log(`app/index.html  v${pkg.version}  sha256 ${buildHash}`);
console.log('app/api.mjs     from api/index.js (local database)');
