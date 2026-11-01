// Copies the web app (../index.html) into app/ and records its SHA-256, so the Windows app can show and log
// which build it runs, and whether the page it loads is exactly the one that was built.
const fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const root = path.resolve(__dirname, '..'), app = path.join(root, 'app');
fs.mkdirSync(app, { recursive: true });
const html = fs.readFileSync(path.join(root, '..', 'index.html'));
const pkg = require(path.join(root, 'package.json'));
const ver = (String(html).match(/const APP_VERSION = '([^']+)'/) || [])[1];
if (ver !== pkg.version) { console.error(`Version mismatch: index.html says ${ver}, desktop/package.json says ${pkg.version}`); process.exit(1); }
fs.writeFileSync(path.join(app, 'index.html'), html);
fs.copyFileSync(path.join(__dirname, 'icon.png'), path.join(app, 'icon.png'));
const buildHash = crypto.createHash('sha256').update(html).digest('hex');
fs.writeFileSync(path.join(app, 'build.json'), JSON.stringify({ version: pkg.version, buildHash, builtAt: new Date().toISOString() }, null, 2));
console.log(`app/index.html  v${pkg.version}  sha256 ${buildHash}`);
