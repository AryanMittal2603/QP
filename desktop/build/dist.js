// Builds the Windows installer (release/UPESSC-QPR-Setup-<version>.exe) with electron-builder.
// To make the installer's uninstaller, electron-builder normally runs a first-pass installer under Wine when it is not
// on Windows. It can instead read the uninstaller straight out of that file (what it does on macOS), so on Linux
// and macOS no Wine is needed.
const mv = require('app-builder-lib/out/util/macosVersion');
if (process.platform !== 'win32') mv.isMacOsCatalina = () => true;
const { build, Platform, Arch } = require('electron-builder');
build({ targets: Platform.WINDOWS.createTarget('nsis', Arch.x64), publish: 'never' })
  .then(files => console.log('built:\n  ' + files.join('\n  ')))
  .catch(e => { console.error(e); process.exit(1); });
