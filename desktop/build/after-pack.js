// Puts the UPESSC icon and version details into the Windows .exe (works on Linux/macOS too, no Wine needed).
const fs = require('node:fs'), path = require('node:path');
exports.default = async function afterPack(ctx) {
  if (ctx.electronPlatformName !== 'win32') return;
  const R = await import('resedit');
  const exe = path.join(ctx.appOutDir, `${ctx.packager.appInfo.productFilename}.exe`);
  const pe = R.NtExecutable.from(fs.readFileSync(exe), { ignoreCert: true });
  const res = R.NtExecutableResource.from(pe);
  const icons = R.Data.IconFile.from(fs.readFileSync(path.join(__dirname, 'icon.ico'))).icons.map(i => i.data);
  const group = R.Resource.IconGroupEntry.fromEntries(res.entries)[0];
  R.Resource.IconGroupEntry.replaceIconsForResource(res.entries, group ? group.id : 1, group ? group.lang : 1033, icons);
  const v = ctx.packager.appInfo.version, [a, b, c] = v.split('.').map(Number);
  const vi = R.Resource.VersionInfo.fromEntries(res.entries)[0] || R.Resource.VersionInfo.createEmpty();
  const lang = (vi.getAllLanguagesForStringValues()[0]) || { lang: 1033, codepage: 1200 };
  vi.setFileVersion(a, b, c, 0, lang.lang); vi.setProductVersion(a, b, c, 0, lang.lang);
  vi.setStringValues(lang, { CompanyName: 'UPESSC', FileDescription: 'UPESSC Question Paper Randomization', ProductName: 'UPESSC QPR', InternalName: 'UPESSC QPR',
    OriginalFilename: 'UPESSC QPR.exe', LegalCopyright: 'Uttar Pradesh Education Service Selection Commission', FileVersion: v, ProductVersion: v });
  vi.outputToResourceEntries(res.entries);
  res.outputResource(pe);
  fs.writeFileSync(exe, Buffer.from(pe.generate()));
  console.log('  • set UPESSC icon and version info on', path.basename(exe));
};
