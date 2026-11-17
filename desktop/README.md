# UPESSC QPR — Windows app

`UPESSC-QPR-Setup-<version>.exe` installs the app for the current Windows user (64-bit Windows 10/11, no admin rights
needed) and adds **UPESSC QPR** to the Start menu and the desktop. It opens straight away after installing.

## Works on its own, on one computer

From version 3.0 the app does not use the internet or the UPESSC server at all. Everything stays on that computer:
the logins, the exams, every roll, the results, the hash-chained audit logs and the QP-Draw certificates. The website
(https://upessc-qpr.vercel.app) keeps its own, separate data online; the two are not connected.

- **First start.** Only the built-in Verifier can sign in: `upessc_verifier` with the default password `upessc@2026`,
  which must be changed straight away. On this computer nobody else can reset the Verifier's password, so keep it safe.
- **Verifier console.** Creates the Admin logins, and sets the Controller of Examinations and Chairman logins
  (name, designation and password for each post).
- **Admin.** Sets up exams, shifts, subjects and colours on this computer and publishes them; *Results & Sync* shows
  every draw made on this computer, and the QP-Draw certificate.
- **Randomizer page.** Opened with the Verifier's login. Then step 1: the Controller of Examinations enters only
  their password; step 2: the Chairman enters only their password. Spins are possible only after both, and only
  while this computer has no internet connection (disconnect Wi-Fi / LAN cable / hotspot).
- **Stays signed in** until *Log out*, also across restarts.
- **Clock.** Times are always shown and judged in IST. A change of the PC clock is written to the audit log and
  shown, but never blocks anything.

Data folder: `%APPDATA%\UPESSC QPR 3` (database, settings, audit logs). Uninstalling keeps it; delete that folder
to start again from scratch. On its first start, 3.0 removes the data of older versions (`%APPDATA%\UPESSC QPR`).

## Build

```
cd desktop
npm install
npm run dist        # → ../release/UPESSC-QPR-Setup-<version>.exe
npm start           # run it locally without packaging
```

`npm run dist` copies `../index.html` (the page) and `../api/index.js` (the API, pointed at the local database in
`local-db.mjs`, which is PostgreSQL compiled to WebAssembly) into `app/`, records the page's SHA-256 in
`app/build.json`, packages it with Electron and builds the installer. It works on Windows, macOS and Linux.
The version in `desktop/package.json` must match `APP_VERSION` in `index.html`.

The installer is not code-signed, so Windows SmartScreen may show "Windows protected your PC" the first time:
*More info → Run anyway*. Signing it with the Commission's code-signing certificate removes that prompt.
