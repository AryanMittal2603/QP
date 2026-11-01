# UPESSC QPR — Windows app

`UPESSC-QPR-<version>-portable.exe` is a single Windows file (64-bit Windows 10/11, no installation, no admin rights).
It opens the same Admin, Randomizer and Approver logins as https://upessc-qpr.vercel.app and talks to the same server,
so exams, users, approvals and synced results are shared with the website.

## What is different from the website

- **Stays signed in.** Signing in needs the internet. After that the app stays signed in until the person presses
  *Log out*, also with no internet and across restarts (Randomizer sessions last 60 days, Admin and Approver 30 days).
  If the server stops accepting the session (expired or disabled), the app asks for the password again; nothing on
  the PC is deleted.
- **Data stays on the PC.** Exams, every roll (which colour came up on which turn, shift-wise and exam-wise — see the
  **Results** tab), and the hash-chained audit log are stored in `%APPDATA%\UPESSC QPR`.
  To keep the data next to the .exe instead (for example on a USB drive), create a folder named `QPR-data` beside the .exe
  before the first start.
- **Network checks.** The app checks the network adapters, the UPESSC server and public "is there internet?" sites,
  measures speed and latency while online, and re-checks right before every roll. Rolls are allowed only when the
  internet is not reachable.
- **Clock checks.** As on the website (server check, check on the shift's date, monotonic timer), plus: Windows'
  time-change notice is caught immediately, sleep/hibernate is told apart from a clock change, and Windows' own
  event log of clock changes (System log, Kernel-General event 1) is read, so a change made while the app was closed
  is also caught.
- **Build hash.** The footer shows the SHA-256 of the page inside the app; the audit log also records the SHA-256 of
  the .exe itself (`exeHash`) at every start, login and draw, for later verification.

## Build

```
cd desktop
npm install
npm run dist        # → ../release/UPESSC-QPR-<version>-portable.exe
npm start           # run it locally without packaging
```

`npm run dist` copies `../index.html` into `app/`, records its SHA-256 in `app/build.json`, packages it with Electron,
and puts the UPESSC icon and version details into the .exe. It works on Windows, macOS and Linux. The version in
`desktop/package.json` must match `APP_VERSION` in `index.html`.

To point a copy at another deployment, put `{"server": "https://your-deployment.example"}` in `config.json` in the
data folder.

The .exe is not code-signed, so Windows SmartScreen may show "Windows protected your PC" on first start:
*More info → Run anyway*. Signing it with the Commission's code-signing certificate removes that prompt.
