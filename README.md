# UPESSC QP Randomization System

A portal that randomizes the Commission's question paper colours: five independent draws per exam × shift × subject, ending with one final colour. The randomization itself runs **offline on a stand-alone PC**, and every draw is kept in a tamper-evident audit trail.

Live: https://upessc-qpr.vercel.app

**Windows app:** `UPESSC-QPR-<version>-portable.exe` runs the same Admin, Randomizer and Approver logins against the same server, and keeps the Randomizer's rolls, turn logs and audit log on that PC. See [desktop/README.md](desktop/README.md).

## Logins and approval

Three consoles: **Admin**, **Randomization** and **Approver**.

- **Approver.** Created once from the Approver Console with the server's `SETUP_KEY`, a name and a mobile number verified by OTP. The approver reviews every request for a new login, approves or rejects it, adds Admin / Randomizer users directly, and disables or re-enables logins.
- **New Admin or Randomizer login.** On the Admin or Randomization login screen, "Create new login": name + mobile number → 6-digit OTP by SMS → choose a password. The request then waits for the approver. It shows the mobile number, login type, the time of every attempt (repeat requests are grouped), and the device, browser, OS, screen, IP address and location, network, PC time zone and clock offset, and app version. After approval the person logs in with mobile number + password.
- **Users added by the approver** are already approved: they verify their number once with "Create new login" (OTP + password) and can log in straight away.
- **Forgot password** resets it with an OTP. Pending, rejected and disabled logins get a clear message instead of "wrong password". A disabled login stops working on the next request.
- OTPs are valid for 5 minutes, allow 5 wrong tries, can be resent after 60 seconds, and are limited to 5 per number per hour.
- The older username/password admin account and the shared Randomization login still work.
- **Signing in always needs the internet** (no offline logins; no password hashes are kept on the PC). Once signed in, the Randomizer works offline. In the Windows app every login stays signed in until the person logs out (sessions last 60 days for the Randomizer, 30 days for Admin and Approver); if the server stops accepting a session, the app asks for the password again and keeps everything on the PC.

## How it works (hybrid online / offline)

1. **Admin Console (online).** Create exams, then shifts (date + allowed randomization window), then subjects with their question paper colours. Upload the logo. Then **publish** the exam. Everything is stored in Neon Postgres, and every admin action goes into a server-side SHA-256 hash-chained audit log.
2. **Randomization Console, login (online).** The randomizer logs in while online. The latest published exams, shifts and settings are downloaded and the PC clock is checked against the server. **Update exams** downloads again later; this also happens automatically whenever the internet comes back.
3. **Disconnect the internet.** The dice are **disabled while the PC can reach the internet**. The app checks this actively (a network adapter, the UPESSC server, and public "is there internet?" sites, every 10–30 seconds and again right before every roll), and measures speed and latency while online. Offline, each subject row shows 1st → 4th → Final. Every click is one independent draw using `crypto.getRandomValues` with rejection sampling. The draw is written atomically with a hash-chained audit entry *before* the animation runs, and the cell is locked permanently. A shift locks once every subject has a final colour.
   **Final iteration:** each exam is either *fixed* (the 5th roll gives the final colour) or *random*: before the first roll, the Randomization PC draws the final iteration (3rd–7th, each equally likely) with the same secure random draw, offline and inside the shift window. The result is written to the audit log and locked for every shift and subject of the exam.
4. **Reconnect.** The local audit chain and draws are uploaded automatically. The server re-verifies the chain, stores it append-only, accepts only draws backed by a matching audit entry, and records conflicts. The admin "Results & Sync" tab shows the results, the PCs that synced, and any conflicts.

Other safeguards:
- Draws are only allowed inside the shift's time window, which is always judged in **IST**, whatever the PC's time zone (a PC not set to IST gets a warning).
- **Clock checks.** Whenever the PC is online its clock is compared with the server's (must be within 2 minutes). Rolls for a shift need such a check on the shift's own date. While the app runs, the clock is compared with a monotonic timer every 5 seconds (the Windows app also reacts to Windows' time-change notice and ignores sleep), it may never go back past the latest time seen (also across restarts), and the Windows app reads Windows' own event log of clock changes. Any change after the last check blocks rolls until the PC has been online again for a moment. At sync, the server flags log entries and draws dated in its future, and draws outside the IST window.
- **Build hash.** The SHA-256 of the running page (and, in the Windows app, of the .exe) is shown in the footer and written into every login, app start and draw, for later verification against the published hash.
- **Results tab** on the Randomization PC: every roll, turn by turn (which colour came up on which attempt), shift-wise and exam-wise, stored on that PC.
- Audit logs can be exported as JSON or CSV, and results as CSV.

## Project layout

- `index.html` — the whole UI (all three consoles), no build step
- `sw.js` — offline page cache (website only)
- `desktop/` — the Windows app (Electron): wraps `index.html`, relays `/api` to the server; `npm run dist` builds the portable .exe into `release/`
- `api/index.js` — single serverless function (all routes), Neon Postgres
- `vercel.json` — rewrites `/api/*` to the function

## Environment (Vercel)

- `DATABASE_URL` — set by the Neon integration
- `AUTH_SECRET` — HMAC key for session tokens
- `SETUP_KEY` — one-time key required to create the approver account
- `SMS_USER`, `SMS_PASS` — SMS gateway username and password (never put these in the code)
- `SMS_TEMPLATE_ID` — DLT template ID of the OTP message
- `SMS_SENDER` — sender ID (default `SESSBA`)
- `SMS_URL` — optional, gateway address (default `http://103.234.185.173/api/swsendNK.asp`)
- `SMS_TEXT` — optional, message text with `{OTP}` where the code goes; must match the DLT template exactly (default: `{OTP} is your application number for the QP form you registered earlier. Kindly review your application by logging into upessc.org.` + line break + `-SESSBA`; write the line break as `\n`)

The schema is created automatically on the first request.
