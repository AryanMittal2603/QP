# UPESSC QP Randomization System

A portal that randomizes the Commission's question paper colours: five independent draws per exam × shift × subject, ending with one final colour. The randomization itself runs **offline on a stand-alone PC**, and every draw is kept in a tamper-evident audit trail.

Live: https://upessc-qpr.vercel.app

## Logins and approval

Three consoles: **Admin**, **Randomization** and **Approver**.

- **Approver.** Created once from the Approver Console with the server's `SETUP_KEY`, a name and a mobile number verified by OTP. The approver reviews every request for a new login, approves or rejects it, adds Admin / Randomizer users directly, and disables or re-enables logins.
- **New Admin or Randomizer login.** On the Admin or Randomization login screen, "Create new login": name + mobile number → 6-digit OTP by SMS → choose a password. The request then waits for the approver. It shows the mobile number, login type, the time of every attempt (repeat requests are grouped), and the device, browser, OS, screen, IP address and location, network, PC time zone and clock offset, and app version. After approval the person logs in with mobile number + password.
- **Users added by the approver** are already approved: they verify their number once with "Create new login" (OTP + password) and can log in straight away.
- **Forgot password** resets it with an OTP. Pending, rejected and disabled logins get a clear message instead of "wrong password". A disabled login stops working on the next request.
- OTPs are valid for 5 minutes, allow 5 wrong tries, can be resent after 60 seconds, and are limited to 5 per number per hour.
- The older username/password admin account and the shared Randomization login still work.
- A Randomization PC can log in offline only people who have logged in online on that PC before. Logins the approver disables or rejects are removed from the PC at its next online login.

## How it works (hybrid online / offline)

1. **Admin Console (online).** Create exams, then shifts (date + allowed randomization window), then subjects with their question paper colours. Upload the logo. Then **publish** the exam. Everything is stored in Neon Postgres, and every admin action goes into a server-side SHA-256 hash-chained audit log.
2. **Randomization Console, login (online).** The randomizer logs in once while online. The latest published exams, shifts and settings are downloaded, and the login is cached in the browser (IndexedDB) for offline use. A service worker caches the page.
3. **Disconnect the network.** The dice are **disabled while the PC is online**. Offline, each subject row shows 1st → 4th → Final. Every click is one independent draw using `crypto.getRandomValues` with rejection sampling. The draw is written atomically with a hash-chained audit entry *before* the animation runs, and the cell is locked permanently. A shift locks once every subject has a final colour.
   **Final iteration:** each exam is either *fixed* (the 5th roll gives the final colour) or *random*: before the first roll, the Randomization PC draws the final iteration (3rd–7th, each equally likely) with the same secure random draw, offline and inside the shift window. The result is written to the audit log and locked for every shift and subject of the exam.
4. **Reconnect.** The local audit chain and draws are uploaded automatically. The server re-verifies the chain, stores it append-only, accepts only draws backed by a matching audit entry, and records conflicts. The admin "Results & Sync" tab shows the results, the PCs that synced, and any conflicts.

Other safeguards:
- Draws are only allowed inside the shift's time window. The PC clock is the source of truth: clock rollback and drift from server time are flagged in the log.
- Audit logs can be exported as JSON or CSV, and results as CSV.

## Project layout

- `index.html` — the whole UI (all three consoles), no build step
- `sw.js` — offline page cache
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
