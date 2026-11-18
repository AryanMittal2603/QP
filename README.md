# UPESSC QP Randomization System

A portal that randomizes the Commission's question paper colours: five independent draws per exam × shift × subject, ending with one final colour. The randomization itself runs **offline on a stand-alone PC**, and every draw is kept in a tamper-evident audit trail.

Live: https://upessc-qpr.vercel.app

**Windows app (3.0):** `UPESSC-QPR-Setup-<version>.exe` installs an app that works **on its own, on one computer**: its logins, exams, rolls, results, audit logs and certificates stay on that computer, with no server and no internet needed. The website keeps its own, separate data online. See [desktop/README.md](desktop/README.md).

## Logins

There is no sign-up, OTP or mobile number. Every login is a username and password created by the **Verifier**.

- **Verifier.** One built-in login: `upessc_verifier`, default password `upessc@2026`. The default password must be changed at the first sign-in; nothing else works until it is. On a fresh database (or a new Windows app installation) only the Verifier can sign in. The Verifier console creates, resets, disables and deletes the **Admin** logins, and sets the **Controller of Examinations** and **Chairman** logins (one per post: name, designation, password).
- **Admin** signs in with the username and password the Verifier gave. Admins set up exams, shifts, subjects and colours, publish them, and see the results.
- **Randomizer page.** The sign-in screen opens on it. **Step 1:** the Controller of Examinations enters only their password, **step 2:** the Chairman enters only their password; the page opens only after both (no Verifier login). The Admin and Verifier sign-ins are under **Other users**; their names, designations and sign-in times are recorded with every draw and printed on the QP-Draw certificate.
- Accounts are checked on every request: a disabled login stops working at once, and a changed or reset password ends the sessions opened with the old one.
- On the website, signing in needs the internet; once the Randomizer page is open (and the committee has signed in), it randomizes offline.

## How it works (hybrid online / offline)

On the website (in the Windows app, all of this happens on the same computer, without the internet):

1. **Admin Console (online).** Create exams, then shifts (date + allowed randomization window), then subjects with their question paper colours. Upload the logo. Then **publish** the exam. Everything is stored in Neon Postgres, and every admin action goes into a server-side SHA-256 hash-chained audit log.
2. **Randomizer page, sign-in (online).** The Controller of Examinations (step 1) and then the Chairman (step 2) sign in while online. The latest published exams, shifts and settings are downloaded and the PC clock is checked against the server. **Update exams** downloads again later; this also happens automatically whenever the internet comes back.
3. **Disconnect the internet.** The dice are **disabled while the PC can reach the internet**. The app checks this actively (a network adapter, the UPESSC server, and public "is there internet?" sites, every 10–30 seconds and again right before every roll), and measures speed and latency while online. Offline, each subject row shows 1st → 4th → Final. Every click is one independent draw using `crypto.getRandomValues` with rejection sampling. The draw is written atomically with a hash-chained audit entry *before* the animation runs, and the cell is locked permanently. A shift locks once every subject has a final colour.
   **Final colour mode** (per exam): *fixed* (the 5th roll gives the final colour); *Best of 5* (5 spins, the colour that comes up most often is final; if colours tie, one tie-breaker spin among only the tied colours decides); or *random*: before the first roll, the Randomization PC draws the final iteration (3rd–7th, each equally likely) with the same secure random draw, offline and inside the shift window. The result is written to the audit log and locked for every shift and subject of the exam.
4. **Reconnect.** The local audit chain and draws are uploaded automatically. The server re-verifies the chain, stores it append-only, accepts only draws backed by a matching audit entry, and records conflicts. The admin "Results & Sync" tab shows the results, the PCs that synced, and any conflicts.

Other safeguards:
- Draws are only allowed inside the shift's time window, which is always judged in **IST**, whatever the PC's time zone (a PC not set to IST gets a warning).
- **Clock checks (website).** Whenever the PC is online its clock is compared with the server's (must be within 2 minutes). Rolls for a shift need such a check on the shift's own date. While the page runs, the clock is compared with a monotonic timer every 5 seconds, and it may never go back past the latest time seen (also across restarts). Any change after the last check blocks rolls until the PC has been online again for a moment. At sync, the server flags log entries and draws dated in its future, and draws outside the IST window. **In the Windows app** there is no server to check against: clock changes are only recorded in the audit log and shown, never blocking.
- **Build hash.** The SHA-256 of the running page is shown in the footer and written into every login, app start and draw, for later verification against the published hash.
- **Results tab** on the Randomization PC: every roll, turn by turn (which colour came up on which attempt), shift-wise and exam-wise, stored on that PC.
- **QP-Draw certificate** (one per shift, once every subject has its final colour): examination details, the final colour of each subject, every spin/attempt with time and audit log entry, the frequency count and tie-breaker in Best of 5, the Controller of Examinations and Chairman with their sign-in times, the PC and build, the SHA-256 hash-chain seal, and the signature lines set in Admin → Settings. Print or download as PDF on the Randomization PC (works offline; the Windows app saves a real PDF), and from Admin → Results & Sync after the PC has synced.
- **Clear this PC** (website, Randomizer page, Audit Log tab): deletes the exams, rolls and audit log kept in that browser, for test PCs or after a server reset. Needs the internet, the Controller of Examinations' and the Chairman's passwords and typing CLEAR; the server records it, and the PC gets a new install ID.
- **Resetting the server:** `DATABASE_URL=… node tools/wipe-exam-data.mjs` deletes all exams and results (logins, settings and the server audit log are kept, and the wipe is recorded there). With `--logins` it also deletes every login, leaving only the built-in Verifier with its default password (which must be changed at the next sign-in). After a reset, a browser that still holds older data is refused at sync and told to use *Clear this PC*.
- Windows apps older than 3.0 (which talked to the server) are refused by the server.
- **Archive or delete an exam (Admin console).** An exam can be **deleted** until its randomization is complete; if spins were already made, the Admin has to type DELETE, and those spins stay in the audit logs and in the Randomizer page's Results, marked as deleted. Once an exam is **closed** (randomization complete, or every shift's window over) it can be **archived**: it becomes read-only and leaves the Randomizer page's exam list, while its results and QP-Draw certificates stay; *Restore* brings it back. A completed exam can only be archived, never deleted. The server enforces these rules and records each action in its audit log.
- Audit logs can be exported as JSON or CSV, and results as CSV.

## Project layout

- `index.html` — the whole UI (Admin, Randomizer page, Verifier console), no build step
- `sw.js` — offline page cache (website only)
- `tools/wipe-exam-data.mjs` — deletes all exam data (and with `--logins`, every login) from the database (asks for confirmation)
- `desktop/` — the Windows app (Electron): runs `index.html` and the same `api/index.js` on a database on that computer; `npm run dist` builds the installer into `release/`
- `api/index.js` — single serverless function (all routes), Neon Postgres (or the Windows app's local database)
- `vercel.json` — rewrites `/api/*` to the function

## Environment (Vercel)

- `DATABASE_URL` — set by the Neon integration
- `AUTH_SECRET` — HMAC key for session tokens

The schema, and the built-in Verifier login, are created automatically on the first request. The SMS / OTP settings of earlier versions (`SETUP_KEY`, `SMS_*`) are no longer used.
