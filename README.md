# UPESSC QP Randomization System

A portal that randomizes the Commission's colour-coded question paper sets: five independent draws per exam × shift × subject, ending with one final colour. The randomization itself runs **offline on a stand-alone PC**, and every draw is kept in a tamper-evident audit trail.

Live: https://upessc-qpr.vercel.app

## How it works (hybrid online / offline)

1. **Admin Console (online).** Create exams, then shifts (date + allowed randomization window), then subjects with their colour-coded QP sets. Set the single Randomization Console login and upload the logo. Then **publish** the exam. Everything is stored in Neon Postgres, and every admin action goes into a server-side SHA-256 hash-chained audit log.
2. **Randomization Console, login (online).** The head client logs in once while online. All published exams and the login are downloaded and cached in the browser (IndexedDB). A service worker caches the page.
3. **Disconnect the network.** The dice are **disabled while the PC is online**. Offline, each subject row shows 1st → 4th → Final. Every click is one independent draw using `crypto.getRandomValues` with rejection sampling. The draw is written atomically with a hash-chained audit entry *before* the animation runs, and the cell is locked permanently. A shift locks once every subject has a final set.
4. **Reconnect.** The local audit chain and draws are uploaded automatically. The server re-verifies the chain, stores it append-only, accepts only draws backed by a matching audit entry, and records conflicts. The admin "Results & Sync" tab shows the results, the PCs that synced, and any conflicts.

Other safeguards:
- Draws are only allowed inside the shift's time window. The PC clock is the source of truth: clock rollback and drift from server time are flagged in the log.
- Audit logs can be exported as JSON or CSV, and results as CSV.
- An encrypted offline package (`.qpr`, AES-256-GCM) is available as a backup for a PC that can never go online.

## Project layout

- `index.html` — the whole UI (both consoles), no build step
- `sw.js` — offline page cache
- `api/index.js` — single serverless function (all routes), Neon Postgres
- `vercel.json` — rewrites `/api/*` to the function

## Environment (Vercel)

- `DATABASE_URL` — set by the Neon integration
- `AUTH_SECRET` — HMAC key for session tokens
- `SETUP_KEY` — one-time key required to create the first administrator

The schema is created automatically on the first request.
