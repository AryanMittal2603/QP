# UPESSC QP Randomization System

Single-file (`index.html`) tool for randomizing colour-coded question paper sets for UPESSC exams. It runs offline.

- **Admin Console**: create exams, shifts (with a randomization time window) and subjects with their colour-coded QP sets. Export an encrypted exam package (`.qpr`, AES-256-GCM).
- **Randomization Console**: import the package on the stand-alone PC, log in, then perform 5 independent draws per subject (1st–4th + Final). Each cell locks permanently the moment it is drawn.
- **Audit**: SHA-256 hash-chained log in IndexedDB. Draw records are cross-checked against the log. Clock rollback and network connectivity are flagged. Export as JSON or CSV, plus a results CSV.
- **Randomness**: `crypto.getRandomValues` with unbiased rejection sampling.

Open `index.html` in the latest Chrome or Edge. No install or network is needed.
