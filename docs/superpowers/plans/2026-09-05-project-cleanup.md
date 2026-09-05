# Project Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the Windows-copied checkout into a lean, truthful macOS base: legacy v1 archived off-repo, dependencies patched to zero audit findings, dead code and stale docs removed, all gates green.

**Architecture:** No application behaviour changes. Five single-concern commits on `main`: (1) toolchain and dependencies, (2) legacy archive, (3) dead script, (4) doc truthfulness, (5) verification. Toolchain goes first so the husky pre-commit hook works for every later commit.

**Tech Stack:** npm workspaces (Node 26 locally, Node 20 in CI), eslint 9, tsc `checkJs`, `node --test`, prettier, husky + lint-staged, bsdtar (macOS `tar`).

**Spec:** `docs/superpowers/specs/2026-09-05-project-cleanup-design.md`

## Global Constraints

- Repo root: `/Users/layth/Documents/Threat Watcher` (note the space; always quote the path).
- Pins (exact, no carets, matching the repo convention): `axios` `1.20.0`, `express` `4.22.2`, `mongoose` `8.24.4`, root override `qs` `6.16.0`. Do not move to express 5, mongoose 9, or `@workos-inc/node` 10 — those are rebuild decisions, out of scope.
- Legacy archive destination: `~/Documents/threat-watcher-legacy-v1.tar.gz` with `~/Documents/threat-watcher-legacy-v1.tar.gz.sha256` beside it. Local disk only; it contains credentials.
- Each task is one commit. Commit messages end with the trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Never run prettier on `.ejs` files (no parser). Prettier globs in the repo already exclude them; do not widen them.
- Definition of done: `npm run lint`, `npm run typecheck`, `npm test` (31 tests), `npm audit` (0 vulnerabilities) pass; demo boots; `git status` clean.
- Scratch directory for temporary files: `/private/tmp/claude-501/-Users-layth-Documents-Threat-Watcher/c7ec59ed-bae3-4342-8091-1664bc667881/scratchpad` (referred to as `$SCRATCH` below; export it first in every shell).

---

### Task 1: Clean reinstall on macOS and patch all audited dependencies

**Files:**
- Modify: `package.json` (root, `overrides.qs`)
- Modify: `backend/package.json` (dependencies)
- Modify: `frontend/package.json` (dependencies)
- Modify: `SECURITY.md:81` (remove the rate-limit claim, since the dep goes away here)
- Delete (untracked): `node_modules/`, `package-lock.json` (regenerated), `.claude/settings.local.json`, every `.DS_Store`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: a working macOS `node_modules`, a fresh `package-lock.json`, a functioning husky pre-commit hook. Every later task's `git commit` relies on this.

- [ ] **Step 1: Record the failing state**

Run:
```bash
cd "/Users/layth/Documents/Threat Watcher" && npm audit --audit-level=high >/dev/null 2>&1; echo "audit exit=$?"; ls node_modules/.bin | grep -c '\.cmd$'
```
Expected: `audit exit=1` and a shim count of `34` (Windows copy).

- [ ] **Step 2: Edit backend/package.json dependencies**

Remove the `axios` and `express-rate-limit` lines and bump `express` and `mongoose`. The `dependencies` block must become exactly:

```json
  "dependencies": {
    "@workos-inc/node": "7.40.0",
    "cheerio": "1.0.0",
    "compression": "1.8.1",
    "cookie-parser": "1.4.7",
    "cors": "2.8.5",
    "dotenv": "16.4.5",
    "express": "4.22.2",
    "helmet": "8.0.0",
    "jose": "5.9.6",
    "mongoose": "8.24.4",
    "pino": "9.5.0",
    "pino-http": "10.3.0",
    "pino-pretty": "11.3.0",
    "prom-client": "15.1.3",
    "string-similarity": "4.0.4",
    "zod": "3.23.8"
  }
```

- [ ] **Step 3: Edit frontend/package.json dependencies**

Change `"axios": "1.16.1"` to `"axios": "1.20.0"` and `"express": "4.21.2"` to `"express": "4.22.2"`. No other lines change.

- [ ] **Step 4: Edit the root package.json qs override**

In `overrides`, change `"qs": "6.15.2"` to `"qs": "6.16.0"`. (No qs 6.15.4 exists; 6.16.0 is the first patched release. express 4.22.2 declares `~6.15.1`, and the override wins over that range.) Leave `path-to-regexp`, `cookie`, `yaml`, and `@eslint/plugin-kit` untouched.

- [ ] **Step 5: Fix the SECURITY.md sentence that references the removed dep**

In `SECURITY.md`, replace the line

```
- **Brute-force resistance** → password attempts are rate-limited by WorkOS at the IdP. Our own `express-rate-limit` is retained for non-auth endpoints.
```

with

```
- **Brute-force resistance** → password attempts are rate-limited by WorkOS at the IdP. The app has no rate limiting of its own yet; add `express-rate-limit` when a public-facing endpoint exists.
```

- [ ] **Step 6: Remove the Windows leftovers and reinstall**

Run:
```bash
cd "/Users/layth/Documents/Threat Watcher" && rm -rf node_modules package-lock.json .claude/settings.local.json && rmdir .claude 2>/dev/null; find . -name .DS_Store -not -path './.git/*' -delete; find .git -name .DS_Store -delete; npm install 2>&1 | tail -5
```
Expected: `npm install` finishes with `found 0 vulnerabilities`. If it reports any vulnerability, run `npm audit` and read which package: a transitive one (undici, js-yaml, brace-expansion, form-data) means a newer in-range release is needed and `npm audit fix` (without `--force`) resolves it; a direct one means a pin above is wrong. Never use `--force`.

- [ ] **Step 7: Verify the install is native and consistent**

Run:
```bash
cd "/Users/layth/Documents/Threat Watcher" && ls node_modules/.bin | grep -c '\.cmd$'; npm ls --depth=0 2>&1 | grep -c extraneous; ls -la node_modules/threat-watcher-backend node_modules/threat-watcher-frontend | grep -c '^l'; npm ls axios express-rate-limit 2>&1 | head -6; ls .husky/_/husky.sh
```
Expected: `0` shims, `0` extraneous, `2` symlinks (the workspace links are symlinks again), `axios` appears only under `threat-watcher-frontend`, `express-rate-limit` is `(empty)`, and `.husky/_/husky.sh` exists.

- [ ] **Step 8: Run all four gates**

Run:
```bash
cd "/Users/layth/Documents/Threat Watcher" && npm run lint && npm run typecheck && npm test 2>&1 | grep -E '^ℹ (tests|pass|fail)' && npm audit
```
Expected: lint and typecheck print nothing but the script banners; tests print `tests 24`/`pass 24`/`fail 0` then `tests 7`/`pass 7`/`fail 0`; audit prints `found 0 vulnerabilities`.

- [ ] **Step 9: Commit**

```bash
cd "/Users/layth/Documents/Threat Watcher" && git add package.json package-lock.json backend/package.json frontend/package.json SECURITY.md && git commit -m "chore(deps): clean reinstall on macOS, patch all audited deps

- express 4.22.2, mongoose 8.24.4, axios 1.20.0 (frontend), qs override 6.16.0
- drop unused backend deps axios and express-rate-limit
- regenerate package-lock.json natively (previous node_modules was a Windows copy)
- SECURITY.md no longer claims express-rate-limit is in use

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```
Expected: the husky hook runs `lint-staged` and the commit succeeds. `git status --short` is empty afterwards.

---

### Task 2: Archive the legacy v1 folder and delete it

**Files:**
- Create (inside the legacy tree, before archiving): `ThreatWatcher/LEGACY-README.md`
- Create (outside repo): `~/Documents/threat-watcher-legacy-v1.tar.gz`, `~/Documents/threat-watcher-legacy-v1.tar.gz.sha256`
- Delete: `ThreatWatcher/` (git-ignored; nothing tracked changes)
- Modify: `.gitignore:1-4` and the `domain.zip` line, `pyproject.toml` (two exclusions), `README.md:150`, `SECURITY.md:34`

**Interfaces:**
- Consumes: working husky hook from Task 1.
- Produces: the archive path used verbatim in Task 4's CLAUDE.md status.

- [ ] **Step 1: Confirm the folder is still git-ignored and untracked**

Run:
```bash
cd "/Users/layth/Documents/Threat Watcher" && git check-ignore -v ThreatWatcher && git ls-files ThreatWatcher | wc -l
```
Expected: `.gitignore:4:ThreatWatcher/	ThreatWatcher` and `0`.

- [ ] **Step 2: Write the archive README into the legacy tree**

```bash
cd "/Users/layth/Documents/Threat Watcher" && cat > ThreatWatcher/LEGACY-README.md <<'EOF'
# Threat Watcher — legacy v1 snapshot (2022 codebase)

Archived 2026-09-05 from the modernized repo's git-ignored `ThreatWatcher/`
folder, just before that folder was deleted. Excluded from this archive:
`venv/`, `.venv/`, `node_modules/`, `site-packages/`, `__pycache__/`, `*.pyc`,
`.DS_Store`, and `WebConent/` (a byte-identical duplicate of `WebContentML/`).

## SECURITY — read first

This snapshot contains hardcoded credentials (MongoDB Atlas, Azure SQL,
WhoisXML, Slack) and a Telethon session file (`DataLeaks/@laythchebbi.session`).
They are catalogued, with rotation steps, in the modern repo's `SECURITY.md`.
Keep this archive on local disk only. Never upload it, sync it, or commit it.
The embedded `.git/` directories also hold those secrets in their history.

## Contents

| Path | What it is |
| --- | --- |
| `URLML/Malicious-URL-Detection-using-Machine-Learning-V1/data/dataNN.csv` | labeled URL dataset (~20 MB) — input for the M4 retrain |
| `URLML/.../pre-trained/vectorizer1.pkl`, `mal-logireg1.pkl` | v1 URL classifier (scikit-learn 0.22.1 pickles) |
| `WebContentML/.../classifier/random_forest.pkl` | v1 web-content classifier |
| `DarkWeb/Darkweb-crawler/mysql-container/backup.sql` | dark-web crawler MySQL dump |
| `DataLeak/`, `DataLeaks/` | Telegram / web-form leak collectors (Django API + scripts) |
| `BackEnd/backend/` | v1 Express API (MSSQL/MySQL/SQLite) |
| `FrontEnd/Threat-Watcher-front-login/Threat-Watcher/` | v1 React frontend |
EOF
ls -la ThreatWatcher/LEGACY-README.md
```
Expected: the file exists (about 1.5 KB).

- [ ] **Step 3: Build the include list and the archive**

`find` decides what goes in (its `-not -path` patterns match across slashes, unlike tar's own excludes), and `tar` reads the NUL-separated list.

```bash
export SCRATCH=/private/tmp/claude-501/-Users-layth-Documents-Threat-Watcher/c7ec59ed-bae3-4342-8091-1664bc667881/scratchpad
cd "/Users/layth/Documents/Threat Watcher" && find ThreatWatcher -type f \
  -not -path '*/venv/*' -not -path '*/.venv/*' -not -path '*/node_modules/*' \
  -not -path '*/site-packages/*' -not -path '*/__pycache__/*' \
  -not -path 'ThreatWatcher/WebConent/*' \
  -not -name '*.pyc' -not -name '.DS_Store' -print0 > "$SCRATCH/legacy-files.list" \
&& tr -cd '\0' < "$SCRATCH/legacy-files.list" | wc -c \
&& tar --null -T "$SCRATCH/legacy-files.list" -czf "$HOME/Documents/threat-watcher-legacy-v1.tar.gz" \
&& ls -lh "$HOME/Documents/threat-watcher-legacy-v1.tar.gz"
```
Expected: a file count in the low thousands (BackEnd 46 + DarkWeb 41 + DataLeak ~4605 + DataLeaks 35 + FrontEnd ~1474 + URLML 42 + WebContentML 51 + README ≈ 6300) and an archive well under 300 MB.

- [ ] **Step 4: Verify the archive before deleting anything**

```bash
export SCRATCH=/private/tmp/claude-501/-Users-layth-Documents-Threat-Watcher/c7ec59ed-bae3-4342-8091-1664bc667881/scratchpad
A="$HOME/Documents/threat-watcher-legacy-v1.tar.gz"
gzip -t "$A" && echo "gzip ok" \
&& tar -tzf "$A" > "$SCRATCH/archive.list" && echo "entries: $(wc -l < "$SCRATCH/archive.list") vs list: $(tr -cd '\0' < "$SCRATCH/legacy-files.list" | wc -c)" \
&& echo "--- must be present ---" && grep -E 'LEGACY-README.md|dataNN.csv|vectorizer1.pkl|mal-logireg1.pkl|WebContentML/.*random_forest.pkl|backup.sql|@laythchebbi.session' "$SCRATCH/archive.list" \
&& echo "--- must be 0 ---" && grep -cE '/node_modules/|/site-packages/|/venv/|/__pycache__/|WebConent/|\.pyc$|\.DS_Store$' "$SCRATCH/archive.list"; \
mkdir -p "$SCRATCH/extract-test" && tar -xzf "$A" -C "$SCRATCH/extract-test" ThreatWatcher/LEGACY-README.md && head -3 "$SCRATCH/extract-test/ThreatWatcher/LEGACY-README.md" \
&& (cd "$HOME/Documents" && shasum -a 256 threat-watcher-legacy-v1.tar.gz > threat-watcher-legacy-v1.tar.gz.sha256 && cat threat-watcher-legacy-v1.tar.gz.sha256)
```
Expected: `gzip ok`; entry count equals list count; all seven "must be present" paths listed; the "must be 0" count is `0` (grep prints `0` and exits 1, which is why that line ends with `;`); the extracted README's first line is the `# Threat Watcher — legacy v1 snapshot` heading; a checksum line is printed. **If any expectation fails, stop. Do not proceed to Step 5.**

- [ ] **Step 5: Delete the legacy folder**

```bash
cd "/Users/layth/Documents/Threat Watcher" && rm -rf ThreatWatcher && ls -d ThreatWatcher 2>&1; git status --short
```
Expected: `ls: ThreatWatcher: No such file or directory` and an empty `git status`.

- [ ] **Step 6: Remove the legacy exclusions from .gitignore and pyproject.toml**

In `.gitignore`, delete the first four lines (the three comment lines and `ThreatWatcher/`) and the `domain.zip` line, so the file starts with `node_modules/`. Keep `*.session` and `*.pkl`.

In `pyproject.toml`, under `[tool.ruff] extend-exclude`, delete the `"ThreatWatcher",` line. Under `[tool.black] extend-exclude`, change

```
/(
  ThreatWatcher
  | venv
  | \.venv
)/
```
to
```
/(
  venv
  | \.venv
)/
```

- [ ] **Step 7: Update the two doc sentences that describe the folder**

In `README.md`, replace the paragraph

```
The `ThreatWatcher/` directory is the **legacy v1 codebase** from 2022. It is preserved as a reference during the modernization and will be deleted once feature parity is reached. Do not add new code there.
```
with
```
The legacy 2022 v1 codebase (formerly the git-ignored `ThreatWatcher/` directory) was archived on 2026-09-05 to `~/Documents/threat-watcher-legacy-v1.tar.gz` and removed from the working tree. The archive is local-only: it contains the credentials catalogued in `SECURITY.md`. It also holds the labeled URL dataset and v1 `.pkl` models needed for the M4 retrain.
```

In `SECURITY.md`, replace

```
(The legacy `ThreatWatcher/` tree can be preserved as a snapshot or deleted once the modernization replaces it.)
```
with
```
(The legacy `ThreatWatcher/` tree was archived to `~/Documents/threat-watcher-legacy-v1.tar.gz` on 2026-09-05 and removed from the working tree. The archive is local-only and still contains every secret listed above.)
```

- [ ] **Step 8: Verify ruff still runs cleanly with the exclusion gone and gates pass**

```bash
cd "/Users/layth/Documents/Threat Watcher" && (command -v ruff >/dev/null && ruff check backend/ml backend/scripts || echo "ruff not installed locally; CI covers it") && npm run lint && npm run typecheck && npm test 2>&1 | grep -E '^ℹ (pass|fail)'
```
Expected: ruff reports no issues (or the "not installed" note); pass 24 / fail 0 and pass 7 / fail 0.

- [ ] **Step 9: Commit**

```bash
cd "/Users/layth/Documents/Threat Watcher" && git add .gitignore pyproject.toml README.md SECURITY.md && git commit -m "chore: archive legacy v1 tree off-repo and drop its exclusions

ThreatWatcher/ (1.1 GB, git-ignored) archived to
~/Documents/threat-watcher-legacy-v1.tar.gz without venvs/node_modules/caches
and deleted from the working tree. Docs point at the archive.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Remove the dead migration script

**Files:**
- Delete: `backend/scripts/migrate_to_mongo.js`
- Modify: `README.md` (delete the "Legacy → MongoDB migration" section, lines 128-136)
- Modify: `deploy/README.md` (delete the "Migration cutover" section, lines 88-96)

**Interfaces:**
- Consumes: nothing.
- Produces: nothing other tasks rely on.

- [ ] **Step 1: Prove it cannot run**

```bash
cd "/Users/layth/Documents/Threat Watcher" && grep -nE 'require\("(mssql|mysql2?|sqlite3?)"\)' backend/scripts/migrate_to_mongo.js; grep -cE '"(mssql|mysql2?|sqlite3?)"' backend/package.json
```
Expected: the script requires `mssql` (and others); `backend/package.json` count is `0`.

- [ ] **Step 2: Delete the script**

```bash
cd "/Users/layth/Documents/Threat Watcher" && git rm -q backend/scripts/migrate_to_mongo.js && ls backend/scripts
```
Expected: only `darkweb_crawl.py` remains.

- [ ] **Step 3: Remove the README section**

In `README.md`, delete this whole block (heading through the "Delete the script after cutover." line, plus the blank line after it):

```
## Legacy → MongoDB migration

One-shot ETL at `backend/scripts/migrate_to_mongo.js`. Set any subset of:

- `LEGACY_MSSQL_URI` — pulls `dailyDomains`, `RegistredDomains` into `daily_domains`, `registered_domains`.
- `LEGACY_MYSQL_URI` — pulls `darkweb_leaks` tables into `darkweb_sources`, `darkweb_pages`.
- `LEGACY_SQLITE_PATH` — pulls Django `auth_user` into `users`.

Then: `node backend/scripts/migrate_to_mongo.js --dry-run` (review) → drop `--dry-run` to commit. Delete the script after cutover.
```

- [ ] **Step 4: Remove the deploy README section**

In `deploy/README.md`, delete this block (heading through the closing fence, plus the blank line after it):

```
## Migration cutover

```bash
sudo -u threatwatcher node /opt/threat-watcher/backend/scripts/migrate_to_mongo.js --dry-run
# review output
sudo -u threatwatcher node /opt/threat-watcher/backend/scripts/migrate_to_mongo.js
# verify counts, then delete the script
```
```

- [ ] **Step 5: Verify no reference survives**

```bash
cd "/Users/layth/Documents/Threat Watcher" && grep -rn "migrate_to_mongo\|LEGACY_MSSQL\|LEGACY_MYSQL\|LEGACY_SQLITE" --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=docs . ; echo "grep exit=$?"
```
Expected: no matches, `grep exit=1`.

- [ ] **Step 6: Commit**

```bash
cd "/Users/layth/Documents/Threat Watcher" && git add -A backend/scripts README.md deploy/README.md && git commit -m "chore: remove unrunnable legacy migration script

migrate_to_mongo.js required mssql/mysql drivers that were never added to
package.json, and its source databases now live only in the v1 archive.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: Make the docs match the code

**Files:**
- Modify: `README.md` (Endpoints section lines 103-123; UI routes row for `/geolocation`; two "Windows Task Scheduler" mentions at lines 32 and 126)
- Modify: `frontend/README.md` (line 13 and the `views/` block of the layout tree)
- Modify: `CLAUDE.md` (Architecture bullet for `ThreatWatcher/`, Status section, one new Gotcha)
- Modify: `docs/superpowers/specs/2026-09-05-project-cleanup-design.md` (one factual correction)

**Interfaces:**
- Consumes: archive path from Task 2.
- Produces: nothing other tasks rely on.

- [ ] **Step 1: Record the stale claims**

```bash
cd "/Users/layth/Documents/Threat Watcher" && grep -nE '/auth/(register|login)|redirects to `/geolocation`|Windows Task Scheduler|Git initialized' README.md frontend/README.md CLAUDE.md
```
Expected: five matches (README 108, 109, 32, 126; frontend/README 13; CLAUDE.md status line).

- [ ] **Step 2: Rewrite the README Endpoints section**

Replace everything from the `## Endpoints (M1)` heading up to (not including) the `## Scheduled jobs` heading with:

```
## Endpoints

Backend (`:3000`). Every `/auth/*` and `/api/*` route requires a WorkOS access token (`requireUser`); routes marked _admin_ also require the `admin` role.

- `GET  /health`, `GET /metrics`
- `GET  /auth/me`
- `GET  /auth/invitations`, `POST /auth/invitations` `{email, role, expiresInDays}`, `DELETE /auth/invitations/:id` — _admin_
- `GET  /api/users/me`, `PATCH /api/users/me`, `PUT /api/users/me/monitored`
- `GET  /api/users`, `PATCH /api/users/:id/role`, `POST /api/users/:id/deactivate`, `POST /api/users/:id/reactivate` — _admin_
- `GET  /api/domains/search/:domain`
- `POST /api/domains/scan/:domain` (writes a `Report`)
- `GET  /api/domains/daily/:domain`, `GET /api/domains/registered/:domain`
- `GET  /api/reports?limit=50`, `GET /api/reports/:id`
- `GET  /api/dataleak/search?q=...&source=telegram|twitter|forum|darkweb|all`

Frontend (`:4000`). Pages are server-rendered (see "UI routes" below). Browser-side code talks to a same-origin `/api/*` proxy that attaches the access token server-side and refreshes it on 401:

- `GET  /api/reports`, `GET /api/reports/:id`, `GET /api/dataleak`
- `GET  /api/me`, `PATCH /api/me`, `PUT /api/me/monitored`
- `GET  /api/admin/users`, `PATCH /api/admin/users/:id/role`, `POST /api/admin/users/:id/deactivate` — _admin_
- `GET  /api/admin/invitations`, `POST /api/admin/invitations`, `DELETE /api/admin/invitations/:id` — _admin_

```

- [ ] **Step 3: Fix the geolocation row and the scheduler mentions in README**

In the UI routes table replace

```
| `/geolocation`            | geo activity surface (M1 design landing)                       |
```
with
```
| `/geolocation`            | geo activity surface — static design mockup, no data behind it |
```

Replace `scheduled via cron / Windows Task Scheduler` (line 32) with `scheduled via cron or the systemd timer in `deploy/systemd/``, and `Schedule via cron/Windows Task Scheduler.` (line 126) with `Schedule via cron or `deploy/systemd/threat-watcher-crawl.timer`.`

- [ ] **Step 4: Fix frontend/README.md**

Replace the line

```
`/` redirects to `/geolocation`. The `Geo activity` page renders a procedural world map, live event feed, top countries, ASN table, targeted assets, and a 24h trend chart.
```
with
```
`/` redirects to `/dashboard`. The `Geo activity` page (`/geolocation`) is a static design mockup: procedural world map, event feed, top countries, ASN table, targeted assets and a 24h trend, all hardcoded, with no backend call behind it yet.
```

Replace the `views/` block of the layout tree

```
  views/
    layout.ejs           Shared shell: <head>, sidebar partial, topbar partial, body slot.
    geolocation.ejs      Page body for /geolocation. Inline <style> + <script> blocks
                         are auto-extracted into the layout's <head> / pre-</body>.
    partials/
```
with
```
  views/
    layout.ejs           Shared shell: <head>, sidebar partial, topbar partial, body slot.
    dashboard.ejs        /dashboard — monitored domains, recent scans, counters
    new-scan.ejs         /new-scan
    scan-report.ejs      /scan/:id
    reports.ejs          /reports
    dark-web.ejs         /dark-web
    settings.ejs         /settings
    geolocation.ejs      /geolocation — static mockup (see above)
    design-system.ejs    /design-system — tokens and components reference
    login.ejs, error.ejs
                         Page bodies may carry inline <style> + <script> blocks; they
                         are auto-extracted into the layout's <head> / pre-</body>.
    partials/
```

- [ ] **Step 5: Update CLAUDE.md**

Replace the Architecture bullet

```
- **`ThreatWatcher/`** — legacy v1. **git-ignored** (contains the leaked creds
  catalogued in `SECURITY.md`). Reference only; never add code there.
```
with
```
- **Legacy v1** — archived 2026-09-05 to `~/Documents/threat-watcher-legacy-v1.tar.gz`
  (local-only; contains the leaked creds catalogued in `SECURITY.md`, plus the
  labeled URL dataset and v1 `.pkl` models for M4). No longer in the tree.
```

Replace the whole `## Status` section with:

```
## Status

M1–M7 + WorkOS auth complete. Repo moved from Windows to macOS on 2026-09-05
and cleaned (spec: `docs/superpowers/specs/2026-09-05-project-cleanup-design.md`):
legacy v1 archived off-repo, deps patched to 0 audit findings, dead migration
script removed, docs re-synced with the real routes. CI
(`.github/workflows/ci.yml`) runs on push; **no git remote yet**. Not yet
booted against live MongoDB/WorkOS — that's the only end-to-end gap.

Next candidates: push to a remote; M4 ML retrain (`train_url_classifier.py` +
`export_onnx.py`, data in the archive); decide on the pending majors
(express 5, mongoose 9, `@workos-inc/node` 10) before building new features.
```

Add this bullet at the end of the `## Gotchas` list:

```
- **A `node_modules` copied from another OS is not an install.** Symptoms:
  `.cmd`/`.ps1` shims in `.bin`, `npm ls` says everything is "extraneous",
  workspace links are empty dirs. Always `rm -rf node_modules package-lock.json
  && npm install` after moving the checkout.
```

- [ ] **Step 6: Correct the spec**

In `docs/superpowers/specs/2026-09-05-project-cleanup-design.md`, section 5, change

```
  `/auth/register`, `/auth/login`, or `/api/domains/registered`; add the
```
to
```
  `/auth/register` or `/auth/login`; `/api/domains/registered/:domain` does exist); add the
```

- [ ] **Step 7: Verify the stale claims are gone and prettier is happy**

```bash
cd "/Users/layth/Documents/Threat Watcher" && grep -nE '/auth/(register|login)|redirects to `/geolocation`|Windows Task Scheduler|Git initialized|express-rate-limit. is retained' README.md frontend/README.md CLAUDE.md SECURITY.md; echo "grep exit=$?"; npx prettier --check README.md frontend/README.md CLAUDE.md SECURITY.md deploy/README.md docs/superpowers/specs/*.md docs/superpowers/plans/*.md
```
Expected: `grep exit=1` (no matches). If prettier lists files, run `npx prettier --write` on exactly those files and re-check.

- [ ] **Step 8: Commit**

```bash
cd "/Users/layth/Documents/Threat Watcher" && git add README.md frontend/README.md CLAUDE.md docs/superpowers && git commit -m "docs: sync README, frontend README and CLAUDE.md with the real routes and repo state

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: Final verification

**Files:** none modified unless prettier or `npm ci` reveals a problem.

**Interfaces:**
- Consumes: everything above.
- Produces: the green-gates evidence for the final report.

- [ ] **Step 1: CI-parity install**

```bash
cd "/Users/layth/Documents/Threat Watcher" && npm ci 2>&1 | tail -3 && npm audit --audit-level=high && echo "audit-high exit=$?"
```
Expected: `npm ci` succeeds (lockfile and package.json in sync), `found 0 vulnerabilities`, `audit-high exit=0`.

- [ ] **Step 2: All four gates plus format check**

```bash
cd "/Users/layth/Documents/Threat Watcher" && npm run lint && npm run typecheck && npm test 2>&1 | grep -E '^ℹ (tests|pass|fail)' && npm audit && npm run format:check 2>&1 | tail -3
```
Expected: pass 24 / fail 0, pass 7 / fail 0, `found 0 vulnerabilities`, `All matched files use Prettier code style!`. If format:check lists files, run `npm run format`, inspect `git diff --stat`, and commit as `style: prettier` with the trailer.

- [ ] **Step 3: Boot the demo and probe it**

```bash
export SCRATCH=/private/tmp/claude-501/-Users-layth-Documents-Threat-Watcher/c7ec59ed-bae3-4342-8091-1664bc667881/scratchpad
cd "/Users/layth/Documents/Threat Watcher" && (cd backend && node src/server.js > "$SCRATCH/be.log" 2>&1 & echo $! > "$SCRATCH/be.pid") && (cd frontend && node src/server.js > "$SCRATCH/fe.log" 2>&1 & echo $! > "$SCRATCH/fe.pid") && for i in $(seq 1 30); do curl -sf http://localhost:3000/health >/dev/null && curl -sf -o /dev/null http://localhost:4000/dashboard && break; node -e "setTimeout(()=>process.exit(0),500)"; done; curl -s http://localhost:3000/health; echo; curl -s -o /dev/null -w "root: %{http_code} -> %{redirect_url}\n" http://localhost:4000/; curl -s http://localhost:4000/dashboard | grep -c "DEMO MODE"; curl -s -o /dev/null -w "geo: %{http_code}\n" http://localhost:4000/geolocation; kill $(cat "$SCRATCH/be.pid") $(cat "$SCRATCH/fe.pid"); grep -ciE "error|unhandled" "$SCRATCH/be.log" "$SCRATCH/fe.log"
```
Expected: `{"ok":true,"demo":true,"mongo":false,"ml":{"url":false,"content":false}}`, `root: 302 -> http://localhost:4000/dashboard`, `1` (banner present), `geo: 200`, and `0` error lines in both logs.

- [ ] **Step 4: Final repo state**

```bash
cd "/Users/layth/Documents/Threat Watcher" && git status --short && git log --oneline -8 && du -sh . node_modules && ls
```
Expected: empty status; five new commits on top of `bd72353 docs: cleanup design spec`; no `ThreatWatcher` in the listing.
