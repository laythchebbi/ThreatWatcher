# Threat Watcher

Early-phase threat detection platform. Modernized from a 2022 multi-component codebase into two stable apps.

## Architecture

```
                              ┌────────────────────┐
                              │   MongoDB           │
                              │   (single store)    │
                              └─────────▲──────────┘
                                        │ mongoose
                                        │
   ┌─────────────────┐  HTTP    ┌──────┴──────────┐  child_process   ┌────────────┐
   │   frontend      │  ──────▶ │   backend       │  ─────────────▶  │  ml/       │
   │   Express+EJS   │          │   Express API   │                   │  Python    │
   │   :4000         │  ◀────── │   :3000         │  scheduled        │  CLI       │
   └─────────────────┘   JSON   └────┬────────────┘                   └────────────┘
                                     │
                                     │ scheduled (cron / Task Scheduler)
                                     ▼
                              ┌──────────────┐    SOCKS5
                              │  scripts/    │  ─────────▶  Tor (system service)
                              │  darkweb     │
                              └──────────────┘
```

- **`frontend/`** — Express + EJS UI (one process on `:4000`).
- **`backend/`** — Express API + ML helpers + scheduled crawler scripts (one process on `:3000`).
- **MongoDB** — single database (`threatwatcher`). Replaces the legacy MSSQL + MySQL + SQLite triple.
- **`ml/`** — small Python scripts (URL classifier, content classifier) called from the backend via `child_process`. CLI protocol: JSON-per-line on stdin/stdout.
- **`scripts/`** — standalone Python jobs (dark-web crawler) scheduled via cron / Windows Task Scheduler. Tor itself is a system service, not managed by the app.

## Run locally

Prereqs: Node 18+, Python 3.9+ (3.9 is required for the legacy scikit-learn 0.22.1 — bumped in M4), MongoDB 6+ (local or Atlas), Tor (only if running the dark-web crawler), a **WorkOS account** (free tier is enough for development).

### WorkOS setup (one-time)

1. Sign up at <https://dashboard.workos.com>. Create a project.
2. Under **Authentication → AuthKit**: enable it. Toggle the providers you want (Email + Password, Google OAuth, Microsoft OAuth).
3. Under **Authentication → AuthKit → Configuration**: disable public sign-up (admin-invite-only).
4. Under **Authentication → MFA**: enable TOTP (opt-in is the default).
5. **Redirect URIs**: add `http://localhost:4000/auth/callback` (dev) and your production URL.
6. **Organizations**: create the org you want all users to live in. Copy its `org_…` ID.
7. From **API Keys**, copy the **Client ID** (`client_…`) and **Secret Key** (`sk_…`).

Put these into the two `.env` files (see `.env.example` in each app).

### Boot

```bash
# Backend
cd backend
cp .env.example .env       # fill MONGODB_URI, WORKOS_*, secrets
npm install
pip install -r ml/requirements.txt
npm start                  # → http://localhost:3000

# Frontend (separate terminal)
cd frontend
cp .env.example .env       # set BACKEND_URL + WORKOS_* + SESSION_PASSWORD
npm install
npm start                  # → http://localhost:4000
```

To create the first admin user:

1. In the WorkOS dashboard, send an invitation to your email with the **admin** role into the configured org.
2. Open the email, click the link → enroll in AuthKit (set password / OAuth).
3. Sign in at `http://localhost:4000/login`.
4. On first sign-in the backend upserts your local `users` row with `role: "admin"`.
5. Now you can invite additional users from `/settings#team`.

`/health` on each app returns 200 when the process is up.

## Development workflow

From the repo root:

```bash
npm install                  # installs root dev tooling (eslint, prettier, husky)
npm install -w backend       # installs backend deps
npm install -w frontend      # installs frontend deps

npm run lint                 # eslint on both apps
npm run format:check         # prettier check
npm test                     # runs node --test in both apps
npm run audit                # npm audit (root + workspaces)
```

Python tooling (for `backend/ml/` and `backend/scripts/`):

```bash
pip install ruff black pip-audit pip-tools
ruff check backend/ml backend/scripts
black --check backend/ml backend/scripts
pip-audit -r backend/ml/requirements.txt
```

Pre-commit hook (husky) runs eslint+prettier on staged files automatically.

## Endpoints (M1)

Backend (`:3000`):

- `GET  /health`
- `POST /auth/register` `{email,password,displayName}`
- `POST /auth/login` `{email,password}` → `{user, token}` (rate-limited)
- `GET  /auth/me` (auth required)
- `GET  /api/domains/search/:domain` (auth required)
- `POST /api/domains/scan/:domain` (auth required, writes a `Report`)
- `GET  /api/domains/daily/:domain`
- `GET  /api/domains/registered/:domain`
- `GET  /api/reports?limit=50`
- `GET  /api/reports/:id`
- `GET  /api/dataleak/search?q=...&source=telegram|twitter|forum|darkweb|all`

Frontend (`:4000`):

- `GET  /login`, `POST /login`, `POST /logout`
- `GET  /geolocation` (the modernized dashboard surface; more screens land in M5)

## Scheduled jobs

- **Dark-web crawler** (`backend/scripts/darkweb_crawl.py`): reads enabled rows from `darkweb_sources`, fetches each via local Tor SOCKS5 (`127.0.0.1:9050`), upserts into `darkweb_pages`. Schedule via cron/Windows Task Scheduler. Tor itself runs as a system service.

## Legacy → MongoDB migration

One-shot ETL at `backend/scripts/migrate_to_mongo.js`. Set any subset of:

- `LEGACY_MSSQL_URI` — pulls `dailyDomains`, `RegistredDomains` into `daily_domains`, `registered_domains`.
- `LEGACY_MYSQL_URI` — pulls `darkweb_leaks` tables into `darkweb_sources`, `darkweb_pages`.
- `LEGACY_SQLITE_PATH` — pulls Django `auth_user` into `users`.

Then: `node backend/scripts/migrate_to_mongo.js --dry-run` (review) → drop `--dry-run` to commit. Delete the script after cutover.

## Repository layout

```
.
├── README.md, SECURITY.md, .gitignore
├── package.json                  workspace-style convenience scripts (lint/format)
├── eslint.config.js, .prettierrc, pyproject.toml
├── .github/workflows/ci.yml      lint + audit + gitleaks per app
├── backend/                      Node.js API + Python ML helpers + crawler scripts
└── frontend/                     Node.js + EJS user-facing app
```

The `ThreatWatcher/` directory is the **legacy v1 codebase** from 2022. It is preserved as a reference during the modernization and will be deleted once feature parity is reached. Do not add new code there.

## Security

See [`SECURITY.md`](./SECURITY.md). Several credentials were committed to source in v1 — they are listed for rotation. **Do not push this repo to any remote until rotation is complete.**

## Status

All seven modernization milestones have landed in this repo:

| #   | Milestone                  | Where                                                                                             |
| --- | -------------------------- | ------------------------------------------------------------------------------------------------- |
| M1  | Foundation + Consolidation | `backend/`, `frontend/`, root configs                                                             |
| M2  | Tests                      | `backend/tests/`, `frontend/tests/` (`node --test`)                                               |
| M3  | Type-check via `checkJs`   | `backend/tsconfig.json`, `frontend/tsconfig.json`, `npm run typecheck`                            |
| M4  | ML refresh path            | `backend/ml/train_url_classifier.py`, `export_onnx.py`, `services/ml-onnx.js`, `ml/README.md`     |
| M5  | UI screens                 | `frontend/src/views/{dashboard,new-scan,scan-report,reports,dark-web,settings,design-system}.ejs` |
| M6  | Observability              | `services/metrics.js`, `/metrics`, request-ID middleware, optional `LOG_FILE` transport           |
| M7  | Production deploy          | `deploy/` — PM2 ecosystem, nginx, systemd units, `deploy/README.md`                               |

See `C:\Users\layth\.claude\plans\i-have-this-old-robust-nebula.md` for the original plan.

## UI routes

| Route                     | Purpose                                                        |
| ------------------------- | -------------------------------------------------------------- |
| `/login`                  | sign-in landing page (no layout)                               |
| `/auth/sign-in`           | redirect to WorkOS AuthKit (email/password or pick a provider) |
| `/auth/sign-in/google`    | force Google OAuth                                             |
| `/auth/sign-in/microsoft` | force Microsoft OAuth                                          |
| `/auth/callback`          | OAuth code exchange                                            |
| `/auth/sign-out`          | destroy sealed session                                         |
| `/dashboard`              | landing, monitored domains, recent scans, threat counters      |
| `/new-scan`               | run a scan against a domain                                    |
| `/scan/:id`               | scan report with SecureScore gauge and findings tabs           |
| `/reports`                | searchable history                                             |
| `/dark-web`               | leak/mention search (Telegram/Twitter/forum/onion)             |
| `/geolocation`            | geo activity surface (M1 design landing)                       |
| `/settings`               | profile, monitored domains, integrations                       |
| `/design-system`          | palette, typography, components reference                      |
| `/metrics`                | Prometheus scrape (gated by nginx in prod)                     |

## Verification commands

```bash
npm install                  # root tooling (eslint, prettier, husky, tsc)
npm install -w backend
npm install -w frontend
pip install -r backend/ml/requirements.txt

npm run lint
npm run typecheck
npm test
npm run audit
```

For an end-to-end smoke (requires a running MongoDB + filled `.env`):

```bash
npm -w backend  start    # backend on :3000
npm -w frontend start    # frontend on :4000
open http://localhost:4000
```
