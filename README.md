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
- **`scripts/`** — standalone Python jobs (dark-web crawler) scheduled via cron or the systemd timer in `deploy/systemd/`. Tor itself is a system service, not managed by the app.

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

## Endpoints

Backend (`:3000`). Every `/auth/*` and `/api/*` route requires a WorkOS access token (`requireUser`); routes marked _admin_ also require the `admin` role.

- `GET  /health`, `GET /metrics`
- `GET  /auth/me`
- `GET  /auth/invitations`, `POST /auth/invitations` `{email, role, expiresInDays}`, `DELETE /auth/invitations/:id` — _admin_
- `GET  /api/users/me`, `PATCH /api/users/me`, `PUT /api/users/me/monitored`
- `GET  /api/users`, `POST /api/users/:id/deactivate`, `POST /api/users/:id/reactivate` — _admin_ (roles come from WorkOS: set them on the invitation or in the WorkOS dashboard)
- `GET  /api/domains/search/:domain`
- `POST /api/domains/scan/:domain` (writes a `Report`)
- `GET  /api/domains/daily/:domain`, `GET /api/domains/registered/:domain`
- `GET  /api/reports?limit=50`, `GET /api/reports/:id`
- `GET  /api/dataleak/search?q=...&source=telegram|twitter|forum|darkweb|all`

Frontend (`:4000`). Pages are server-rendered (see "UI routes" below). Browser-side code talks to a same-origin `/api/*` proxy that attaches the access token server-side and refreshes it on 401:

- `GET  /api/reports`, `GET /api/reports/:id`, `GET /api/dataleak`
- `GET  /api/me`, `PATCH /api/me`, `PUT /api/me/monitored`
- `GET  /api/admin/users`, `POST /api/admin/users/:id/deactivate` — _admin_
- `GET  /api/admin/invitations`, `POST /api/admin/invitations`, `DELETE /api/admin/invitations/:id` — _admin_

## Scheduled jobs

- **Dark-web crawler** (`backend/scripts/darkweb_crawl.py`): reads enabled rows from `darkweb_sources`, fetches each via local Tor SOCKS5 (`127.0.0.1:9050`), upserts into `darkweb_pages`. Schedule via cron or `deploy/systemd/threat-watcher-crawl.timer`. Tor itself runs as a system service.

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

The legacy 2022 v1 codebase (formerly the git-ignored `ThreatWatcher/` directory) was archived on 2026-09-05 to `~/Documents/threat-watcher-legacy-v1.tar.gz` and removed from the working tree. The archive is local-only: it contains the credentials catalogued in `SECURITY.md`. It also holds the labeled URL dataset and v1 `.pkl` models needed for the M4 retrain.

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
| `/geolocation`            | geo activity surface — static design mockup, no data behind it |
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
