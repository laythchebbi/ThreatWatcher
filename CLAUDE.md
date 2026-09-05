# Threat Watcher — project memory

Early-phase threat-detection platform. Modernized in 2026 from a dormant 2022 v1
into a two-app npm **workspaces** monorepo. Quality/reliability is the priority.

## Architecture

- **`backend/`** — Express API (port 3000). MongoDB via mongoose (single DB —
  replaced the legacy MSSQL/MySQL/SQLite). WorkOS auth (access tokens verified
  via JWKS with `jose`). Python ML classifiers called over a `child_process`
  bridge. `prom-client` `/metrics`, `pino` logging, `zod` validation,
  structured `HttpError`, `helmet` + `compression`.
- **`frontend/`** — Express + EJS UI (port 4000). WorkOS AuthKit OAuth flow,
  sealed `iron-session` cookies. **Dashboard + reports are server-rendered**
  (no client-fetch flash). Calls backend via an `/api/*` proxy that attaches the
  access token server-side and refreshes on 401.
- **Legacy v1** — archived 2026-09-05 to `~/Documents/threat-watcher-legacy-v1.tar.gz`
  (local-only; contains the leaked creds catalogued in `SECURITY.md`, plus the
  labeled URL dataset and v1 `.pkl` models for M4). No longer in the tree.

Auth model: admin-invite-only, single WorkOS org, roles `analyst`/`admin`,
opt-in TOTP. Local `users` collection is upserted from WorkOS on each sign-in
and holds app-specific fields (`monitoredDomains`, `role`, `deactivatedAt`).

## Commands (run from repo root)

```bash
npm install            # installs BOTH workspaces (one root lockfile)
npm run lint           # eslint, both apps
npm run typecheck      # tsc --checkJs, both apps
npm test               # node --test, 31 tests
npm run format         # prettier (JS/JSON/MD/CSS only — NOT .ejs)
npm audit              # must stay at 0 vulnerabilities
```

All four gates are currently green; keep them that way.

## Demo mode (run the app with no MongoDB / no WorkOS)

`backend/.env` and `frontend/.env` set `DEMO_MODE=true` (both gitignored).
Then `cd backend && npm start` and `cd frontend && npm start` →
open **http://localhost:4000** (auth bypassed, mock admin, in-memory seed data,
amber DEMO banner). Live scans still use the real `domain-similarity` engine.

- Demo code is fully isolated: `backend/src/demo/{data,router}.js`, plus
  `DEMO_MODE`-gated branches in both `config/index.js`, backend `server.js`
  (`isDemo` → mount `demo/router`, skip db/ML), and frontend
  `middleware/session.js` (`isDemo` → inject `DEMO_USER`).
- Refuses to start if `DEMO_MODE` + `NODE_ENV=production`.
- For real mode: set `DEMO_MODE=false`, fill `MONGODB_URI` + WorkOS keys.

## Conventions

- Plain CommonJS `.js` (no TS source). Types via `tsconfig` `checkJs` +
  `types/express.d.ts` (augments `req.user`/`req.auth`/`req.id`) + JSDoc.
  `moduleResolution: node16`.
- `node --test` (no Jest). Tests set placeholder env vars at the top so
  `config` loads. Test script is `node --test --test-reporter=spec` (NOT
  `node --test tests` — that tries to load `tests` as a module).
- Prettier (LF, 100 cols, double quotes). husky + lint-staged pre-commit runs
  eslint+prettier on staged `.js`. `.gitattributes` pins LF.

## Gotchas (these wasted time — remember them)

- **npm `overrides` only apply on a clean install.** After editing
  `overrides`/dep versions, `rm -rf node_modules package-lock.json && npm install`,
  or they're silently ignored. (Used to patch express-transitive
  path-to-regexp/qs/cookie without forcing express 5.)
- **Prettier can't parse `.ejs`** (no parser). Keep `.ejs` out of all prettier
  and lint-staged globs or commits/format break.
- **`export =`-via-ESM libs need destructured/`.default` imports** under
  checkJs: `const { pino } = require("pino")`, `helmet = require("helmet").default`,
  `const { pinoHttp } = require("pino-http")`. Plain `require()` is "not callable".
- **`res.json()` is typed `{}`** under these settings — cast the _expression_
  (`/** @type {T} */ (await res.json())`), not the binding.
- Mongoose: don't set both `index: true` on a field AND `schema.index()` for it
  (duplicate-index warning).
- Real bugs caught this session by actually running the code: cheerio was used
  but unlisted; `revokeInvitation` was called with an object not a string;
  mongoose 8.8.4 had a critical search-injection CVE (now 8.24.4). Lesson: run
  lint/typecheck/test/audit before declaring anything done.
- **A `node_modules` copied from another OS is not an install.** Symptoms:
  `.cmd`/`.ps1` shims in `.bin`, `npm ls` says everything is "extraneous",
  workspace links are empty dirs. Always
  `rm -rf node_modules package-lock.json && npm install` after moving the
  checkout.
- **`npm ls` exits 1 on this repo by design.** The root `overrides.qs` pin
  (6.16.0) deliberately exceeds express's declared `~6.15.1` range, so
  `npm ls` reports qs as "invalid" (ELSPROBLEMS). CI never runs `npm ls`;
  `npm ci`, `npm install`, and `npm audit` are unaffected. Don't chase it.

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
