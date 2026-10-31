# Threat Watcher — project memory

Early-phase threat-detection platform. Modernized in 2026 from a dormant 2022 v1
into a two-app npm **workspaces** monorepo. Quality/reliability is the priority.

## Architecture

- **`backend/`** — Express API (port 3000). MongoDB via mongoose (single DB —
  replaced the legacy MSSQL/MySQL/SQLite). WorkOS auth (access tokens verified
  via JWKS with `jose`). Python ML classifiers called over a `child_process`
  bridge. `prom-client` `/metrics`, `pino` logging, `zod` validation,
  structured `HttpError`, `helmet` + `compression`. No CORS/cookies on the
  backend: browsers only ever talk to the frontend, which proxies with a header.
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

## v2 in `app/` (2026-10-31, branch `v2-core`)

The rewrite lives in a third workspace, `app/`: one Express process, built-in
sign-in (scrypt + versioned sealed sessions), MongoDB only, a scheduled watch
cycle (dnstwist in the Python worker → certificates → DNS → RDAP → page fetch →
posture → diff → leak mentions → events). Plan 2 (2026-10-31) added the signal
steps, `providers.js` (one token bucket per external API, 6 h per-label cache),
the SSRF-guarded fetch in `http.js`, and leak sources (`leaks.js`, `hibp.js`). Design:
`docs/superpowers/specs/2026-10-30-threat-watcher-v2-design.md`; plans in
`docs/superpowers/plans/`. `backend/` and `frontend/` stay until Plan 3
deletes them. `app/README.md` has the run instructions. Tests there use
`mongodb-memory-server` (first run downloads a MongoDB binary).

## Commands (run from repo root)

```bash
npm install            # installs BOTH workspaces (one root lockfile)
npm run lint           # eslint, both apps
npm run typecheck      # tsc --checkJs, both apps
npm test               # node --test, three workspaces (33 legacy + app)
npm run format         # prettier (JS/JSON/MD/CSS only — NOT .ejs)
npm audit              # 0 high/critical is the CI gate; see the minimatch note below
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
- **zod 4 `.default()` short-circuits.** When the input is `undefined`, zod 4
  returns the default as-is and skips the schema's `.transform()`, so the
  default must be the _output_ type (`.default(false)`, not `.default("false")`).
  Bumped 3→4 on 2026-10-30 for GHSA-mrhx-c7xc-m3w5; `tsc` catches the type
  mismatch, the frontend smoke test asserts `SESSION_COOKIE_SECURE === false`.
- **Gate chains must abort on failure.** `(npm run typecheck … && echo ok || … | head)` returns
  the exit code of `head`, so two Plan 2 commits landed with tsc red. Use
  `npm run typecheck >/dev/null || { …; exit 1; }`.
- **Python edits through exact-anchor replacements break after prettier reflows the
  target**; several Plan 2 steps silently skipped a file. Prefer regex anchors or Edit.
- **minimatch GHSA-g3hv-75wg-m249 (moderate, 2026-10-31)** reaches us only via
  eslint and ejs→jake→filelist; every minimatch < 11.0.1 is affected and the
  consumers pin 3.x/5.x, so there is no non-breaking fix. CI gates at `high`, so
  it does not fail builds. Re-check `npm audit` when eslint or ejs release.
- **undici 8 needs Node >= 22.19.** CI ran Node 20 until 2026-10-31 and every test that
  loads `http.js` died at require time (`createZstdDecompress` is undefined on 20). CI and
  `app/package.json` `engines` now say 22. Also: the bucket's poll timers are `unref()`'d,
  so a test that awaits a refilling `take()` must hold a ref'd timer or the loop drains.
- **Never hand the built-in `fetch` an undici 8 dispatcher.** On Node 22 the built-in
  fetch is an older undici and throws `invalid onRequestStart method`; Node 26 hides it.
  `fetchPage` pins DNS with an undici `Agent`, so the cycle defaults to undici's `fetch`.
  To run tests on Node 22 without nvm or Docker: `npm i --no-save node@22` in a temp dir.
- **helmet's default `Referrer-Policy: no-referrer` breaks every form.** Browsers then send
  `Origin: null` on same-origin POSTs and `originCheck` answers 403 `bad_origin`. Keep
  `referrerPolicy: same-origin` (tests/app.test.js pins it). Node `fetch` tests never see this.
- **Audit advisories drift.** The 2026-09-05 "0 vulnerabilities" state went to
  1 critical + 6 high by 2026-10-30 with no code change. Re-run `npm audit`
  before claiming the gate is green; the `qs` override must stay inside
  express's declared range or `npm ls` reports ELSPROBLEMS.

## Status

M1–M7 + WorkOS auth complete. Repo moved from Windows to macOS on 2026-09-05
and cleaned (spec: `docs/superpowers/specs/2026-09-05-project-cleanup-design.md`):
legacy v1 archived off-repo, deps patched to 0 audit findings, dead migration
script removed, docs re-synced with the real routes. CI
(`.github/workflows/ci.yml`) runs on push; remote `origin` is github.com/laythchebbi/ThreatWatcher (public; history
rewritten 2026-10-31 to scrub the leaked v1 values before the first push). Not yet
booted against live MongoDB/WorkOS — that's the only end-to-end gap.

Next candidates: rotate the SECURITY.md credentials; M4 ML retrain (`train_url_classifier.py` +
`export_onnx.py`, data in the archive); decide on the pending majors
(express 5, mongoose 9, `@workos-inc/node` 10) before building new features.
