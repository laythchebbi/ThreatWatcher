# Project cleanup design — 2026-09-05

**Goal.** Leave the repo as a lean, truthful base to rebuild on: the modernized
`backend/` and `frontend/` stay, everything that is dead, duplicated, stale, or
inherited from the Windows machine goes, and all four quality gates return to
green on this Mac.

**Context.** The repo was copied from a Windows PC on 2026-09-05. Findings from
the arrival scan: `node_modules/` is a Windows copy (34 `.cmd`/`.ps1` shims,
workspace links broken, `npm ls` reports most packages extraneous);
`npm audit` reports 9 vulnerabilities (5 high) from advisories published after
the last commit; the git-ignored legacy `ThreatWatcher/` folder is 1.1 GB and
is the only copy of the v1 source, pre-trained models, and training data;
several docs describe code that does not exist.

**Approach.** Small, single-concern commits on `main`, in the order below, so
any step reverts on its own. No branch (no remote, no reviewer). No history
rewrite (history is secret-free and holds recoverable design work).

## 1. Archive the legacy v1 folder, then delete it

- Source: `ThreatWatcher/` (git-ignored, no git of its own).
- Destination: `~/Documents/threat-watcher-legacy-v1.tar.gz` plus a
  `.sha256` file beside it. Outside the repo.
- Exclude: `venv/`, `.venv/`, `node_modules/`, `site-packages/`,
  `__pycache__/`, `*.pyc`, `.DS_Store`, and `WebConent/` (byte-identical
  duplicate of `WebContentML/`; only `.git` internals differ).
- Include a `LEGACY-README.md` at the archive root listing what is inside:
  `URLML/` (labeled URL dataset `dataNN.csv`, `vectorizer1.pkl`,
  `mal-logireg1.pkl`), `WebContentML/` (`random_forest.pkl`), `DarkWeb/`
  (`backup.sql`), `DataLeak/`, `DataLeaks/`, `BackEnd/`, `FrontEnd/`.
- Expected size: about 290 MB uncompressed.
- **Security:** the archive contains the hardcoded credentials catalogued in
  `SECURITY.md` and a Telegram `.session` file. It stays on local disk only.
- Verify before deleting: `tar -tzf` succeeds, the four model/data files above
  are listed, checksum file written. Then `rm -rf ThreatWatcher/`.

## 2. Remove Windows leftovers

Delete `node_modules/`, `package-lock.json`, `.claude/settings.local.json`
(Windows-path permissions, per-user, git-ignored), and every `.DS_Store`.
Reinstall with `npm install` on this Mac. `.husky/_/` regenerates.

## 3. Dependencies: zero audit findings

| Package                          | Action                                             |
| -------------------------------- | -------------------------------------------------- |
| backend `axios`                  | remove (not imported; backend uses native `fetch`) |
| backend `express-rate-limit`     | remove (not imported anywhere)                     |
| frontend `axios`                 | bump to the patched 1.x                            |
| `express` (both apps)            | bump to the patched 4.x                            |
| `mongoose`                       | bump to the patched 8.x                            |
| root override `qs`               | raise above 6.15.3                                 |
| `undici`, `js-yaml`, `brace-expansion` | transitive (cheerio, eslint, ejs); fix via `npm audit fix` or a direct bump if needed |

Edit `package.json` files first, then clean install (overrides only apply on a
clean install). Acceptance: `npm audit` reports 0 vulnerabilities and CI's
`npm audit --audit-level=high` exits 0.

## 4. Code pruning

- Remove `backend/scripts/migrate_to_mongo.js`: requires `mssql`/`mysql`
  drivers that are not in any `package.json`, so it cannot run; its source
  databases are in the archive.
- **Keep** the geolocation page (`/geolocation`), route, and sidebar entry.
  It is a static mockup with hardcoded numbers; docs will say so.
- **Keep** the design-system page (`/design-system`).
- Keep `backend/scripts/darkweb_crawl.py`, `deploy/`, and `backend/ml/`.

## 5. Docs made truthful

- `README.md`: rewrite "Endpoints" from the real routes (no
  `/auth/register`, `/auth/login`, or `/api/domains/registered`; add the
  `/api/users/*` and `/auth/invitations` routes); drop the "Legacy → MongoDB
  migration" section; mark `/geolocation` as a static mockup.
- `frontend/README.md`: `/` redirects to `/dashboard`, not `/geolocation`;
  layout tree lists all views; geolocation described as a static mockup.
- `SECURITY.md`: remove the claim that `express-rate-limit` is retained.
- `deploy/README.md`: drop the migration cutover section.
- `.gitignore` and `pyproject.toml`: remove `ThreatWatcher/` exclusions.
- `CLAUDE.md`: status reflects the Mac move, archive location, audit state,
  and the removed items.

## 6. Verification (definition of done)

1. `npm run lint`, `npm run typecheck`, `npm test` (31 tests), `npm audit`
   (0 vulnerabilities) all pass.
2. Demo boot: backend `/health` returns ok, frontend `/` redirects to
   `/dashboard`, dashboard renders with the demo banner.
3. `git status` clean; each concern is its own commit.

## Out of scope

M4 ML retrain, replacing frontend `axios` with `fetch`, booting against live
WorkOS/MongoDB, adding a git remote.
