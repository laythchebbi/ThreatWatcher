# Security policy & rotation runbook

This file is the source of truth for credential rotation and history scrub. Anything that lived in `ThreatWatcher/` source (the legacy v1 codebase from 2022) must be assumed compromised — those files were public-readable and the credentials are present in git history of embedded `.git/` repos.

## Reporting

Email security findings to **security@<your-domain>** (replace before publishing). Do not open public issues for vulnerabilities.

## Compromised credentials — rotate immediately

| #   | Credential                                                                          | Where it leaked                                                                                                                                                       | Action                                                                                                                                                                    |
| --- | ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | MongoDB Atlas user `layth1` (cluster `cluster0.kjfil.mongodb.net`)                  | `ThreatWatcher/BackEnd/backend/app.js:76`, `ThreatWatcher/BackEnd/backend/data_get.py:7`                                                                              | Rotate password in Atlas console. Tighten IP allowlist. Audit cluster access logs for past 30 days.                                                                       |
| 2   | Azure SQL user `layth` (`threatwatcher.database.windows.net`, db `threatwatcherdb`) | `ThreatWatcher/BackEnd/backend/app.js:63-72` (commented but in git history)                                                                                           | Rotate password in Azure portal. Confirm the DB is being decommissioned per the modernization plan.                                                                       |
| 3   | WhoisXML API key `***REMOVED***`                                 | `ThreatWatcher/BackEnd/backend/FetchingAPI.js:95`                                                                                                                     | Revoke key at whoisxmlapi.com. Generate new key. Set as `WHOISXML_API_KEY` in `backend/.env`.                                                                             |
| 4   | Slack bot token                                                                     | `ThreatWatcher/BackEnd/backend/consumer.js`                                                                                                                           | Rotate at api.slack.com. Set as `SLACK_BOT_TOKEN` in `backend/.env`.                                                                                                      |
| 5   | Telethon session for `@laythchebbi`                                                 | `ThreatWatcher/DataLeaks/@laythchebbi.session` and `ThreatWatcher/DataLeak/data_leak_api/data_leak_api/api/@laythchebbi.session` (both now only in the local archive) | Terminate all active Telegram sessions in the app; re-auth from a clean machine. The `.session` file is now `.gitignore`d but exists in history of the embedded git repo. |

After rotation, document the rotation date next to each row. Do NOT remove this table — it's the historical record.

## Scrubbing git history

There are embedded `.git/` directories inside `ThreatWatcher/FrontEnd/Threat-Watcher-front-login/Threat-Watcher/` and `ThreatWatcher/DataLeaks/`. These hold the leaked credentials in commit history.

The simplest, safest path:

1. **Don't rewrite history if the repo was never published.** If these `.git/` repos were only on your machine, just delete them and start fresh:

   ```bash
   rm -rf "ThreatWatcher/FrontEnd/Threat-Watcher-front-login/Threat-Watcher/.git"
   rm -rf "ThreatWatcher/DataLeaks/.git"
   ```

   Then init a single new repo at the project root. (The legacy `ThreatWatcher/` tree was archived to `~/Documents/threat-watcher-legacy-v1.tar.gz` on 2026-09-05 and removed from the working tree. The archive is local-only and still contains every secret listed above.)

2. **If the old repos were pushed to a remote** (GitHub, GitLab, etc.), you must:

   - Use [`git filter-repo`](https://github.com/newren/git-filter-repo) (NOT `git filter-branch`) on each embedded repo:
     ```bash
     cd "ThreatWatcher/FrontEnd/Threat-Watcher-front-login/Threat-Watcher"
     git filter-repo --replace-text <(cat <<'EOF'
     ***REMOVED***==>***REMOVED***
     ***REMOVED***==>***REMOVED***
     ***REMOVED***==>***REMOVED***
     EOF
     )
     ```
   - Force-push the rewritten history (`git push --force-with-lease`).
   - Tell every cloned-down collaborator to re-clone.
   - **Rotate every credential anyway** — assume any prior clone or fork still has the old values.

3. **Verify** with `gitleaks detect --source .` — it should find zero matches after the scrub.

## What goes in `.env`, never in git

- `MONGODB_URI`
- `WORKOS_API_KEY`
- `SESSION_PASSWORD`
- Any future API keys or DB connection strings

The repo root `.gitignore` excludes `.env` and `.env.local`. Each app (`backend/`, `frontend/`) ships a `.env.example` with the _names_ of required variables but no values.

## Legacy v1 archive (local-only)

The 2022 v1 tree was archived on 2026-09-05 to
`~/Documents/threat-watcher-legacy-v1.tar.gz` (sha256 file beside it). It still
contains every secret in rows 1–5 above plus two Telethon `.session` files.
Keep it on local disk only: never commit, upload, or sync it, and do not enable
iCloud "Desktop & Documents" sync on this Mac while it lives in `~/Documents`.
Delete the archive once rows 1–5 are rotated and the M4 retrain has extracted
`dataNN.csv` and the v1 `.pkl` models it needs.

## Pre-commit + CI protection (added in M1)

- `husky` runs `lint-staged` on every commit (eslint + prettier on staged files).
- `.gitleaks.toml` declares custom rules for the three known leaked values (Mongo password, WhoisXML key, MSSQL password). CI runs `gitleaks` on every push/PR and fails on any match outside this file and `SECURITY.md`.
- `.github/workflows/ci.yml` additionally runs `npm audit` (high+ severity) and `pip-audit`.

## Threat model

What the modernization addresses:

- **Secrets in source** → moved to `.env`, validated by zod at startup, redacted from logs (pino redact paths).
- **SQL injection** → consolidated on MongoDB + mongoose; no raw SQL anywhere in active code.
- **Identity & access** → delegated to **WorkOS User Management** (AuthKit). Backend never sees passwords; it validates WorkOS-issued access tokens via the project JWKS (RS256). Frontend stores access + refresh tokens in a sealed, httpOnly, SameSite=Lax cookie (`iron-session`, AES-GCM). Admins invite users; public sign-up is disabled in the WorkOS dashboard.
- **Two-factor auth** → opt-in TOTP enrollment in the WorkOS AuthKit hosted flow. Settings → "Manage 2FA & sessions" links users to the WorkOS portal.
- **Session revocation** → access tokens are short-lived; refresh-token rotation happens server-side in the frontend's `/api/*` proxy. Sign-out destroys the sealed cookie. Admins can deactivate a user (`POST /api/users/:id/deactivate`) which causes the `requireUser` middleware to return 403 even with a valid token.
- **Brute-force resistance** → password attempts are rate-limited by WorkOS at the IdP. The app has no rate limiting of its own yet; add `express-rate-limit` when a public-facing endpoint exists.
- **OAuth (Google, Microsoft)** → handled by AuthKit; we never receive the IdP's tokens directly.
- **Open CORS** → restricted to `FRONTEND_ORIGIN`.
- **Bare catches that hide failures** → replaced by `pino` structured logging at warn/error.
- **Unvalidated input** → zod schemas on every route (`searchDomainParams`, `invitationBody`, `dataleakQuery`, etc.). Search params reject anything that isn't a valid RFC-1035 domain.
- **Helmet** applied on both apps with a strict CSP on the frontend.

WorkOS-specific environment variables (rotate in WorkOS dashboard if leaked):

- `WORKOS_API_KEY` — server-only. Treat like a Mongo connection string.
- `WORKOS_CLIENT_ID` — public-ish (visible to the browser on AuthKit redirects).
- `WORKOS_ORGANIZATION_ID` — non-secret identifier of the single tenant org.
- `SESSION_PASSWORD` (frontend) — symmetric key sealing the session cookie. **Rotating this signs every user out.** Generate with `openssl rand -base64 48`.

Out of scope (tracked in later milestones):

- Per-route audit logging to a separate sink (M6 in progress).
- Threat-intel feed corroboration (VirusTotal, AbuseIPDB) — M7.
- WebAuthn / passkeys via WorkOS — when needed; toggle in the WorkOS dashboard, no code change required.
- Multi-tenant (organizations) — would require adding an `organizationId` scope to every Mongo query.
