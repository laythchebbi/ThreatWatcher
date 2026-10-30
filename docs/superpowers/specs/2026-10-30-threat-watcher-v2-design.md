# Threat Watcher v2 — design

Date: 2026-10-30. Status: draft for approval. Supersedes the "two apps + WorkOS"
shape documented in `README.md` and `CLAUDE.md`.

## 1. Intent

Threat Watcher is a SaaS product that warns a customer while a phishing campaign
against their brand is still being prepared: a lookalike domain gets registered,
pointed at a server, issued a TLS certificate, and loaded with a copy of the
customer's login page. Every one of those steps leaves a public trace. The
product watches those traces for the customer's protected domains and raises an
event the moment something new appears, before any phishing email is sent.

Today's code runs the checks only when a user presses "scan", requires a WorkOS
account before the app can even start, and is split into two Node processes to
carry WorkOS tokens between them. v2 makes continuous watching the core, moves
sign-in into the app, and collapses the two processes into one.

## 2. Decisions already made (by the owner)

- **Auth is self-hosted.** No external identity provider. The reason WorkOS goes
  is setup friction, so v2 must run with nothing but Node, MongoDB and an `.env`.
- **One person per account** for now. No organizations, teams or roles.
- **Visual direction: "Console".** Dark, dense, monospace numerals, a severity
  stripe on every row. The existing `.tw-*` token set (IBM Plex Sans / Mono,
  oklch accent) stays; it is tightened, not replaced.
- **Alerts reach the customer on the dashboard and by email.** Slack and
  Microsoft Teams messages are product features (webhook integrations the
  customer configures), not something the operator wires in `.env`.
- **Proactive is the point.** On-demand scans remain as a tool, but the product
  is the scheduled watch.
- **Leak mentions are part of the watch.** Besides lookalike infrastructure,
  the product checks whether data leaks or dark-web posts talk about the
  customer's company, and alerts on new mentions the same way.

## 3. Goals

1. A customer can sign up, add a domain, and within one watch cycle see what is
   already out there for it.
2. From then on, anything new (domain, DNS answer, certificate, live page) shows
   up as an event with a severity and a timestamp, on the dashboard and in their
   inbox / Slack / Teams, without them touching the app.
3. A developer can run the whole thing locally with `npm install`, a MongoDB
   URL, and `npm start`. Nothing else to sign up for.
4. One deployable process. One `.env`. One port.

## 4. Non-goals (not in v2)

- Teams, shared workspaces, roles, SSO, SCIM.
- Takedown requests, abuse reporting, registrar integration.
- Browser screenshots of phishing pages.
- Billing and plans.
- The geolocation page (stays a mockup or is removed; builder's call).
- Rewriting the Python classifier. It stays an optional signal.

## 5. Anti-goals (would make v2 a failure even if it "works")

- A customer adds a domain and nothing happens until they press a button.
- An alert fires for the same lookalike every cycle. Events are about **change**.
- Setting the app up needs a dashboard on someone else's website.
- A second process, a proxy, or a token hop re-appears "for cleanliness".

## 6. Constraints

- Keep the stack: Node 20, Express 4, EJS, MongoDB via mongoose, plain CommonJS
  with `checkJs`, `node --test`, prettier, eslint. No TypeScript source, no
  front-end framework, no build step.
- Python stays optional and out of the request path: a child process worker the
  app runs without if the model is missing (as now).
- Single VM deploy behind nginx (`deploy/`), systemd units.
- All four gates stay green: lint, typecheck, test, `npm audit` at 0.
- Reuse first: `iron-session` (already a dependency) for sessions,
  `node:crypto` for password hashing, `domain-similarity.js` for scoring,
  the crawler as it is.

## 7. The shape of v2 (owner-approved direction, details are my calls)

### 7.1 One process

`app/` (rename of `backend/`; `frontend/` is deleted) is one Express server that
renders EJS pages **and** answers JSON for the little client-side script the
pages need. No `/api/*` proxy, no Bearer tokens, no second `config/`, `logger.js`,
`metrics.js`. Port 3000. Everything the two apps shared is kept once.

### 7.2 Sign-up, sign-in, sessions (my call)

- `users` gains `passwordHash` (scrypt via `node:crypto.scrypt`, 16-byte salt,
  N=2^15, stored as `scrypt$N$salt$hash`) and `emailVerifiedAt`.
- Pages: `/signup`, `/login`, `/logout` (POST), `/forgot`, `/reset/:token`.
- Session = sealed `iron-session` cookie holding `{ userId }` only. 30 days,
  `httpOnly`, `sameSite=lax`, `secure` in production. Rolling: re-sealed when
  older than 1 day.
- Login is rate limited per email and per IP (10 per 15 min, in memory; one
  process, so that is enough).
- Password reset = random 32-byte token, sha256 stored with a 1-hour expiry,
  emailed as a link. Email verification uses the same mechanism. Unverified
  accounts can use the app but receive no alerts until verified (so we never
  spam an address someone typed by mistake).
- No 2FA in v2. The schema leaves room (`totpSecret`), the UI does not.
- Self-serve sign-up is open. No invite mode in v2 (my call after review: with
  no admin role there is nobody in the app to mint invites; a private beta is
  done by not publishing the URL, or with nginx basic auth in front).

### 7.3 Data model

```
users         _id, email, passwordHash, emailVerifiedAt, createdAt
domains       _id, userId, name, createdAt, lastWatchedAt, nextWatchAt
sightings     _id, domainId, lookalike, firstSeenAt, lastSeenAt,
              dns { resolves, a[] }, cert { seenAt, issuer, notBefore },
              http { status, title, similarity }, ml { label, score },
              similarity, punycode, substring, severity, state(open|dismissed)
events        _id, domainId, sightingId, kind, severity, at, payload
alertChannels _id, userId, kind(email|slack|teams), target, minSeverity,
              verifiedAt, lastDeliveredAt, lastError
darkweb_sources / darkweb_pages   unchanged (crawler)
```

A **sighting** is one lookalike domain as currently known. An **event** is a
change to a sighting: `new_lookalike`, `dns_live`, `cert_issued`, `page_live`,
`page_mimics_login`, `gone`. Alerts are sent for events, never for sightings,
which is what keeps the "same alert every cycle" anti-goal out.

**Leak mentions** use the same pattern with a second collection:

```
mentions      _id, domainId, source(darkweb|telegram|twitter|forum|paste),
              sourceRef (page or post id), excerpt, matchedTerms[],
              firstSeenAt, state(open|dismissed)
```

A new `mentions` row raises a `leak_mention` event (severity high; critical when
the excerpt contains an `@<domain>` email address or the words password,
credentials, combo, dump next to the brand). `domains` gains `terms[]`: the
registrable label (`acme-corp`) plus any brand words the customer adds, so
"ACME Corp" in a forum post is found even without the domain.

**Dismissed and gone (my call after review).** Dismissing a sighting records
`dismissedAtSeverity`. It stays silent while its severity is at or below that
level; the moment the watch raises it higher (a dismissed parked domain gets a
certificate, say) it re-opens with that event and alerts normally. So dismiss
mutes noise, never a real escalation. `gone` fires when a sighting that
resolved stops resolving (CT records never disappear, so DNS and HTTP are the
only observable "gone"); the sighting stays, flagged `inactive`, and a later
return re-fires `dns_live`. SecureScore and the dashboard feed use open,
non-dismissed sightings and their events.

**First cycle is a baseline (my call after review).** A newly added domain's
first cycle writes sightings and events but delivers no per-event alerts; it
sends one summary ("watch started: 14 lookalikes already registered, 3 with
certificates, 1 live page") to every channel. Certificates whose `notBefore`
predates the sighting's `firstSeenAt` are recorded but never raise
`cert_issued`, so crt.sh history does not masquerade as fresh activity. The
builder caps the first cycle's HTTP step at the 50 highest-similarity live
candidates to keep a popular brand's backlog from stalling the scheduler.

Severity (my call, builder may tune): `new_lookalike` = low; `dns_live` =
medium; `cert_issued` = high; `page_live` = high; `page_mimics_login` =
critical; punycode or substring match bumps one step. SecureScore is kept as a
per-domain summary derived from open sightings (same formula as today) so the
dashboard keeps a single number per domain.

### 7.4 The watch cycle (my call)

An in-process scheduler (`setInterval` every minute, picks domains whose
`nextWatchAt` has passed, at most 3 concurrently) runs, per domain:

1. **Permute.** dnstwister fuzz as today (15 s timeout). On failure, reuse the
   last permutation list stored on the domain so a flaky API never blanks a
   watch.
2. **Certificates.** Query certificate transparency for `%.<label>%` style
   matches via crt.sh JSON (`https://crt.sh/?q=<pattern>&output=json`, 20 s
   timeout). Any certificate name that passes the same Dice ≥ 0.7 /
   punycode / substring filter becomes a sighting even if DNS does not resolve
   yet. This is the earliest signal we have.
3. **DNS.** `dns.resolve` A records for every candidate (as today).
4. **HTTP.** For sightings that resolve: `GET https://` then `http://`, 8 s
   timeout, 256 KB cap, follow ≤ 3 redirects. Record status and `<title>`.
   Compare visible text to the customer's own page once per cycle
   (`string-similarity`, already a dependency) → `http.similarity`;
   ≥ 0.6 marks `page_mimics_login`.
5. **ML.** URL classifier label if the worker is up, else null.
   5b. **Leaks.** Search every leak source for the domain's `terms[]` and the
   domain name itself, limited to items newer than the domain's
   `lastWatchedAt` (so each post is considered once). Sources in v2: the
   `darkweb_pages` the crawler fills, plus a `leakSources` list in code that
   the builder can extend with one fetch-and-match function per source.
   Telegram, Twitter and forum feeds need their own ingestion (API keys or
   scraping) and are **out of v2 scope beyond the interface**; the empty
   collections and their models are deleted until a feed exists. Matches
   become `mentions` rows and `leak_mention` events.
6. **Diff** against stored sightings → events. Set `nextWatchAt = now + 6 h`
   (`WATCH_INTERVAL_HOURS` env). A manual "Scan now" button just sets
   `nextWatchAt = now`.

Each step is a function that takes a candidate list and returns enrichments, so
the builder can test them in isolation with recorded fixtures.

### 7.5 Alerts (my call on mechanics)

- Delivery runs right after a cycle's diff: for each event ≥ channel's
  `minSeverity`, group events per domain per cycle into one message.
- **Email:** SMTP via `nodemailer` (one new dependency), `SMTP_URL` in `.env`.
  Without `SMTP_URL` the app logs the email instead of sending (dev mode).
- **Slack:** incoming webhook URL the customer pastes. **Teams:** incoming
  webhook URL. Both are a `POST` with a JSON body; same code path with two
  formatters. The customer presses "Send test" on save, which sets
  `verifiedAt`.
- Failures set `lastError` on the channel and show on the Alerts page; no
  retries beyond one immediate retry.

### 7.6 Pages (Console direction)

| Route                                           | What it shows                                                                                                                                               |
| ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/`                                             | Dashboard: open events feed across all domains, newest first, severity stripe, one line each. Top strip: domains watched, open sightings, events last 24 h. |
| `/domains`                                      | List with SecureScore, open sightings count, last watched, next watch. "Add domain" inline.                                                                 |
| `/domains/:id`                                  | Timeline of events for that domain; table of sightings with similarity, DNS, cert, page, ML columns; dismiss button per sighting; "Scan now".               |
| `/dark-web`                                     | Open leak mentions across all domains, newest first, with source and excerpt; plus the free keyword search over `darkweb_pages` as today.                   |
| `/alerts`                                       | Email, Slack, Teams channels; minimum severity per channel; send test.                                                                                      |
| `/settings`                                     | Email, password change, delete account.                                                                                                                     |
| `/signup`, `/login`, `/forgot`, `/reset/:token` | Auth pages, no shell.                                                                                                                                       |

Server-rendered as now. The only client JS is: dismiss sighting, send test
alert, add/remove domain without a full reload. Keep `app.js` to theme prefs
plus those three fetches.

### 7.7 What gets deleted

`frontend/` entirely; `backend/src/middleware/auth.js` (WorkOS), `services/
workos.js`, `routes/auth.js` invitations, `@workos-inc/node`, `jose`, `axios`,
the `/api/*` proxy, `DEMO_MODE` and `demo/` (a local MongoDB is the only
requirement now; the README gives a one-line `docker run` and a `brew` line),
the Report model and `/reports` pages (replaced by sightings and events),
`metrics.js` duplicates. `deploy/` shrinks to one service plus the crawler
timer; `nginx.conf` to one upstream.

### 7.8 Migration

There are no production users. No data migration; the dev database is dropped.

## 8. Left to the builder

- Exact crt.sh query strategy and how to cap results for short labels.
- The login-page similarity threshold and how to pick which customer page to
  compare against (default: `https://<domain>/`).
- Email templates and the Slack/Teams message layouts.
- Index design on `sightings` and `events`.
- How the dashboard paginates past 200 events.
- Whether to keep the geolocation mockup page.
- Test fixtures: recorded dnstwister, crt.sh and HTTP responses.

## 9. Plan of record (expected order, for the implementation plan)

1. Collapse to one process with the existing pages still working (no auth
   change yet) and delete `frontend/`.
2. Replace WorkOS with self-hosted auth; delete WorkOS code and demo mode.
3. Data model: domains, sightings, events; convert the scan into the watch
   cycle; scheduler.
4. Certificate transparency and HTTP enrichment.
   4b. Leak mentions: `terms[]`, `mentions`, the crawler-pages source, the
   `/dark-web` page.
5. Alerts: email, then Slack and Teams.
6. Console UI pass over the new pages.
7. Deploy files and docs.

Each step leaves the gates green and the app runnable.
