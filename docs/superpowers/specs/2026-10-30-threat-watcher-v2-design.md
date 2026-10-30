# Threat Watcher v2 — design

Date: 2026-10-30. Status: draft for approval, revised after two independent reviews. Supersedes the "two apps + WorkOS"
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
  N=2^14, r=8, p=1, `maxmem` passed explicitly, stored as
  `scrypt$N$r$p$salt$hash`), `emailVerifiedAt`, `sessionVersion`, and the
  token fields `verifyTokenHash/verifyTokenExpiresAt`,
  `resetTokenHash/resetTokenExpiresAt`.
- Pages: `/signup`, `/login`, `/logout` (POST), `/forgot`, `/reset/:token`.
- Session = sealed `iron-session` cookie holding `{ userId, sv }`. 30 days,
  `httpOnly`, `sameSite=lax`, `secure` in production. Rolling: re-sealed when
  older than 1 day. `sv` must equal `users.sessionVersion`, which is bumped on
  password change, reset and account deletion, so a stolen or stale cookie can
  be revoked (sealed cookies have no server state otherwise).
- Rate limits, in memory (one process): login 10 per 15 min per email and per
  IP; `/signup` and `/forgot` 5 per hour per IP; "Send test" alert 5 per hour
  per user.
- No account enumeration: login, signup and forgot return the same message
  and run scrypt against a dummy hash when the email is unknown, so timing
  matches. Forgot always says "if that address exists we sent a link".
- CSRF: `sameSite=lax` plus an `Origin`/`Referer` host check on every
  state-changing route (five lines of middleware, second belt).
- Password: 10 to 128 characters, no other rules. A Have I Been Pwned range
  check (k-anonymity, no key) is a later addition, not v2.
- Password reset = random 32-byte token, sha256 stored with a 1-hour expiry,
  single use, cleared on use and on any password change, emailed as a link.
  Email verification uses the same mechanism.
- Abuse cap: an unverified account can look around but cannot add a domain;
  `MAX_DOMAINS_PER_ACCOUNT` = 5 until billing exists. Without this, one
  sign-up could burn the VM's IP against dnstwister and crt.sh for everyone.
- Delete account requires the password and bumps `sessionVersion`.
- No 2FA in v2. The schema leaves room (`totpSecret`), the UI does not.
- Self-serve sign-up is open. No invite mode in v2 (my call after review: with
  no admin role there is nobody in the app to mint invites; a private beta is
  done by not publishing the URL, or with nginx basic auth in front).

### 7.3 Data model

```
users         _id, email (unique), passwordHash, emailVerifiedAt,
              sessionVersion, verifyTokenHash/ExpiresAt, resetTokenHash/ExpiresAt,
              createdAt
domains       _id, userId, name ({userId,name} unique), terms[], createdAt,
              lastWatchedAt, nextWatchAt, watchingSince, lastPermutation[],
              baselineDoneAt
sightings     _id, userId, domainId, lookalike ({domainId,lookalike} unique),
              firstSeenAt, lastSeenAt, baseline(bool), inactive(bool),
              dnsMisses, dns { resolves, a[] },
              cert { firstIssuedAt, issuer, notBefore, lastSeenAt },
              http { status, title, hasPasswordForm, brandTermFound, similarity },
              ml { label, score }, similarity, punycode, substring, severity,
              state(open|dismissed|ignored), dismissedAtSeverity
events        _id, userId, domainId, sightingId|mentionId, kind, severity, at,
              payload, alertedAt
alertChannels _id, userId, kind(email|slack|teams), target, minSeverity,
              verifiedAt, lastDeliveredAt, lastError
darkweb_sources / darkweb_pages   as today, plus a 90-day TTL index on
              darkweb_pages.crawledAt (unbounded growth otherwise)
```

`userId` is denormalised onto sightings, events and mentions so every
dashboard query is one indexed range per user, not a `$in` over domain ids.

A **sighting** is one lookalike domain as currently known. An **event** is a
change to a sighting: `new_lookalike`, `dns_live`, `cert_issued`, `page_live`,
`page_mimics_login`, `gone`. Alerts are sent for events, never for sightings,
which is what keeps the "same alert every cycle" anti-goal out.

**Leak mentions** use the same pattern with a second collection:

```
mentions      _id, domainId, source(darkweb), sourceRef (page id),
              excerpt, excerptHash, matchedTerms[], firstSeenAt,
              state(open|dismissed), dismissedAtSeverity
```

A new `mentions` row raises a `leak_mention` event. `domains.terms[]` holds
the registrable label (`acme-corp`, auto-derived) plus brand words the customer
adds on `/domains/:id` (4 to 40 characters, at most 5), so "ACME Corp" in a
forum post is found even without the domain. Matching is case-insensitive,
whole-word, with `-` and space treated alike. A term that matches more than
5 % of crawled pages is rejected at save time with that number shown.

Severity of a mention (my call after review): a match on a customer-added term
= high; a match only on the auto-derived label = medium, because short labels
(`box`, `mail`) match everything; **critical only when the excerpt holds an
`@<domain>` address or the full domain name**. Words like password, combo or
dump near the match bump one level at most, never to critical on their own,
because dark-web index pages carry those words on every line. The `source`
enum holds only what has a fetcher; new values are added with their fetcher,
not reserved.

A dismissed mention re-raises only when its `excerptHash` changes on a later
crawl (a growing thread), not when the page's timestamp or layout changes.

**Dismissed, ignored and gone (my call after review).** Dismissing a sighting
records `dismissedAtSeverity`. It stays silent while its severity is at or
below that level; the moment the watch raises it higher (a dismissed parked
domain gets a certificate, say) it re-opens with that event and alerts
normally. So dismiss mutes noise, never a real escalation. **Ignored** is the
second button, for the customer's own defensive registrations, CDN hosts and
subsidiaries: an ignored sighting never raises again. `gone` fires only after
**two consecutive** cycles without an A record (parked domains flap); the
sighting stays, flagged `inactive`, and a later return re-fires `dns_live`
only if the A set changed. Once per cycle the watch probes a random label per
TLD and drops TLDs that resolve everything (wildcard TLDs). SecureScore and the
dashboard feed use open, non-dismissed, non-ignored sightings and their events.

**First cycle is a baseline (my call after review).** A newly added domain's
first cycle writes sightings and events but delivers no per-event alerts; it
sends one summary ("watch started: 14 lookalikes already registered, 3 with
certificates, 1 live page") to every channel. Sightings created in that cycle
carry `baseline: true`: their first `dns_live` and `page_live`, whenever they
land (the first cycle caps the HTTP step at the 50 highest-similarity live
candidates, so some land in cycle two), are recorded, not alerted. Only
`cert_issued` with `notBefore` after `firstSeenAt`, and `page_mimics_login`,
alert on baseline sightings. Certificates older than the sighting are recorded
but never raise `cert_issued`, so crt.sh history does not masquerade as fresh
activity. `cert_issued` fires **once per sighting**; renewals (Let's Encrypt
every 60 to 90 days, parking hosts auto-issue) update `cert.lastSeenAt`
silently.

Severity (my call, builder may tune): `new_lookalike` = low; `dns_live` =
medium; `cert_issued` = medium, high if the sighting also resolves or is
punycode/substring (auto-issued certs on parked pages are not "high");
`page_live` = high; `page_mimics_login` = critical; punycode or substring match
bumps one step. SecureScore is kept as a
per-domain summary derived from open sightings (same formula as today) so the
dashboard keeps a single number per domain.

### 7.4 The watch cycle (my call)

An in-process scheduler (`setInterval` every minute, picks domains whose
`nextWatchAt` has passed, at most 3 concurrently) runs, per domain:

1. **Permute.** dnstwister fuzz as today (15 s timeout). On failure, reuse the
   last permutation list stored on the domain so a flaky API never blanks a
   watch.
   1b. **Combosquats.** Generated locally, no API: label × {login, secure,
   support, verify, account, portal, my, mail, help, id} joined with `-` and
   nothing, × the domain's own TLD plus com, net, org, co, io, app. This is
   the most common 2026 phishing pattern and dnstwister's permutations miss
   most of it.
2. **Certificates.** Query crt.sh JSON (`https://crt.sh/?q=%25<label>%25&output=json`,
   20 s timeout, response body capped at 5 MB and 5 000 rows). Skipped for
   labels shorter than 5 characters (the query times out or returns the
   internet). Results are cached **per label** for 6 h so two customers on the
   same brand cost one call; on failure the last cached result is reused, as
   for dnstwister. CT finds subdomain and substring lookalikes
   (`acme-corp-login.example`), not typos, so it complements step 1 rather
   than replacing it. Any name that passes the Dice ≥ 0.7 / punycode /
   substring filter becomes a sighting even before DNS resolves.
   One in-process token bucket per external provider (dnstwister, crt.sh) is
   shared by all cycles so the VM's IP is never the thing that gets banned.
3. **DNS.** `dns.resolve` A records for every candidate (as today).
4. **HTTP.** For sightings that resolve: `GET https://` then `http://`, 8 s
   timeout, follow ≤ 3 redirects, fixed User-Agent. **SSRF guard:** the
   target is resolved first and refused if any address is loopback, private,
   link-local or metadata (`169.254.169.254`); the check repeats after every
   redirect. The 256 KB cap applies to the **decoded** body. Record status
   and `<title>` (rendered with `<%=`, never raw).
   `page_mimics_login` = the page contains a `type=password` form **and** a
   brand term (label or `terms[]`) in its title, text or links. Text
   similarity against `https://<domain>/` is still computed
   (`string-similarity`) and stored as a secondary number, but does not drive
   the event: phishing clones the login page, whose visible text is a dozen
   words, so Dice against marketing copy misses.
5. **ML.** URL classifier label if the worker is up, else null.
   5b. **Leaks.** Search every leak source for the domain's `terms[]` and the
   domain name itself, limited to pages crawled after the domain's
   `lastWatchedAt` (first cycle: everything, as part of the baseline above,
   so history is recorded but not alerted). Sources in v2: the
   `darkweb_pages` the crawler fills, behind a `leakSources` list in code
   that the builder extends with one fetch-and-match function per source.
   Telegram, Twitter and forum feeds need their own ingestion (API keys or
   scraping) and are **out of v2 scope beyond the interface**; the empty
   collections and their models are deleted until a feed exists. Matches
   become `mentions` rows and `leak_mention` events.

   **Where the crawled pages come from (my call after review).** The crawler
   reads `darkweb_sources`; nothing creates those rows today. v2 ships
   `backend/data/darkweb-sources.json` (an empty list with the row format
   documented) and `npm run seed:sources`, which upserts it. The operator
   fills the file; there is no sources page. On a default install the leak
   feature is honestly empty and the `/dark-web` page says "no leak sources
   configured" with a pointer to the seed file. The crawler's `KEYWORDS` env
   goes: matching now happens per domain in the watch step. The crawl timer
   (hourly) bounds how fresh a mention can be.

6. **Diff** against stored sightings → events. Set `nextWatchAt = now + 6 h
± 15 min` jitter (`WATCH_INTERVAL_HOURS` env) so domains added in one
   afternoon do not fire together forever. A manual "Scan now" button just
   sets `nextWatchAt = now`.

**Claiming a domain (my call after review).** The scheduler claims with one
atomic `findOneAndUpdate` on `nextWatchAt <= now AND (watchingSince is null OR
watchingSince < now - 20 min)`, setting `watchingSince = now`. A crash mid-cycle
therefore frees the domain after 20 minutes instead of forever. Capacity at the
defaults (3 concurrent, 6 h interval, about 2 min per domain): roughly 500
watched domains per process. That number lives in 7.9 so the owner knows when
to raise concurrency.

Each step is a function that takes a candidate list and returns enrichments, so
the builder can test them in isolation with recorded fixtures.

### 7.5 Alerts (my call on mechanics)

- Delivery is idempotent: after a cycle, deliver events where `alertedAt` is
  null and severity ≥ the channel's `minSeverity`, grouped per domain into one
  message, then set `alertedAt`. A crash between writing events and sending
  therefore sends on the next pass instead of losing or doubling alerts.
- **Email:** the target is the account's verified address, not a free field
  (a free field plus "Send test" is an open relay). SMTP via `nodemailer`
  (one new dependency), `SMTP_URL` in `.env`; the README recommends a
  transactional provider's free tier, since mail from a bare VM lands in spam.
  Without `SMTP_URL` the app logs the email instead of sending (dev mode);
  in production the log line never contains tokens or links.
- **Slack:** incoming webhook URL the customer pastes. **Teams:** incoming
  webhook URL. Both are a `POST` with a JSON body; same code path with two
  formatters. Webhook URLs are secrets: masked in the UI after save, never
  logged. "Send test" on save sets `verifiedAt` and is rate limited.
- Failures set `lastError` on the channel and show on the Alerts page; no
  retries beyond one immediate retry.
- Alert latency target: event written → message sent in under 1 minute.

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

The Python crawler, Tor and its systemd timer remain as the **one scheduled
sidecar**; anti-goal 5 is about request-path processes, not batch jobs.

`frontend/` entirely; `backend/src/middleware/auth.js` (WorkOS), `services/
workos.js`, `routes/auth.js` invitations, `@workos-inc/node`, `jose`, `axios`,
the `/api/*` proxy, `DEMO_MODE` and `demo/` (a local MongoDB is the only
requirement now; the README gives a one-line `docker run` and a `brew` line),
the Report model and `/reports` pages (replaced by sightings and events),
`metrics.js` duplicates. `deploy/` shrinks to one service plus the crawler
timer; `nginx.conf` to one upstream.

### 7.8 Migration

There are no production users. No data migration; the dev database is dropped.

### 7.9 Rewrite, not refactor (owner: "redo and optimise")

The new app is written fresh in `app/`. Ported as files, with their tests:
`domain-similarity.js`, the ML bridge and `url_classifier.py`, the crawler and
its timer, the config/logger/request-id/error-handler pattern, and the CSS
tokens. Everything else is new code. `backend/` and `frontend/` are deleted
once `app/` runs, in the same change, so the repo never holds two apps.

**Clean code bar.** One job per module; a route file holds routes and nothing
else, a service holds logic and touches no `req`/`res`. No wrapper layers,
no factories with one product, no options nobody asked for. Every watch step
is a pure function over plain objects so it is testable from fixtures without
a database. Names say what things are (`sightings`, not `data`). Comments
explain only what the code cannot show. Prettier, eslint and `checkJs` stay
on; lint-staged keeps them on every commit.

**Performance bar (measured, not hoped).**

- Auth reads one session cookie; no database write per request. User lookup
  is one indexed `_id` read.
- Every page renders from one or two indexed queries. Indexes: `users`
  `{ email }` unique; `domains` `{ userId, name }` unique, `{ nextWatchAt }`;
  `sightings` `{ domainId, lookalike }` unique, `{ userId, state }`;
  `events` `{ userId, at }`, `{ domainId, at }`, `{ alertedAt }` sparse;
  `mentions` `{ domainId, sourceRef }` unique, `{ userId, firstSeenAt }`;
  `alertChannels` `{ userId }`; `darkweb_pages` `{ crawledAt }` TTL 90 d.
- The dashboard feed is paginated at 100 events and stays under 100 ms of
  server time with 50 000 events spread over 20 users (fixture-seeded test).
- Login p95 under 300 ms (scrypt runs on the libuv thread pool).
- The watch cycle bounds its fan-out: DNS 50 in flight, HTTP 8 in flight
  (memory ceiling 8 × 256 KB decoded), crt.sh one call per label per 6 h,
  all with timeouts; a domain with 1 000 candidates finishes in under 60 s
  against recorded fixtures whose DNS stub answers in 50 ms, so the test
  measures the concurrency bounds, not CPU.
- At most 3 domains watched concurrently; one atomic claim per domain with a
  20-minute expiry; capacity about 500 domains per process at the defaults.
- Static assets served with long cache headers; responses gzipped; the
  client script stays under 5 KB.

Each of these is a line item in the implementation plan with its own check.

## 8. Left to the builder

- Which customer page to compare text against (default: `https://<domain>/`).
- Email templates and the Slack/Teams message layouts.
- How the dashboard paginates past 100 events (cursor on `{ at, _id }`).
- The exact private-range list for the SSRF guard (RFC 1918, loopback,
  link-local, ULA, metadata).
- Whether to keep the geolocation mockup page.
- Test fixtures: recorded dnstwister, crt.sh and HTTP responses.

## 9. Plan of record (expected order, for the implementation plan)

1. Scaffold `app/`: config, logger, server, sessions with `sessionVersion`,
   sign-up/sign-in/forgot/reset with rate limits, enumeration-safe responses
   and the Origin check; the ported scoring and ML modules with their tests.
   Gates green on `app/`.
2. Data model and indexes: domains, sightings, events, mentions,
   alertChannels. Domain pages: add, list, detail.
3. Watch cycle as pure steps with fixtures: permute, DNS, diff, scheduler,
   baseline rule, dismiss/gone rules.
4. Combosquats, certificate transparency with per-label cache and provider
   token buckets, HTTP enrichment with the SSRF guard and the password-form
   rule, with the fan-out bounds.
5. Leak mentions: `terms[]`, `mentions`, the crawler-pages source, seed
   command, the `/dark-web` page.
6. Alerts: idempotent delivery on `alertedAt`; email, then Slack and Teams;
   baseline summary message; domain cap and verification gate.
7. Console UI pass over every page; client script under 5 KB.
8. Performance checks from 7.9 as tests; delete `backend/` and `frontend/`;
   deploy files and docs.

Each step leaves the gates green and the app runnable.
