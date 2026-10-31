# Threat Watcher v2 — `app/`

The single-process successor to `backend/` + `frontend/`. One Express server
renders the pages and runs the watch; sign-in is built in; MongoDB is the only
service. Design: `docs/superpowers/specs/2026-10-30-threat-watcher-v2-design.md`.
Plans 1 and 2 of 3 are in (`docs/superpowers/plans/2026-10-31-v2-core.md`,
`2026-10-31-v2-signals.md`): accounts, domains, the watch cycle with
permutations, DNS, certificates, page facts, RDAP, email posture and leak
mentions (crawled pages and Have I Been Pwned). Alerts, the UI pass and
deleting the old apps are Plan 3.

## Run locally

```bash
# MongoDB (pick one)
docker run -d --name tw-mongo -p 27017:27017 mongo:7
brew install mongodb-community && brew services start mongodb-community

# Python worker: dnstwist permutations (+ the optional URL classifier)
python3 -m venv app/.venv && app/.venv/bin/pip install -r app/ml/requirements.txt

# App
cp app/.env.example app/.env        # set SESSION_PASSWORD; PYTHON_BIN=app/.venv/bin/python
npm install                         # from the repo root, installs every workspace
npm -w app start                    # → http://localhost:3000
```

Another project on this Mac tends to hold port 3000; run with `PORT=3100` and
`BASE_URL=http://localhost:3100` when it does.

Until Plan 3 adds the SMTP transport, verification and reset emails are
logged instead of sent (full text at `info` outside production); copy the
link out of the log. Behind nginx set `TRUST_PROXY=loopback` so the per-IP
rate limits see real client addresses. Add a domain, press **Scan now** or wait for the
minute tick, and the first watch cycle (the baseline) fills the domain page.

## Test data

```bash
npm -w app run seed:demo   # local only; refuses NODE_ENV=production
```

Creates a verified test account with two watched domains (acme-corp.com,
northwind-bank.com), lookalikes in every tab, events, leak mentions and a
crawled leak page. The sign-in details are at the top of `scripts/seed-demo.js`.
Running it again replaces that account's data and signs it out. Next real scan
is five hours out; press **Scan now** to run one against live sources.

## Tests

```bash
npm -w app test      # node --test; route and model tests use mongodb-memory-server
```

The first run downloads a MongoDB binary (about 150 MB) into
`~/.cache/mongodb-binaries`. Pure modules (diff, severity, permute, dns,
password, session) need no database.

## Layout

```
src/server.js         boot: db → worker → scheduler → listen
src/app.js            createApp(): middleware, routes, error handling (tests listen on port 0)
src/config.js         zod-validated .env
src/middleware/       session (iron-session + sessionVersion), rate-limit, origin-check, errors
src/services/auth.js  signup, login, verify, reset
src/services/password.js  scrypt
src/services/watch/   permute → certs → dns → rdap → http → posture → diff → leaks → cycle → scheduler
                      providers (token buckets, label cache), severity, warninglists, hibp
src/services/ml-bridge.js  the Python worker (permute + classify)
src/routes/           auth, dashboard, domains (+ sighting/mention actions, terms, HIBP key, scan now), darkweb
src/views/            EJS, Console look; styles in public/css/styles.css
ml/url_classifier.py  worker; ml/requirements.txt
data/warninglists/    vendored MISP lists (npm run update:warninglists)
data/darkweb-sources.json  crawl targets (npm run seed:sources)
scripts/darkweb_crawl.py   Tor crawler (hourly timer), scripts/seed-sources.js
```
