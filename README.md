# Threat Watcher

Threat Watcher is a web application that finds phishing campaigns before they start.
You give it the domains that you own. It finds lookalike domains that attackers
register, it watches what those domains do, and it shows each change to you as an
event. It also finds data leaks that speak about your company.

NOTE: This document uses ASD-STE100 Simplified Technical English.

## 1 What the application does

The application runs a watch cycle for each monitored domain every 6 hours. One
watch cycle does these steps:

1. It makes a list of lookalike domains (permutations) with dnstwist.
2. It gets new TLS certificates for those names from Certificate Transparency logs.
3. It resolves the DNS records (A, MX, NS) of each candidate domain.
4. It gets the registrar and the registration date of each live domain from RDAP.
5. It downloads the home page of each live domain. It looks for a password form and
   for your brand terms.
6. It checks the SPF, DMARC and DKIM records of your own domain. It gives the domain
   a grade from A to F.
7. It compares the new data with the data from the last cycle. It makes one event for
   each change.
8. It searches crawled leak pages and Have I Been Pwned for mentions of your terms.

Each event has a severity: info, low, medium, high or critical. The dashboard shows
the events in order of severity. On the domain page you can dismiss an event, ignore
a lookalike domain, or start a new scan.

## 2 Repository layout

| Path                       | Content                                                                       |
| -------------------------- | ----------------------------------------------------------------------------- |
| `app/`                     | The application (version 2). Use this directory.                              |
| `backend/`, `frontend/`    | The old version 1 applications. Plan 3 removes them. Do not add code to them. |
| `docs/superpowers/specs/`  | The design documents.                                                         |
| `docs/superpowers/plans/`  | The implementation plans.                                                     |
| `SECURITY.md`              | The security policy and the list of credentials that you must rotate.         |
| `.github/workflows/ci.yml` | The continuous integration checks.                                            |

## 3 Requirements

- Node.js 22.19 or newer
- npm (installed with Node.js)
- Python 3.9 or newer
- MongoDB 7

## 4 Installation

1. Clone the repository.
2. Go to the root directory of the repository.
3. Install the Node.js packages:

   ```bash
   npm install
   ```

4. Make a Python virtual environment and install the worker packages:

   ```bash
   python3 -m venv app/.venv
   app/.venv/bin/pip install -r app/ml/requirements.txt
   ```

5. Copy the example configuration file:

   ```bash
   cp app/.env.example app/.env
   ```

6. Open `app/.env` and set the values. Refer to section 5.

## 5 Configuration

The application reads its configuration from `app/.env`.

| Key                       | Required | Description                                                                                              |
| ------------------------- | -------- | -------------------------------------------------------------------------------------------------------- |
| `MONGODB_URI`             | Yes      | The MongoDB connection string.                                                                           |
| `BASE_URL`                | Yes      | The public URL of the application. The application uses it in email links and in the Origin check.       |
| `SESSION_PASSWORD`        | Yes      | A random string of 32 characters or more. Make one with `openssl rand -base64 48`.                       |
| `PORT`                    | No       | The HTTP port. Default: 3000.                                                                            |
| `PYTHON_BIN`              | No       | The Python interpreter. Set it to `app/.venv/bin/python` after step 4 of the installation.               |
| `CERTSPOTTER_API_KEY`     | No       | A Cert Spotter API key. Without a key, the application uses crt.sh.                                      |
| `WATCH_INTERVAL_HOURS`    | No       | The number of hours between two watch cycles of one domain. Default: 6.                                  |
| `WATCH_CONCURRENCY`       | No       | The number of domains that the scheduler watches at the same time. Default: 3.                           |
| `MAX_DOMAINS_PER_ACCOUNT` | No       | The maximum number of domains for one account. Default: 5.                                               |
| `TRUST_PROXY`             | No       | Set it to `loopback` when nginx runs on the same host. Then the rate limits see the real client address. |
| `SMTP_URL`                | No       | The SMTP server for emails. Without it, the application writes each email to the log.                    |

CAUTION: Do not add `app/.env` to git. It contains secrets.

## 6 Start the application

1. Make sure that MongoDB runs. Example:

   ```bash
   docker run -d --name tw-mongo -p 27017:27017 mongo:7
   ```

2. Start the application from the root directory of the repository:

   ```bash
   npm -w app start
   ```

3. Open http://localhost:3000 in a browser.
4. Make an account. The application writes the verification link to the log. Open
   the link in the browser.
5. Add a domain and click **Scan now**. The first watch cycle fills the domain page.

NOTE: If another program uses port 3000, set `PORT=3100` and
`BASE_URL=http://localhost:3100` in `app/.env`.

## 7 Tests and checks

Run these commands from the root directory of the repository. Each command must
complete without an error before you commit.

```bash
npm run lint
```

```bash
npm run typecheck
```

```bash
npm test
```

```bash
npm audit --audit-level=high
```

NOTE: The first test run downloads a MongoDB binary of approximately 150 MB into
`~/.cache/mongodb-binaries`.

## 8 Status

Plans 1 and 2 of 3 are complete. The application has accounts, domains, the watch
cycle with all signals, and leak mentions.

Plan 3 is the next step. It adds alerts by email, Slack and Microsoft Teams, a user
interface review, deployment files, and the removal of `backend/` and `frontend/`.

## 9 Security

Read `SECURITY.md` before you deploy the application. It lists the credentials of
the old version 1 that you must rotate. Send security reports by email. Do not open a
public issue for a vulnerability.
