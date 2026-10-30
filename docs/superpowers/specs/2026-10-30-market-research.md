# Market and technique research — 2026-10-30

Three research agents looked at (1) commercial brand-protection products,
(2) open-source tools and free data sources, (3) leak monitoring and alert
delivery. Everything below cites the page a claim came from; items the agents
could not read directly are marked _(unverified)_. This document feeds the v2
design (`2026-10-30-threat-watcher-v2-design.md`); the "Decision" lines say
what was folded in there and what waits.

## 1. What the market looks like

| Product                                                                                   | Audience             | Signals                                                                                 | Alerting                            | Response                                           | Pricing                                                              |
| ----------------------------------------------------------------------------------------- | -------------------- | --------------------------------------------------------------------------------------- | ----------------------------------- | -------------------------------------------------- | -------------------------------------------------------------------- |
| [Red Sift Brand Trust](https://redsift.com/products/brand-trust)                          | Security teams, MSPs | 150M domains/day, visual + linguistic match, logo abuse, WHOIS/SSL/MX, DNS history      | Slack, SIEM, API                    | Takedown packages with bundled evidence            | Not public; trial 2 domains                                          |
| [ZeroFox](https://zerofox.com/demo/domain-protection)                                     | Enterprise SOC       | Registrations, parked→malicious re-checks, social, dark web                             | Rule engine, API                    | 3-step takedown wizard, status dashboard           | AWS listing $33,500/yr for 10 domains + 250 takedowns _(unverified)_ |
| [Bolster / CheckPhish](https://checkphish.bolster.ai/)                                    | SMB to enterprise    | Registrations, MX, live URL scanning, computer vision                                   | API                                 | AI takedown; free DIY tier                         | Free 1 domain; ~$50/domain/mo and up _(unverified)_                  |
| [Doppel](https://www.doppel.com/)                                                         | Brand/exec teams     | Domains, social, ads, dark web, correlated "Threat Graph"                               | Integrations                        | Agentic takedown, median <10 h                     | Not public                                                           |
| [Netcraft](https://www.netcraft.com/)                                                     | Brands, banks        | Proxy crawl, 100+ attack types, cloaking evasion, pre-live "verified attack indicators" | Provider reporting                  | Disrupt in 5 min, median takedown 33 min           | Not public                                                           |
| [Allure Security](https://www.alluresecurity.com/)                                        | Banks, retail        | 1.5B URLs/day "during setup", app stores, dark web, ads, <1 % FP claim                  | API, email, Slack, Teams            | 24/7 SOC, decoy credentials, evidence with custody | Not public                                                           |
| [DomainTools Iris Detect](https://docs.domaintools.com/iris/detect/concepts/)             | SOC, hunters         | Passive DNS discovery, risk score, infra-change tracking (IP, NS, registrar)            | API, SIEM                           | Escalate to Google Web Risk                        | Not public                                                           |
| [Recorded Future Brand Intel](https://www.recordedfuture.com/products/brand-intelligence) | T&S, SOC             | Typosquats, DNS + cert, logo, leaked creds, dark-web chatter, screenshots on alerts     | Playbooks, SIEM/SOAR                | Takedown from platform                             | Not public                                                           |
| [Phish.Report](https://phish.report/)                                                     | Banks, non-experts   | Open-source IOK rules on page HTML, real-Chrome screenshots, abuse-contact DB           | Alerts "within minutes" of creation | Guided takedown, case timeline                     | $500/mo unlimited takedowns                                          |
| [DNSArchive Brand Protection](https://dnsarchive.net/brand-protection)                    | Indie/SMB            | Keyword vs newly observed domains + 509M archive, phishing-kit hosts, NS, fast-flux     | Slack/email/JSON webhook per brand  | None                                               | From $20/mo self-serve                                               |
| [PhishFence](https://www.producthunt.com/products/phishfence)                             | Indie/SMB            | Typo/homoglyph/TLD, DMARC/SPF/DKIM                                                      | Screenshot + pre-filled takedown    | DIY                                                | Free 1 domain                                                        |
| [Axur](https://help.axur.com/en/articles/11566976-smart-monitoring-of-similar-domains)    | Enterprise           | TLD/homoglyph by default, typo/combo opt-in, MX filter, 7-day watch on inactive         | Tickets, rule editor with preview   | Auto-quarantine                                    | Not public                                                           |
| [EasyDMARC lookalike checker](https://easydmarc.com/tools/lookalike-domain-checker)       | SMB                  | Typo/homoglyph/combo/TLD; Active/Parked/Unregistered counts; copied-text diff           | Daily scan, email                   | Guidance                                           | Free checker                                                         |

**Where small products win** ([summary from the scan](https://www.producthunt.com/products/phishfence)):
public flat pricing, self-serve sign-up with no DNS or agent changes, Slack and
email per brand instead of SIEM connectors, and speed claims measured in
minutes from registration. Enterprise suites hide prices, meter takedowns and
bundle social, app-store and ad monitoring most SMBs do not need.

**Decision:** keep the one-person self-serve shape; make the alert itself the
product (facts, evidence, abuse contact, one-click report) rather than the
dashboard; default to low-false-positive signals and let the customer opt into
noisier permutations.

## 2. Signals the v2 design did not have

| Signal                                                       | Why                                                                                     | Source and cost                                                                                                                                                                                                         | Decision                                                                                               |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Local permutations instead of dnstwister.report              | Same algorithm, no third-party quota, add brand keywords and UTS#39 homoglyph skeletons | [dnstwist](https://github.com/elceef/dnstwist) lib in the Python worker, release 2025-01-30; dnstwister.report's Splunk add-on is "Not Supported" since 2024                                                            | **v2**: run dnstwist in the worker; dnstwister.report only as fallback                                 |
| Combosquats (`brand-login.com`)                              | Most common 2026 pattern; permutation engines miss it                                   | Generated locally                                                                                                                                                                                                       | **v2** (already added after design review)                                                             |
| MX record on a lookalike                                     | Means it can send or receive phishing mail; Axur uses it as the main noise filter       | Plain DNS, free                                                                                                                                                                                                         | **v2**: `dns.mx[]` on the sighting; `mx_live` bumps severity                                           |
| RDAP: registration date, registrar, nameservers              | Age-gating (attackers' domains are young), defensive-registration detection, evidence   | `https://rdap.org/domain/{d}`, free, no key; WHOIS port 43 sunset 2025-01-28 ([ICANN](https://www.icann.org/en/blogs/details/icann-board-approves-rdap-amendments-04-05-2023-en))                                       | **v2**: on first sighting and in alerts                                                                |
| Newly registered domain feeds                                | Catches the domain the day it is registered, before DNS or a cert                       | [whoisds](https://www.whoisds.com/newly-registered-domains) free daily list capped at 70 000 names; [ICANN CZDS](https://czds.icann.org/home) full zone files, free with per-TLD approval                               | **Later**: whoisds diff first; CZDS once approved                                                      |
| Streaming certificate transparency instead of polling crt.sh | Minutes after issuance; crt.sh is pull-only, 60 req/min, frequent 50x                   | Self-hosted [certstream-server-go](https://github.com/d-Rickyy-b/certstream-server-go) (v1.10.1, 2026-09); [Cert Spotter search API](https://sslmate.com/help/reference/ct_search_api_v1) free key with `after=` cursor | **v2**: Cert Spotter search API with cursor as primary, crt.sh backfill; **Later**: self-hosted stream |
| Cloned-page fingerprint beyond text                          | Kits obfuscate HTML; DOM fuzzy hash, screenshot pHash, favicon hash cluster per kit     | TLSH/ssdeep of rendered DOM ([Obsidian](https://www.obsidiansecurity.com/blog/detecting-aitm-phishing-sites-with-fuzzy-hashing)), `sharp-phash`, favicon mmh3 ([SANS](https://isc.sans.edu/diary.html?date=2021-04-19)) | **v2**: password-form + brand term rule (cheap); **Later**: pHash + favicon, needs a browser           |
| Known-phishing feeds                                         | Confirms a live page with near-zero FP                                                  | [Phish.Report IOK](https://phish.report/IOK) Sigma rules, open source; urlscan.io free key 1 000 searches/day ([pricing](https://urlscan.io/pricing/))                                                                  | **Later**: IOK rules on fetched pages; urlscan search on alert                                         |
| Customer's own DMARC/SPF/DKIM                                | Exact-domain spoofing, which lookalike watching never sees; onboarding hook             | DNS TXT, free                                                                                                                                                                                                           | **v2**: grade on the domain page, weekly re-check                                                      |
| Parked / CDN / popular-domain suppression                    | Parked lookalikes are mostly noise; shared-hosting IPs are not evidence                 | [MISP warninglists](https://github.com/MISP/misp-warninglists) (CC0: parking NS, CDN ranges, Tranco top-1M)                                                                                                             | **v2**: parked = watch, not alert                                                                      |
| Infrastructure-change tracking                               | "Parked domain wakes up" is the moment customers pay for                                | Own re-resolution (IP, NS, MX)                                                                                                                                                                                          | **v2**: `infra_changed` event                                                                          |
| Browser blocklist escalation                                 | Protects users before takedown                                                          | Google Web Risk Submission API (paid; Lookup free to 100k/mo)                                                                                                                                                           | **Later**                                                                                              |

**Sources to avoid in a paid SaaS** ([terms](https://openphish.com/terms.html),
[Safe Browsing terms](https://developers.google.com/safe-browsing/terms),
[VirusTotal](https://docs.virustotal.com/reference/public-vs-premium-api)):
OpenPhish community feed, Google Safe Browsing API and the VirusTotal public API
all forbid commercial use. URLhaus needs an Auth-Key since 2025-06-30.
PhishTank registration is reported closed _(unverified)_. phishing_catcher
(x0rz) is dead since 2020; Spoofguard does not exist as a tool; Google's CT
search endpoint is broken. Passive-DNS providers have no self-serve free tier.

## 3. Leak monitoring

| Source                                                               | Detects                                                          | Cost                                                                                                                                                | Legal                                                                 | Decision                                                                                   |
| -------------------------------------------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| [Have I Been Pwned domain search](https://haveibeenpwned.com/API/v3) | Breached addresses on the customer's domain, stealer logs on Pro | Free for domains with ≤10 breached addresses; Core from $4.39/mo; Pro $379/mo for stealer logs ([pricing](https://haveibeenpwned.com/Subscription)) | Domain must be verified (DNS TXT); CC BY attribution; real User-Agent | **v2**: customer pastes their own HIBP key; we poll `/latestBreach` then `/breachedDomain` |
| [ransomware.live](https://www.ransomware.live/api)                   | Victim posts on ransomware leak sites, hours after posting       | Free PRO key                                                                                                                                        | Commercial use needs written approval                                 | **Later**, after approval                                                                  |
| [Hudson Rock Cavalier](https://docs.hudsonrock.com/docs)             | Infostealer infections by domain                                 | Free web search; API pricing not public; v2→v3 migration _(unverified)_                                                                             | Free tools redact                                                     | **Later**                                                                                  |
| GitHub code search                                                   | Public repos containing `@customer.com` plus secrets             | Free with a token, 10 req/min ([docs](https://docs.github.com/en/rest/search/search?apiVersion=2022-11-28))                                         | Verify with TruffleHog to cut noise                                   | **Later**                                                                                  |
| [LeakCheck public API](https://docs.leakcheck.io/overview)           | Which breaches contain an email, no passwords                    | Free, 1 req/s, attribution link required                                                                                                            | Fine                                                                  | **Later**                                                                                  |
| Pastebin scraping API                                                | New pastes                                                       | PRO + whitelisted IP, 1 req/s                                                                                                                       | Only the three scrape endpoints                                       | **No** (low yield)                                                                         |
| Telegram channels                                                    | Leak channels                                                    | Free MTProto                                                                                                                                        | Feb 2026 ToS bans scraping; accounts get observed/banned              | **No**                                                                                     |
| Dehashed, SpyCloud, Flare, Intelligence X, KELA, DarkOwl             | Deep breach data                                                 | Paid: $30/mo to five figures; Intelligence X API €7 000/yr                                                                                          | Plaintext passwords are a liability to store                          | **No** for a self-serve product                                                            |

## 4. Alert delivery facts that change the design

- **Microsoft Teams:** Office 365 connector webhooks were switched off in
  May 2026 ([Microsoft](https://devblogs.microsoft.com/microsoft365dev/retirement-of-office-365-connectors-within-microsoft-teams/)).
  Only Workflows (Power Automate) webhooks work. Payload is an Adaptive Card:
  `{"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","contentUrl":null,"content":{...}}]}`,
  28 KB max, 4 req/s. Do not validate the hostname strictly; the URL is on a
  Power Automate domain and changes ([Learn](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)).
- **Slack:** one webhook = one channel; 50 blocks, section text ≤3 000 chars,
  1 message/s/channel, always send a top-level `text` fallback
  ([docs](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks)).
- **Email:** Gmail requires SPF and DKIM for everyone, DMARC plus one-click
  unsubscribe above 5 000/day; add `List-Unsubscribe` headers anyway
  ([Google](https://support.google.com/a/answer/81126)). Critical alerts go
  immediately; medium and low go in a daily digest at the start of the
  customer's business day; skip empty digests; counts by severity in the
  subject ([Knock](https://knock.app/template-library/workflows/alert-digest)).
- **Grouping:** one notification per domain per 5 minutes; re-notify an open
  threat at most every 4 hours; never re-alert a dismissed threat unless the
  evidence changes (PagerDuty, Grafana and Datadog guidance).

## 5. Features worth adding, ranked

| #   | Feature                                                                                                             | Why customers pay                                               | Size       | When                                                     |
| --- | ------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | ---------- | -------------------------------------------------------- |
| 1   | Threat lifecycle with change re-alerts: new → watched → changed → live → escalated / ignored                        | Being told when a parked domain wakes up is the product         | medium     | v2 (events model already does this; add `infra_changed`) |
| 2   | Local dnstwist + combosquats + MX flag                                                                              | Earlier, wider, fewer false positives, no quota                 | small      | v2                                                       |
| 3   | Cert Spotter cursor polling, crt.sh backfill, per-label cache                                                       | Minutes instead of hours, no 50x flakiness                      | small      | v2                                                       |
| 4   | Alert content = evidence: RDAP facts, resolved IP and ASN, cert issuer, page title, screenshot later, abuse contact | What users cannot assemble at 2 a.m.                            | medium     | v2 facts, screenshot later                               |
| 5   | Own-domain DMARC/SPF/DKIM grade on the domain page                                                                  | Free to compute, converts trials, catches exact-domain spoofing | small      | v2                                                       |
| 6   | Parked / CDN suppression with MISP lists; parked = watch                                                            | Cuts the noisy majority                                         | small      | v2                                                       |
| 7   | Daily digest for medium/low, immediate for high/critical, per-channel                                               | Alert fatigue is why customers churn                            | small      | v2                                                       |
| 8   | Teams via Workflows Adaptive Card; Slack Block Kit with fallback text                                               | The old Teams format is dead                                    | small      | v2                                                       |
| 9   | HIBP domain-breach panel with the customer's own key                                                                | Credible "are we in a breach" answer                            | small      | v2                                                       |
| 10  | Takedown kit: pre-filled abuse email to the hosting ASN and registrar, one click                                    | The step after detection; Phish.Report charges $500/mo for it   | medium     | later                                                    |
| 11  | Newly registered domain diff (whoisds, then CZDS)                                                                   | Earliest signal of all                                          | medium     | later                                                    |
| 12  | Screenshot + pHash + favicon hash with a headless browser; IOK rule match                                           | Catches clones that rewrite text; names the kit                 | large      | later                                                    |
| 13  | Ransomware leak-site mentions (ransomware.live), infostealer check (Hudson Rock), GitHub secret search              | Highest-severity leak signals                                   | small each | later, after ToS approval                                |
| 14  | Google Web Risk submission on a confirmed phish                                                                     | Visibly protects end users                                      | small      | later                                                    |
| 15  | Self-hosted CT stream (certstream-server-go)                                                                        | Seconds instead of minutes                                      | medium     | later                                                    |

## 6. UI ideas worth copying

- Domain groups as tabs: New / Watched / Changed / Inactive / Ignored, with a
  "changed in the last N days" filter (Iris Detect).
- A case timeline per threat: registered → DNS → cert → live → reported
  (Phish.Report).
- Summary counters Active / Parked / Unregistered and a side-by-side copied
  text diff (EasyDMARC).
- Rule editor that previews "average daily results" before saving (Axur).
- Per-brand infrastructure tab (IPs, NS, MX) with change alerts (DNSArchive).
- Alert message = screenshot + facts + pre-filled report (PhishFence).
- Evidence log with timestamps on every action (Allure).

Not checked: no endpoint was exercised from this repo; pricing for Fortra,
Bolster, Memcyco and DNS Spy came from secondary listings. Risk: HIBP and
Hudson Rock tiers change often; re-check before committing to one.
