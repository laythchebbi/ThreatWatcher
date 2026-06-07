// In-memory demo dataset. Used ONLY when DEMO_MODE is on. Mutated by the
// demo scan endpoint so new scans show up in the dashboard/reports during a
// session. Nothing here touches MongoDB.

const DAY = 86_400_000;
const now = Date.now();
const iso = (msAgo) => new Date(now - msAgo).toISOString();

const demoUser = {
  _id: "demo000000000000000000a1",
  workosUserId: "demo-user",
  email: "demo@threatwatcher.local",
  displayName: "Demo Analyst",
  role: "admin",
  monitoredDomains: ["acme-corp.com", "acmebank.io", "acme-pay.com"],
  lastLoginAt: iso(0),
  createdAt: iso(30 * DAY),
};

function mkReport(id, domain, score, lookalikes, darkWebHits, scored, msAgo) {
  return {
    _id: id,
    domain,
    secureScore: score,
    confidence: 0.85,
    findings: {
      lookalikes,
      maliciousUrls: scored.filter((s) => s.mlLabel === 1).length,
      contentMatches: 0,
      darkWebHits,
      dataLeaks: 0,
    },
    reportContent: { scored },
    createdAt: iso(msAgo),
  };
}

const reports = [
  mkReport(
    "rep_acmecorp01",
    "acme-corp.com",
    0.41,
    3,
    2,
    [
      {
        domain: "acme-c0rp.com",
        similarity: 0.86,
        punycode: false,
        substring: true,
        mlLabel: 1,
        mlScore: 0.86,
      },
      {
        domain: "acme-corp-login.com",
        similarity: 0.72,
        punycode: false,
        substring: true,
        mlLabel: 1,
        mlScore: 0.72,
      },
      {
        domain: "acme-corp.co",
        similarity: 0.69,
        punycode: false,
        substring: true,
        mlLabel: 0,
        mlScore: 0.41,
      },
    ],
    2 * DAY
  ),
  mkReport(
    "rep_acmebank01",
    "acmebank.io",
    0.28,
    4,
    5,
    [
      {
        domain: "xn--acmebank-9bc.io",
        similarity: 0.91,
        punycode: true,
        substring: false,
        mlLabel: 1,
        mlScore: 0.91,
      },
      {
        domain: "acmebank-secure.io",
        similarity: 0.78,
        punycode: false,
        substring: true,
        mlLabel: 1,
        mlScore: 0.78,
      },
      {
        domain: "acmebank.co",
        similarity: 0.74,
        punycode: false,
        substring: true,
        mlLabel: 1,
        mlScore: 0.6,
      },
      {
        domain: "acmeb4nk.io",
        similarity: 0.7,
        punycode: false,
        substring: false,
        mlLabel: 0,
        mlScore: 0.35,
      },
    ],
    6 * 3600_000
  ),
  mkReport(
    "rep_acmepay001",
    "acme-pay.com",
    0.83,
    1,
    0,
    [
      {
        domain: "acme-pay.net",
        similarity: 0.66,
        punycode: false,
        substring: true,
        mlLabel: 0,
        mlScore: 0.22,
      },
    ],
    5 * DAY
  ),
  mkReport("rep_globex0001", "globex.com", 0.95, 0, 0, [], 8 * DAY),
  mkReport(
    "rep_initech001",
    "initech.io",
    0.55,
    2,
    1,
    [
      {
        domain: "1nitech.io",
        similarity: 0.82,
        punycode: false,
        substring: false,
        mlLabel: 1,
        mlScore: 0.82,
      },
      {
        domain: "initech-hr.io",
        similarity: 0.68,
        punycode: false,
        substring: true,
        mlLabel: 0,
        mlScore: 0.3,
      },
    ],
    11 * DAY
  ),
  mkReport(
    "rep_umbrella01",
    "umbrella-health.com",
    0.36,
    2,
    3,
    [
      {
        domain: "umbrella-health-portal.com",
        similarity: 0.8,
        punycode: false,
        substring: true,
        mlLabel: 1,
        mlScore: 0.8,
      },
      {
        domain: "umbre11a-health.com",
        similarity: 0.77,
        punycode: false,
        substring: false,
        mlLabel: 1,
        mlScore: 0.77,
      },
    ],
    14 * DAY
  ),
];

const leaks = {
  telegram: [
    {
      _id: "tg1",
      channel: "@combolists_daily",
      text: "Fresh combo: acme-corp.com employee creds — 1,204 lines (email:pass)",
      postedAt: iso(1 * DAY),
    },
    {
      _id: "tg2",
      channel: "@breach_alerts",
      text: "acmebank.io customer DB sample dropped, includes acmebank.io webmail logins",
      postedAt: iso(3 * DAY),
    },
  ],
  twitter: [
    {
      _id: "tw1",
      handle: "@h4ckwatch",
      text: "Seeing phishing kits hosted on acme-corp-login.com targeting acme-corp.com SSO",
      postedAt: iso(2 * DAY),
    },
  ],
  forum: [
    {
      _id: "fr1",
      forum: "BreachForums",
      threadUrl: "http://forum.onion/t/12345",
      title: "Selling acmebank.io access",
      body: "VPN + webmail access to acmebank.io, DM for price",
      postedAt: iso(4 * DAY),
    },
    {
      _id: "fr2",
      forum: "XSS.is",
      threadUrl: "http://forum.onion/t/67890",
      title: "umbrella-health.com patient data",
      body: "Database from umbrella-health.com, 50k records",
      postedAt: iso(9 * DAY),
    },
  ],
  darkweb: [
    {
      _id: "dw1",
      sourceUrl: "http://leak.onion",
      pageUrl: "http://leak.onion/acme",
      title: "ACME dump index",
      body: "Index of leaked acme-corp.com and acme-pay.com archives",
      crawledAt: iso(1 * DAY),
    },
  ],
};

const invitations = [
  { id: "inv_pending01", email: "new.analyst@acme-corp.com", role: "analyst", state: "pending" },
  { id: "inv_pending02", email: "soc.lead@acme-corp.com", role: "admin", state: "pending" },
];

module.exports = { demoUser, reports, leaks, invitations };
