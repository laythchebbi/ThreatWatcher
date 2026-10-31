// Seed a local test account with two watched domains, sightings in every state,
// events, leak mentions and crawled pages, so every page has something to show.
// Re-running replaces the demo account's data. Refuses to run in production.
//
//   npm -w app run seed:demo
//
// Sign in with the test account below (local development only).
const crypto = require("node:crypto");
const { domainToASCII } = require("node:url");
const { env } = require("../src/config");
const db = require("../src/db");
const models = require("../src/models");
const { hashPassword } = require("../src/services/password");
const { eventSeverity } = require("../src/services/watch/severity");
const { matchPage, mentionSeverity } = require("../src/services/watch/leaks");
const { brandTermsFor } = require("../src/services/watch/cycle");

const DEMO_EMAIL = "demo@threatwatcher.test";
const DEMO_PASSWORD = "demo-password-123";

const { User, Domain, Sighting, Event, Mention, DarkwebPage, DarkwebSource } = models;
const now = Date.now();
const ago = (h) => new Date(now - h * 3600_000);
// Baseline three weeks back, so baseline rows land in the Watched tab, not New (< 1 week).
const BASELINE_H = 21 * 24;
const hash = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");

/**
 * One lookalike: `s` is the sighting body, `events` are [kind, hoursAgo, extraPayload?].
 * Severity comes from the real ladder so a later real scan agrees with the seed.
 */
const ACME = {
  name: "acme-corp.com",
  terms: ["acme", "acmepay"],
  posture: {
    checkedAt: ago(20),
    spf: { present: true, policy: "~all", lookups: 6 },
    dmarc: { present: true, policy: "none", rua: "" },
    dkim: { selectorsFound: [] },
    grade: "D",
    findings: [
      "DMARC is p=none: spoofed mail from acme-corp.com is delivered",
      "SPF ends in ~all (softfail), not -all",
      "No DKIM selector found among the common names",
    ],
  },
  lookalikes: [
    {
      s: {
        lookalike: "acme-corp-login.com",
        substring: true,
        similarity: 0.86,
        dns: {
          resolves: true,
          a: ["203.0.113.24"],
          mx: ["mx1.acme-corp-login.com"],
          ns: ["ns1.njalla.no"],
        },
        rdap: {
          registeredAt: ago(52),
          registrar: "Njalla",
          ns: ["ns1.njalla.no"],
          fetchedAt: ago(5),
        },
        cert: {
          firstIssuedAt: ago(30),
          issuer: "Let's Encrypt R11",
          notBefore: ago(30),
          lastSeenAt: ago(5),
        },
        http: {
          status: 200,
          title: "Acme Corp | Sign in to your account",
          finalHost: "acme-corp-login.com",
          hasPasswordForm: true,
          brandTermFound: true,
          similarity: 0.72,
          fetchedAt: ago(5),
        },
      },
      events: [
        ["new_lookalike", 50],
        ["dns_live", 50],
        ["mx_live", 50],
        ["cert_issued", 30],
        ["page_live", 6],
        ["page_mimics_login", 5],
      ],
    },
    {
      s: {
        lookalike: "acrne-corp.com",
        similarity: 0.83,
        dns: { resolves: true, a: ["198.51.100.7"], mx: [], ns: ["dns1.registrar-servers.com"] },
        rdap: {
          registeredAt: ago(96),
          registrar: "NameCheap, Inc.",
          ns: ["dns1.registrar-servers.com"],
          fetchedAt: ago(5),
        },
        cert: {
          firstIssuedAt: ago(18),
          issuer: "Let's Encrypt E6",
          notBefore: ago(18),
          lastSeenAt: ago(5),
        },
        http: { error: "connect ECONNREFUSED", fetchedAt: ago(5) },
      },
      events: [
        ["new_lookalike", 70],
        ["dns_live", 70],
        ["cert_issued", 18],
      ],
    },
    {
      s: {
        lookalike: domainToASCII("аcme-corp.com"), // first letter is Cyrillic
        punycode: true,
        similarity: 0.9,
        dns: { resolves: true, a: ["192.0.2.80"], mx: [], ns: ["ns1.sedoparking.com"] },
        infra: { parked: true, cdn: false },
        rdap: { registeredAt: ago(400), registrar: "Sedo", fetchedAt: ago(5) },
        http: {
          status: 200,
          title: "acme-corp.com is for sale",
          finalHost: domainToASCII("аcme-corp.com"),
          fetchedAt: ago(5),
        },
      },
      events: [
        ["new_lookalike", 40],
        ["dns_live", 40],
      ],
    },
    {
      s: {
        lookalike: "acmecorp-support.com",
        substring: true,
        similarity: 0.79,
        dns: {
          resolves: true,
          a: ["203.0.113.91"],
          mx: ["mail.acmecorp-support.com"],
          ns: ["ns1.digitalocean.com"],
        },
        rdap: { registeredAt: ago(200), registrar: "Tucows Domains Inc.", fetchedAt: ago(5) },
      },
      events: [
        [
          "infra_changed",
          9,
          { changed: ["a"], before: { a: ["203.0.113.12"] }, after: { a: ["203.0.113.91"] } },
        ],
      ],
      baseline: true,
    },
    {
      s: {
        lookalike: "acme-corp.net",
        similarity: 0.92,
        dns: {
          resolves: true,
          a: ["192.0.2.10"],
          mx: ["mx.acme-corp.com"],
          ns: ["ns1.acme-corp.com"],
        },
        rdap: {
          registeredAt: ago(9000),
          registrar: "MarkMonitor Inc.",
          defensive: true,
          fetchedAt: ago(5),
        },
        state: "ignored",
      },
      events: [],
      baseline: true,
    },
    {
      s: {
        lookalike: "acme-corpp.com",
        similarity: 0.95,
        state: "dismissed",
        dismissedAtSeverity: "low",
      },
      events: [],
      baseline: true,
    },
    {
      s: {
        lookalike: "acme-c0rp.com",
        similarity: 0.9,
        inactive: true,
        dnsMisses: 2,
        dns: { resolves: false, a: [], mx: [], ns: [] },
      },
      events: [["gone", 3]],
      baseline: true,
    },
  ],
  quiet: [
    "accme-corp.com",
    "acme-crop.com",
    "acmecorp.com",
    "acme-corp.co",
    "acme-corp.io",
    "acme-corp.org",
    "acme-cprp.com",
    "acmw-corp.com",
    "acme--corp.com",
    "acme-corp-app.com",
    "myacme-corp.com",
    "acme-corp.shop",
  ],
  pages: [
    {
      pageUrl: "http://leakforumexample.onion/t/88412",
      title: "[SELL] corporate VPN + mail access, EU logistics firms",
      body: "Fresh combo, checked 2 days ago. Includes j.doe@acme-corp.com and 41 more addresses on the same domain, OWA + Fortinet VPN. Escrow only.",
      crawledAt: ago(14),
    },
    {
      pageUrl: "http://pasteexample.onion/p/7c1e",
      title: "dump part 3",
      body: "...billing export from the AcmePay merchant portal, 2.3k rows, card BINs masked. Sample on request...",
      crawledAt: ago(28),
    },
    {
      pageUrl: "http://leakforumexample.onion/t/80110",
      title: "Old acme thread",
      body: "Anyone still have the 2019 acme marketing list? Probably useless now.",
      crawledAt: ago(60),
      dismissed: true,
    },
  ],
  hibp: {
    sourceRef: "hibp:ExampleCloudCRM",
    excerpt: "ExampleCloudCRM, 2026-08-14, 14 addresses, data: Email addresses, Names, Passwords",
    severity: "high",
    at: 22,
  },
};

const NORTHWIND = {
  name: "northwind-bank.com",
  terms: ["northwind"],
  posture: {
    checkedAt: ago(20),
    spf: { present: true, policy: "-all", lookups: 4 },
    dmarc: { present: true, policy: "reject", rua: "mailto:dmarc@northwind-bank.com" },
    dkim: { selectorsFound: ["selector1", "google"] },
    grade: "A",
    findings: [],
  },
  lookalikes: [
    {
      s: {
        lookalike: "northwind-bank-secure.com",
        substring: true,
        similarity: 0.81,
        dns: {
          resolves: true,
          a: ["198.51.100.150"],
          mx: ["mx.northwind-bank-secure.com"],
          ns: ["ns1.cloudns.net"],
        },
        rdap: { registeredAt: ago(10), registrar: "Hosting Concepts B.V.", fetchedAt: ago(4) },
        cert: {
          firstIssuedAt: ago(8),
          issuer: "ZeroSSL ECC Domain Secure Site CA",
          notBefore: ago(8),
          lastSeenAt: ago(4),
        },
      },
      events: [
        ["new_lookalike", 9],
        ["dns_live", 9],
        ["mx_live", 9],
        ["cert_issued", 8],
      ],
    },
    {
      s: {
        lookalike: "northwlnd-bank.com",
        similarity: 0.94,
        dns: { resolves: true, a: ["192.0.2.33"], mx: [], ns: ["ns1.parkingcrew.net"] },
        infra: { parked: true, cdn: false },
      },
      events: [
        ["new_lookalike", 30],
        ["dns_live", 30],
      ],
    },
  ],
  quiet: [
    "northwind-bnak.com",
    "nortwind-bank.com",
    "northwind-bank.net",
    "northwindbank.com",
    "northwind-bank.co",
  ],
  pages: [],
  hibp: null,
};

function sightingDoc(user, domain, item, firstSeen) {
  const s = item.s;
  return {
    userId: user._id,
    domainId: domain._id,
    firstSeenAt: firstSeen,
    lastSeenAt: s.inactive ? ago(15) : ago(5),
    baseline: Boolean(item.baseline),
    dns: { resolves: false, a: [], mx: [], ns: [] },
    infra: { parked: false, cdn: false },
    similarity: 0.8,
    state: "open",
    ...s,
  };
}

function worstSeverity(sighting, kinds) {
  const order = ["low", "medium", "high", "critical"];
  let worst = "low";
  for (const k of kinds) {
    let sev = eventSeverity(k, sighting);
    if (
      sighting.infra?.parked &&
      ["dns_live", "mx_live", "cert_issued", "new_lookalike"].includes(k)
    )
      sev = "low";
    if (order.indexOf(sev) > order.indexOf(worst)) worst = sev;
  }
  return worst;
}

async function seedDomain(user, spec) {
  const domain = await Domain.create({
    userId: user._id,
    name: spec.name,
    terms: spec.terms,
    lastWatchedAt: ago(5),
    // Next real scan in 5 h, so the seed is not replaced as soon as the app starts. Use "Scan now" to run one.
    nextWatchAt: new Date(now + 5 * 3600_000),
    posture: spec.posture,
    baselineDoneAt: ago(BASELINE_H),
    ownRdap: {
      registrar: "MarkMonitor Inc.",
      ns: [`ns1.${spec.name}`],
      fetchedAt: ago(BASELINE_H),
    },
  });

  const events = [];
  for (const item of spec.lookalikes) {
    const kinds = item.events.map(([k]) => k);
    const firstSeen = item.baseline
      ? ago(BASELINE_H)
      : ago(Math.max(...item.events.map(([, h]) => h), 1));
    const doc = sightingDoc(user, domain, item, firstSeen);
    doc.severity = kinds.length ? worstSeverity(doc, kinds) : "low";
    const sighting = await Sighting.create(doc);
    for (const [kind, h, extra] of item.events) {
      let severity = eventSeverity(kind, doc);
      if (
        doc.infra?.parked &&
        ["dns_live", "mx_live", "cert_issued", "new_lookalike"].includes(kind)
      )
        severity = "low";
      events.push({
        userId: user._id,
        domainId: domain._id,
        sightingId: sighting._id,
        kind,
        severity,
        at: ago(h),
        payload: { lookalike: doc.lookalike, ...(extra || {}) },
      });
    }
  }
  await Sighting.insertMany(
    spec.quiet.map((name) => ({
      userId: user._id,
      domainId: domain._id,
      lookalike: name,
      firstSeenAt: ago(BASELINE_H),
      lastSeenAt: ago(5),
      baseline: true,
      similarity: 0.85,
      severity: "low",
      state: "open",
    }))
  );

  if (spec.posture.grade === "D" || spec.posture.grade === "F") {
    events.push({
      userId: user._id,
      domainId: domain._id,
      kind: "posture_weak",
      severity: "low",
      at: ago(20),
      payload: { grade: spec.posture.grade, findings: spec.posture.findings },
    });
  }

  const terms = brandTermsFor(domain);
  for (const p of spec.pages) {
    const page = await DarkwebPage.findOneAndUpdate(
      { sourceUrl: "http://leakforumexample.onion/", pageUrl: p.pageUrl },
      { title: p.title, body: p.body, bodyHash: hash(p.body), crawledAt: p.crawledAt },
      { upsert: true, new: true }
    );
    const m = matchPage(page, terms, domain.name);
    if (!m) throw new Error(`seed page ${p.pageUrl} does not match ${domain.name}`);
    const severity = mentionSeverity({
      ...m,
      domainName: domain.name,
      customerTerms: domain.terms,
    });
    const mention = await Mention.create({
      userId: user._id,
      domainId: domain._id,
      source: "darkweb",
      sourceRef: `darkweb:${p.pageUrl}`,
      excerpt: m.excerpt,
      excerptHash: hash(m.excerpt),
      matchedTerms: m.matchedTerms,
      severity,
      firstSeenAt: p.crawledAt,
      lastSeenAt: p.crawledAt,
      state: p.dismissed ? "dismissed" : "open",
      dismissedAtSeverity: p.dismissed ? severity : undefined,
    });
    events.push({
      userId: user._id,
      domainId: domain._id,
      mentionId: mention._id,
      kind: "leak_mention",
      severity,
      at: p.crawledAt,
      payload: {
        source: "darkweb",
        sourceRef: mention.sourceRef,
        matchedTerms: m.matchedTerms,
        excerpt: m.excerpt.slice(0, 240),
      },
    });
  }
  if (spec.hibp) {
    const h = spec.hibp;
    const mention = await Mention.create({
      userId: user._id,
      domainId: domain._id,
      source: "hibp",
      sourceRef: h.sourceRef,
      excerpt: h.excerpt,
      excerptHash: hash(h.excerpt),
      matchedTerms: [domain.name],
      severity: h.severity,
      firstSeenAt: ago(h.at),
      lastSeenAt: ago(h.at),
    });
    events.push({
      userId: user._id,
      domainId: domain._id,
      mentionId: mention._id,
      kind: "leak_mention",
      severity: h.severity,
      at: ago(h.at),
      payload: {
        source: "hibp",
        sourceRef: h.sourceRef,
        matchedTerms: [domain.name],
        excerpt: h.excerpt,
      },
    });
  }

  await Event.insertMany(events);
  return {
    domain: domain.name,
    sightings: spec.lookalikes.length + spec.quiet.length,
    events: events.length,
  };
}

async function main() {
  if (env.NODE_ENV === "production")
    throw new Error("seed:demo refuses to run with NODE_ENV=production");
  await db.connect();

  const old = await User.findOne({ email: DEMO_EMAIL });
  if (old) {
    const q = { userId: old._id };
    await Promise.all([
      Domain.deleteMany(q),
      Sighting.deleteMany(q),
      Event.deleteMany(q),
      Mention.deleteMany(q),
    ]);
    await User.deleteOne({ _id: old._id });
  }
  const user = await User.create({
    email: DEMO_EMAIL,
    passwordHash: await hashPassword(DEMO_PASSWORD),
    emailVerifiedAt: ago(80),
  });

  await DarkwebSource.updateOne(
    { url: "http://leakforumexample.onion/" },
    {
      $set: {
        kind: "forum",
        title: "Example leak forum (seed data)",
        enabled: true,
        lastCrawledAt: ago(1),
        lastStatus: "ok",
      },
    },
    { upsert: true }
  );

  const results = [];
  for (const spec of [ACME, NORTHWIND]) results.push(await seedDomain(user, spec));
  console.table(results);
  console.log(
    `sign in at ${env.BASE_URL}/login as ${DEMO_EMAIL} (password in app/scripts/seed-demo.js)`
  );
  await db.disconnect();
}

main().catch(async (err) => {
  console.error(err.message);
  await db.disconnect().catch(() => {});
  process.exit(1);
});
