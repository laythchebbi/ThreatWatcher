require("./helpers/env");
const { test, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const { withDb } = require("./helpers/db");
const { startApp } = require("./helpers/http");
const mailer = require("../src/lib/mailer");
const { rateLimit } = require("../src/middleware/rate-limit");

const PW = "correct horse battery";
const json = { headers: { accept: "application/json" } };

beforeEach(() => {
  mailer._reset();
  rateLimit._reset();
});

async function setup(t) {
  const models = await withDb(t);
  const app = await startApp(t);
  await app.post("/signup", { email: "w@example.com", password: PW });
  await models.User.updateOne({ email: "w@example.com" }, { emailVerifiedAt: new Date() });
  const user = await models.User.findOne({ email: "w@example.com" });
  const domain = await models.Domain.create({
    userId: user._id,
    name: "acme-corp.com",
    terms: ["acme bank"],
    posture: {
      checkedAt: new Date(),
      grade: "D",
      findings: ["Move DMARC to p=reject with a rua reporting address."],
      spf: { present: true, policy: "strict", lookups: 1 },
      dmarc: { present: true, policy: "none" },
      dkim: { selectorsFound: [] },
    },
  });
  const sighting = await models.Sighting.create({
    userId: user._id,
    domainId: domain._id,
    lookalike: "acme-corp-login.com",
    severity: "critical",
    similarity: 0.73,
    dns: { resolves: true, a: ["1.1.1.1"], mx: [], ns: ["ns1.example.net"] },
    rdap: { registeredAt: new Date("2026-10-21T00:00:00Z"), registrar: "NameCheap, Inc.", ns: [] },
    cert: {
      firstIssuedAt: new Date("2026-10-30T00:00:00Z"),
      issuer: "Let's Encrypt",
      notBefore: new Date("2026-10-30T00:00:00Z"),
      tbs: "t",
    },
    http: { status: 200, title: "Sign in <script>", hasPasswordForm: true, brandTermFound: true },
  });
  const mention = await models.Mention.create({
    userId: user._id,
    domainId: domain._id,
    source: "darkweb",
    sourceRef: "darkweb:http://s.onion/a",
    excerpt: "Selling acme bank access <b>bold</b>",
    excerptHash: "h",
    matchedTerms: ["acme bank"],
    severity: "high",
  });
  return { ...models, ...app, user, domain, sighting, mention };
}

test("dark-web page lists open mentions and shows the empty-sources notice", async (t) => {
  const { fetchWithCookies } = await setup(t);
  const res = await fetchWithCookies("/dark-web");
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /Selling acme bank access &lt;b&gt;bold&lt;\/b&gt;/, "excerpt escaped");
  assert.match(html, /No dark-web sources are connected yet/);
  assert.doesNotMatch(html, /seed:sources/, "no operator commands on a customer page");
});

test("dark-web page shows source count and last crawl when sources exist", async (t) => {
  const { fetchWithCookies, DarkwebSource } = await setup(t);
  await DarkwebSource.create({
    url: "http://s.onion",
    lastCrawledAt: new Date("2026-10-31T01:02:00Z"),
  });
  const html = await (await fetchWithCookies("/dark-web")).text();
  assert.match(html, /1 source/);
  assert.match(html, /2026-10-31 01:02/);
});

test("keyword search escapes regex and returns matching pages", async (t) => {
  const { fetchWithCookies, DarkwebPage } = await setup(t);
  await DarkwebPage.create({
    sourceUrl: "http://s.onion",
    pageUrl: "http://s.onion/x",
    title: "ACME (dump)",
    body: "acme-corp.com creds here",
    crawledAt: new Date(),
  });
  const html = await (await fetchWithCookies("/dark-web?q=ACME+(dump)")).text();
  assert.match(html, /ACME \(dump\)/);
  const none = await (await fetchWithCookies("/dark-web?q=.*")).text();
  assert.ok(!/creds here/.test(none), "a regex query is treated literally");
  assert.equal(
    (await fetchWithCookies("/dark-web?q=a")).status,
    200,
    "too-short query is ignored, not an error"
  );
});

test("mention dismiss stores severity and reopen clears; other user's mention is 404", async (t) => {
  const { post, Mention, User, Domain, domain, mention } = await setup(t);
  const dismissed = await post(`/domains/${domain._id}/mentions/${mention._id}/dismiss`, {}, json);
  assert.deepEqual(await dismissed.json(), { ok: true, state: "dismissed" });
  const m = await Mention.findById(mention._id);
  assert.equal(m.dismissedAtSeverity, "high");
  const reopened = await post(`/domains/${domain._id}/mentions/${mention._id}/reopen`, {}, json);
  assert.deepEqual(await reopened.json(), { ok: true, state: "open" });
  const other = await User.create({ email: "o@example.com", passwordHash: "x" });
  const theirs = await Domain.create({ userId: other._id, name: "other.example" });
  assert.equal(
    (await post(`/domains/${theirs._id}/mentions/${mention._id}/dismiss`, {}, json)).status,
    404
  );
});

test("domain page shows posture grade, registrar, certificate and page columns, escaped", async (t) => {
  const { fetchWithCookies, domain } = await setup(t);
  const html = await (await fetchWithCookies(`/domains/${domain._id}`)).text();
  assert.match(html, /Email posture[\s\S]*?\bD\b/);
  assert.match(html, /Move DMARC to p=reject/);
  assert.match(html, /NameCheap, Inc\./);
  assert.match(html, /Let's Encrypt|Let&#39;s Encrypt/);
  assert.match(html, /Sign in &lt;script&gt;/, "page title escaped");
  assert.match(html, /Selling acme bank access/);
});
