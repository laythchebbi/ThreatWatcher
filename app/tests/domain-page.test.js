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
  await app.post("/signup", { email: "p@example.com", password: PW });
  await models.User.updateOne({ email: "p@example.com" }, { emailVerifiedAt: new Date() });
  const user = await models.User.findOne({ email: "p@example.com" });
  const domain = await models.Domain.create({
    userId: user._id,
    name: "acme-corp.com",
    nextWatchAt: new Date(Date.now() + 3600_000),
    baselineDoneAt: new Date(),
  });
  const mk = (over) =>
    models.Sighting.create({
      userId: user._id,
      domainId: domain._id,
      severity: "medium",
      similarity: 0.8,
      dns: { resolves: true, a: ["1.1.1.1"], mx: [], ns: [] },
      ...over,
    });
  const open = await mk({ lookalike: "acme-c0rp.com" });
  const inactive = await mk({
    lookalike: "acme-corp.co",
    inactive: true,
    dns: { resolves: false, a: [], mx: [], ns: [] },
  });
  const ignored = await mk({ lookalike: "acme-corp.net", state: "ignored" });
  await models.Event.create({
    userId: user._id,
    domainId: domain._id,
    sightingId: open._id,
    kind: "dns_live",
    severity: "medium",
    at: new Date(),
    payload: { lookalike: "acme-c0rp.com" },
  });
  return { ...models, ...app, user, domain, open, inactive, ignored };
}

test("another user's domain is 404 on page and actions", async (t) => {
  const { fetchWithCookies, post, Domain, User, open } = await setup(t);
  const other = await User.create({ email: "o@example.com", passwordHash: "x" });
  const theirs = await Domain.create({ userId: other._id, name: "other.example" });
  assert.equal((await fetchWithCookies(`/domains/${theirs._id}`, json)).status, 404);
  assert.equal(
    (await post(`/domains/${theirs._id}/sightings/${open._id}/dismiss`, {}, json)).status,
    404
  );
  assert.equal((await post(`/domains/${theirs._id}/scan`, {}, json)).status, 404);
});

test("dismiss stores the severity at dismissal, ignore and reopen change state", async (t) => {
  const { post, Sighting, domain, open } = await setup(t);
  const dismissed = await post(`/domains/${domain._id}/sightings/${open._id}/dismiss`, {}, json);
  assert.equal(dismissed.status, 200);
  assert.deepEqual(await dismissed.json(), { ok: true, state: "dismissed" });
  const s = await Sighting.findById(open._id);
  assert.equal(s.state, "dismissed");
  assert.equal(s.dismissedAtSeverity, "medium");
  await post(`/domains/${domain._id}/sightings/${open._id}/ignore`, {}, json);
  assert.equal((await Sighting.findById(open._id)).state, "ignored");
  const reopened = await post(`/domains/${domain._id}/sightings/${open._id}/reopen`, {}, json);
  assert.deepEqual(await reopened.json(), { ok: true, state: "open" });
});

test("a sighting under another domain is 404", async (t) => {
  const { post, Domain, user, domain, open } = await setup(t);
  const second = await Domain.create({ userId: user._id, name: "second.example" });
  assert.equal(
    (await post(`/domains/${second._id}/sightings/${open._id}/dismiss`, {}, json)).status,
    404
  );
  assert.equal(
    (await post(`/domains/${domain._id}/sightings/000000000000000000000000/dismiss`, {}, json))
      .status,
    404
  );
});

test("scan now makes the domain claimable immediately", async (t) => {
  const { post, Domain, domain } = await setup(t);
  await Domain.updateOne({ _id: domain._id }, { watchingSince: new Date() });
  const res = await post(`/domains/${domain._id}/scan`, {});
  assert.equal(res.status, 302);
  assert.equal(res.headers.get("location"), `/domains/${domain._id}`);
  const d = await Domain.findById(domain._id);
  assert.ok(d.nextWatchAt <= new Date());
  assert.equal(d.watchingSince, null);
});

test("page shows the timeline and groups sightings into tabs", async (t) => {
  const { fetchWithCookies, domain } = await setup(t);
  const res = await fetchWithCookies(`/domains/${domain._id}`);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /dns_live/);
  assert.match(html, /data-tab="watched"[^>]*>[\s\S]*?acme-c0rp\.com/);
  assert.match(html, /data-tab="inactive"[^>]*>[\s\S]*?acme-corp\.co\b/);
  assert.match(html, /data-tab="ignored"[^>]*>[\s\S]*?acme-corp\.net/);
  assert.match(html, /Scan now/);
});
