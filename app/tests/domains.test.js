require("./helpers/env");
const { test, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const { withDb } = require("./helpers/db");
const { startApp } = require("./helpers/http");
const mailer = require("../src/lib/mailer");
const { rateLimit } = require("../src/middleware/rate-limit");

const PW = "correct horse battery";

beforeEach(() => {
  mailer._reset();
  rateLimit._reset();
});

async function signedIn(t, { verified = true, email = "d@example.com" } = {}) {
  const models = await withDb(t);
  const app = await startApp(t);
  await app.post("/signup", { email, password: PW });
  if (verified) await models.User.updateOne({ email }, { emailVerifiedAt: new Date() });
  return { ...models, ...app };
}

test("add domain normalises and validates", async (t) => {
  const { post, Domain } = await signedIn(t);
  const ok = await post("/domains", { name: "ACME-Corp.com." });
  assert.equal(ok.status, 302);
  assert.equal(ok.headers.get("location"), "/domains");
  const d = await Domain.findOne({ name: "acme-corp.com" });
  assert.ok(d, "stored lowercase without the trailing dot");
  assert.ok(d.nextWatchAt <= new Date(), "watched on the next tick");
  const bad = await post("/domains", { name: "not a domain" });
  assert.equal(bad.status, 400);
  const dup = await post("/domains", { name: "acme-corp.com" });
  assert.equal(dup.status, 409);
});

test("unverified account cannot add a domain", async (t) => {
  const { post } = await signedIn(t, { verified: false });
  const res = await post(
    "/domains",
    { name: "acme-corp.com" },
    { headers: { accept: "application/json" } }
  );
  assert.equal(res.status, 403);
  assert.deepEqual(await res.json(), { error: "email_unverified" });
});

test("sixth domain is refused", async (t) => {
  const { post } = await signedIn(t);
  for (let i = 1; i <= 5; i++)
    assert.equal((await post("/domains", { name: `d${i}.example` })).status, 302);
  const sixth = await post(
    "/domains",
    { name: "d6.example" },
    { headers: { accept: "application/json" } }
  );
  assert.equal(sixth.status, 422);
  assert.deepEqual(await sixth.json(), { error: "domain_limit" });
});

test("dashboard renders counters and the domain list shows the domain", async (t) => {
  const { post, fetchWithCookies } = await signedIn(t);
  await post("/domains", { name: "acme-corp.com" });
  const dash = await fetchWithCookies("/");
  assert.equal(dash.status, 200);
  const html = await dash.text();
  assert.match(html, /domains watched/);
  assert.match(html, /acme-corp\.com/);
  const list = await fetchWithCookies("/domains");
  assert.match(await list.text(), /acme-corp\.com/);
});

test("delete removes the domain", async (t) => {
  const { post, Domain } = await signedIn(t);
  await post("/domains", { name: "acme-corp.com" });
  const d = await Domain.findOne({ name: "acme-corp.com" });
  const res = await post(`/domains/${d._id}/delete`, {});
  assert.equal(res.status, 302);
  assert.equal(await Domain.countDocuments(), 0);
});

test("delete removes the domain's mentions too", async (t) => {
  const { post, Domain, Mention, user } = await signedIn(t);
  await post("/domains", { name: "acme-corp.com" });
  const d = await Domain.findOne({ name: "acme-corp.com" });
  await Mention.create({
    userId: d.userId,
    domainId: d._id,
    source: "darkweb",
    sourceRef: "darkweb:x",
    excerpt: "x",
    excerptHash: "h",
    severity: "medium",
  });
  await post(`/domains/${d._id}/delete`, {});
  assert.equal(await Mention.countDocuments({ domainId: d._id }), 0);
});
