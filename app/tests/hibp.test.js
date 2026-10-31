require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { withDb } = require("./helpers/db");
const { hibpSource } = require("../src/services/watch/hibp");
const { leakSources } = require("../src/services/watch/leaks");
const { createBucket, createCache } = require("../src/services/watch/providers");
const latest = require("./fixtures/hibp-latest.json");
const breached = require("./fixtures/hibp-breached.json");

const deps = () => ({
  buckets: { hibp: createBucket({ perMinute: 1000 }) },
  cache: createCache({ ttlMs: 60_000 }),
});

function makeFetch(log, { status = 200 } = {}) {
  return async (url, init) => {
    const u = String(url);
    log.push(u);
    assert.equal(init.headers["hibp-api-key"], "key123");
    assert.match(init.headers["User-Agent"], /ThreatWatcher/);
    if (status !== 200) return new Response("nope", { status });
    if (/\/latestBreach$/.test(u)) return new Response(JSON.stringify(latest), { status: 200 });
    if (/\/breacheddomain\/acme-corp\.com$/.test(u))
      return new Response(JSON.stringify(breached), { status: 200 });
    if (/\/breach\/AcmeCorpBreach2026$/.test(u))
      return new Response(JSON.stringify(latest), { status: 200 });
    if (/\/breach\/OldForum2019$/.test(u))
      return new Response(
        JSON.stringify({
          ...latest,
          Name: "OldForum2019",
          Title: "Old Forum",
          Domain: "oldforum.example",
          BreachDate: "2019-02-01",
          PwnCount: 50000,
          DataClasses: ["Email addresses"],
        }),
        { status: 200 }
      );
    return new Response("nope", { status: 404 });
  };
}

async function seed(t, hibp) {
  const models = await withDb(t);
  const user = await models.User.create({ email: "h@example.com", passwordHash: "x" });
  const domain = await models.Domain.create({ userId: user._id, name: "acme-corp.com", hibp });
  return { ...models, user, domain };
}

test("hibp is registered as a leak source", () => {
  assert.ok(leakSources.some((s) => s.name === "hibp"));
});

test("no key → no calls", async (t) => {
  const { domain, ...models } = await seed(t, undefined);
  const log = [];
  const out = await hibpSource.find({
    domain,
    terms: [],
    since: null,
    models,
    fetchImpl: makeFetch(log),
    ...deps(),
  });
  assert.deepEqual(out, []);
  assert.equal(log.length, 0);
});

test("new breach → one mention per breach touching the domain, high severity, lastBreachSeen stored", async (t) => {
  const { domain, Domain, ...models } = await seed(t, { apiKey: "key123" });
  const log = [];
  const out = await hibpSource.find({
    domain,
    terms: [],
    since: null,
    models: { ...models, Domain },
    fetchImpl: makeFetch(log),
    ...deps(),
  });
  assert.equal(out.length, 2, "two distinct breaches across the two aliases");
  const main = out.find((c) => c.sourceRef === "hibp:AcmeCorpBreach2026");
  assert.equal(main.source, "hibp");
  assert.equal(main.severity, "high");
  assert.match(
    main.excerpt,
    /ACME Corp, 2026-10-20, 1204 addresses, data: Email addresses, Passwords/
  );
  assert.equal((await Domain.findById(domain._id)).hibp.lastBreachSeen, "AcmeCorpBreach2026");
});

test("unchanged latest breach → no second domain call", async (t) => {
  const { domain, Domain, ...models } = await seed(t, {
    apiKey: "key123",
    lastBreachSeen: "AcmeCorpBreach2026",
  });
  const log = [];
  const out = await hibpSource.find({
    domain,
    terms: [],
    since: null,
    models: { ...models, Domain },
    fetchImpl: makeFetch(log),
    ...deps(),
  });
  assert.deepEqual(out, []);
  assert.equal(log.length, 1, "only latestBreach");
});

test("401 records the error and returns nothing", async (t) => {
  const { domain, Domain, ...models } = await seed(t, { apiKey: "key123" });
  const out = await hibpSource.find({
    domain,
    terms: [],
    since: null,
    models: { ...models, Domain },
    fetchImpl: makeFetch([], { status: 401 }),
    ...deps(),
  });
  assert.deepEqual(out, []);
  assert.match((await Domain.findById(domain._id)).hibp.error, /401/);
});
