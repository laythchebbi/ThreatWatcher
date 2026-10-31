require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { withDb } = require("./helpers/db");
const { runCycle } = require("../src/services/watch/cycle");
const { createCache } = require("../src/services/watch/providers");
const rdapFixture = require("./fixtures/rdap-acme-c0rp.json");
// The customer's own domain sits at a different registrar, so lookalikes are not "defensive".
const ownRdapFixture = {
  ...rdapFixture,
  entities: [
    {
      handle: "146",
      roles: ["registrar"],
      vcardArray: ["vcard", [["fn", {}, "text", "GoDaddy.com, LLC"]]],
    },
  ],
  nameservers: [{ ldhName: "NS1.GODADDY.COM" }],
};

const NOW = new Date("2026-10-31T00:00:00Z");
const login = fs.readFileSync(path.join(__dirname, "fixtures/page-login.html"), "utf8");
const marketing = fs.readFileSync(path.join(__dirname, "fixtures/page-marketing.html"), "utf8");
const emptyLists = { parkingNs: new Set(), cdnCidrs: [] };
const spotter = [
  {
    id: "1",
    tbs_sha256: "tbs1",
    dns_names: ["acme-corp-login.com"],
    not_before: "2026-10-30T00:00:00Z",
    issuer: { friendly_name: "Let's Encrypt" },
  },
];

function makeFetch(log, { certsFail = false } = {}) {
  return async (url) => {
    const u = String(url);
    log.push(u);
    if (/haveibeenpwned\.com\/api\/v3\/latestBreach$/.test(u))
      return new Response(
        JSON.stringify({
          Name: "AcmeBreach",
          Title: "ACME",
          BreachDate: "2026-10-20",
          PwnCount: 10,
          DataClasses: ["Email addresses"],
        }),
        { status: 200 }
      );
    if (/haveibeenpwned\.com\/api\/v3\/breacheddomain\//.test(u))
      return new Response(JSON.stringify({ alice: ["AcmeBreach"] }), { status: 200 });
    if (/haveibeenpwned\.com\/api\/v3\/breach\//.test(u))
      return new Response(
        JSON.stringify({
          Name: "AcmeBreach",
          Title: "ACME",
          BreachDate: "2026-10-20",
          PwnCount: 10,
          DataClasses: ["Email addresses"],
        }),
        { status: 200 }
      );
    if (/certspotter|crt\.sh/.test(u)) {
      if (certsFail) throw new Error("provider down");
      return new Response(JSON.stringify(spotter), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (/rdap\.org\/domain\/acme-corp\.com$/.test(u))
      return new Response(JSON.stringify(ownRdapFixture), { status: 200 });
    if (/rdap\.org\/domain\//.test(u))
      return new Response(JSON.stringify(rdapFixture), { status: 200 });
    if (/^https?:\/\/acme-corp\.com\//.test(u))
      return new Response(marketing, { status: 200, headers: { "content-type": "text/html" } });
    if (/^https?:\/\/acme-corp-login\.com\//.test(u))
      return new Response(login, {
        status: 200,
        headers: { "content-type": "text/html", server: "nginx" },
      });
    return new Response("nope", { status: 404 });
  };
}

const resolver = {
  resolve4: async (n) =>
    n === "acme-corp-login.com" || n === "acme-corp.com"
      ? ["1.1.1.1"]
      : Promise.reject(new Error("ENOTFOUND")),
  resolve6: async () => [],
  resolveMx: async () => [],
  resolveNs: async () => ["ns1.example.net"],
  resolveTxt: async (name) => {
    const table = {
      "acme-corp.com": ["v=spf1 -all"],
      "_dmarc.acme-corp.com": ["v=DMARC1; p=none"],
    };
    if (name in table) return table[name].map((s) => [s]);
    throw new Error("ENODATA");
  },
};

const deps = (log, over = {}) => ({
  worker: { permute: async () => ["acme-corp-login.com", "acme-c0rp.com"] },
  resolver,
  fetchImpl: makeFetch(log, over),
  apiKey: "k",
  connect: () => {
    throw new Error("no tls in tests");
  },
  lists: emptyLists,
  now: NOW,
  random: () => Buffer.alloc(32, 1),
  cache: createCache({ ttlMs: 6 * 3600_000 }), // fresh per test: the module cache would leak between tests
  ...over,
});

async function seed(t) {
  const models = await withDb(t);
  const user = await models.User.create({ email: "c@example.com", passwordHash: "x" });
  const domain = await models.Domain.create({ userId: user._id, name: "acme-corp.com" });
  return { ...models, user, domain };
}

test("first cycle stores cert facts, rdap, http and posture", async (t) => {
  const { Domain, Sighting, Event, domain } = await seed(t);
  const log = [];
  await runCycle(domain, deps(log));
  const s = await Sighting.findOne({ domainId: domain._id, lookalike: "acme-corp-login.com" });
  assert.equal(s.cert.tbs, "tbs1");
  assert.equal(s.rdap.registrar, "NameCheap, Inc.");
  assert.equal(s.http.hasPasswordForm, true);
  assert.equal(s.http.brandTermFound, true);
  assert.equal(s.http.headers.server, "nginx");
  assert.ok(s.http.similarity !== null, "reference text was fetched and compared");
  const d = await Domain.findById(domain._id);
  assert.equal(d.certCursor, "1");
  assert.equal(d.ownRdap.registrar, "GoDaddy.com, LLC");
  assert.equal(d.posture.grade, "D");
  const kinds = (await Event.find({ domainId: domain._id })).map((e) => e.kind);
  assert.ok(kinds.includes("cert_issued"), kinds.join(","));
  assert.ok(kinds.includes("page_mimics_login"), kinds.join(","));
  assert.ok(kinds.includes("posture_weak"), kinds.join(","));
  assert.equal(
    log.filter((u) => /^https?:\/\/acme-corp\.com\//.test(u)).length,
    1,
    "own page fetched once"
  );
});

test("a failing certificate provider does not stop DNS and HTTP", async (t) => {
  const { Sighting, domain } = await seed(t);
  await runCycle(domain, deps([], { certsFail: true }));
  const s = await Sighting.findOne({ domainId: domain._id, lookalike: "acme-corp-login.com" });
  assert.equal(s.dns.resolves, true);
  assert.equal(s.http.status, 200);
  assert.equal(s.cert?.tbs, undefined);
});

test("posture is checked weekly, not every cycle", async (t) => {
  const { Domain, domain } = await seed(t);
  await runCycle(domain, deps([]));
  const first = (await Domain.findById(domain._id)).posture.checkedAt;
  await runCycle(
    await Domain.findById(domain._id),
    deps([], { now: new Date(NOW.getTime() + 6 * 3600_000) })
  );
  assert.equal((await Domain.findById(domain._id)).posture.checkedAt.getTime(), first.getTime());
  await runCycle(
    await Domain.findById(domain._id),
    deps([], { now: new Date(NOW.getTime() + 8 * 86400_000) })
  );
  assert.ok((await Domain.findById(domain._id)).posture.checkedAt > first);
});

test("own rdap is refreshed monthly and sighting rdap only on first resolve", async (t) => {
  const { Domain, domain } = await seed(t);
  const log = [];
  await runCycle(domain, deps(log));
  const rdapCalls = () => log.filter((u) => /rdap\.org/.test(u)).length;
  const afterFirst = rdapCalls();
  assert.equal(afterFirst, 2, "own domain + the resolving sighting");
  await runCycle(
    await Domain.findById(domain._id),
    deps(log, { now: new Date(NOW.getTime() + 6 * 3600_000) })
  );
  assert.equal(rdapCalls(), afterFirst, "nothing new resolved, no new rdap calls");
});

test("with an HIBP key the leak step still persists dark-web mentions and adds the breach", async (t) => {
  const { Domain, Mention, DarkwebPage, domain } = await seed(t);
  await Domain.updateOne({ _id: domain._id }, { hibp: { apiKey: "key123" } });
  await DarkwebPage.create({
    sourceUrl: "http://s.onion",
    pageUrl: "http://s.onion/p",
    title: "dump",
    body: "acme-corp.com creds",
    crawledAt: new Date(NOW.getTime() - 1000),
  });
  await runCycle(await Domain.findById(domain._id), deps([]));
  const sources = (await Mention.find({ domainId: domain._id })).map((m) => m.source).sort();
  assert.deepEqual(sources, ["darkweb", "hibp"]);
  assert.equal((await Domain.findById(domain._id)).hibp.lastBreachSeen, "AcmeBreach");
});

test("RDAP is capped per cycle and selected by missing rdap, not by first resolve", async (t) => {
  const { domain } = await seed(t);
  const many = Array.from({ length: 60 }, (_, i) => `acme-corp-${i}.com`);
  const log = [];
  const wideResolver = {
    ...resolver,
    resolve4: async (n) =>
      many.includes(n) || n === "acme-corp.com"
        ? ["1.1.1.1"]
        : Promise.reject(new Error("ENOTFOUND")),
  };
  await runCycle(
    domain,
    deps(log, { worker: { permute: async () => many }, resolver: wideResolver })
  );
  const sightingRdap = log.filter((u) => /rdap\.org\/domain\/acme-corp-\d+\.com$/.test(u)).length;
  assert.ok(sightingRdap <= 50 && sightingRdap > 0, `rdap calls: ${sightingRdap}`);
});
