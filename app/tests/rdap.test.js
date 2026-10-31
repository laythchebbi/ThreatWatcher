require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { lookupRdap, isDefensive, isStale } = require("../src/services/watch/rdap");
const { createBucket } = require("../src/services/watch/providers");
const fixture = require("./fixtures/rdap-acme-c0rp.json");

const buckets = { rdap: createBucket({ perMinute: 1000 }) };
const ok = (body) => ({ ok: true, status: 200, json: async () => body });

test("parses registration date, registrar and nameservers", async () => {
  let url;
  const out = await lookupRdap("acme-c0rp.com", {
    fetchImpl: async (u) => ((url = String(u)), ok(fixture)),
    buckets,
  });
  assert.equal(url, "https://rdap.org/domain/acme-c0rp.com");
  assert.equal(out.registeredAt.toISOString(), "2026-10-21T14:05:00.000Z");
  assert.equal(out.registrar, "NameCheap, Inc.");
  assert.deepEqual(out.ns, ["dns1.registrar-servers.com", "dns2.registrar-servers.com"]);
});

test("404 and network errors return null", async () => {
  assert.equal(
    await lookupRdap("nope.example", {
      fetchImpl: async () => ({ ok: false, status: 404 }),
      buckets,
    }),
    null
  );
  assert.equal(
    await lookupRdap("nope.example", {
      fetchImpl: async () => {
        throw new Error("boom");
      },
      buckets,
    }),
    null
  );
});

test("registrar fallback to handle when no vcard", async () => {
  const noVcard = { ...fixture, entities: [{ handle: "1068", roles: ["registrar"] }] };
  const out = await lookupRdap("x.com", { fetchImpl: async () => ok(noVcard), buckets });
  assert.equal(out.registrar, "1068");
});

test("defensive when registrar and a nameserver match", () => {
  const own = {
    registrar: "namecheap, inc.",
    ns: ["dns2.registrar-servers.com", "dns1.registrar-servers.com"],
  };
  assert.equal(
    isDefensive({ registrar: "NameCheap, Inc.", ns: ["dns1.registrar-servers.com"] }, own),
    true
  );
  assert.equal(isDefensive({ registrar: "NameCheap, Inc.", ns: ["ns1.other.net"] }, own), false);
  assert.equal(
    isDefensive({ registrar: "GoDaddy", ns: ["dns1.registrar-servers.com"] }, own),
    false
  );
  assert.equal(isDefensive(null, own), false);
  assert.equal(
    isDefensive({ registrar: "NameCheap, Inc.", ns: ["dns1.registrar-servers.com"] }, null),
    false
  );
});

test("stale after a year", () => {
  const now = new Date("2026-10-31T00:00:00Z");
  assert.equal(isStale({ registeredAt: new Date("2025-10-01T00:00:00Z") }, now), true);
  assert.equal(isStale({ registeredAt: new Date("2026-10-21T00:00:00Z") }, now), false);
  assert.equal(isStale({ registeredAt: null }, now), false);
  assert.equal(isStale(null, now), false);
});
