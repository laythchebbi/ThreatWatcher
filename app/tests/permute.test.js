require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { combosquats, permutations } = require("../src/services/watch/permute");
const fixture = require("./fixtures/dnstwist-acme-corp.json");

test("combosquats cover word, joiner and tld grid", () => {
  const out = combosquats("acme-corp.com");
  assert.ok(out.includes("acme-corp-login.com"));
  assert.ok(out.includes("acme-corplogin.io"));
  assert.ok(out.includes("acme-corp-secure.net"));
  assert.ok(!out.includes("acme-corp.com"));
  assert.equal(new Set(out).size, out.length);
  assert.equal(out.length, 10 * 2 * 6, "own tld .com is already in the list");
});

test("combosquats keeps a multi-label tld once", () => {
  const out = combosquats("acme.co.uk");
  assert.ok(out.includes("acme-login.co.uk"));
  assert.equal(out.filter((d) => d.endsWith(".co.uk")).length, 20);
});

test("permutations drops self and duplicates and prefers the worker", async () => {
  const worker = {
    permute: async () => ["ACME-CORP.com", "acme-c0rp.com", "acme-c0rp.com", " acmecorp.com "],
  };
  const { candidates, source } = await permutations("acme-corp.com", {
    worker,
    fetchImpl: () => {
      throw new Error("must not be called");
    },
    previous: [],
  });
  assert.equal(source, "worker");
  assert.ok(candidates.includes("acme-c0rp.com"));
  assert.ok(candidates.includes("acmecorp.com"));
  assert.ok(candidates.includes("acme-corp-login.com"), "combosquats merged in");
  assert.ok(!candidates.includes("acme-corp.com"));
  assert.equal(new Set(candidates).size, candidates.length);
});

test("falls back to dnstwister then to previous", async () => {
  const failing = {
    permute: async () => {
      throw new Error("worker down");
    },
  };
  const fetchImpl = async (url) => {
    assert.match(url, /^https:\/\/dnstwister\.report\/api\/fuzz\/[0-9a-f]+$/);
    return { ok: true, json: async () => fixture };
  };
  const viaApi = await permutations("acme-corp.com", { worker: failing, fetchImpl, previous: [] });
  assert.equal(viaApi.source, "dnstwister");
  assert.ok(viaApi.candidates.includes("xn--acme-corp-9bc.com"));
  const viaPrevious = await permutations("acme-corp.com", {
    worker: failing,
    fetchImpl: async () => ({ ok: false, status: 503 }),
    previous: ["acme-c0rp.com"],
  });
  assert.equal(viaPrevious.source, "previous");
  assert.ok(viaPrevious.candidates.includes("acme-c0rp.com"));
});
