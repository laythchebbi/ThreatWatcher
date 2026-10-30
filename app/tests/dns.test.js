require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { resolveCandidates, probeWildcardTlds, tldOf } = require("../src/services/watch/dns");

test("resolveCandidates keeps only resolving names and bounds concurrency", async () => {
  let inFlight = 0;
  let peak = 0;
  const resolver = {
    resolve4: async (n) => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
      if (n.startsWith("dead")) throw new Error("ENOTFOUND");
      return ["1.2.3.4"];
    },
    resolveMx: async () => [{ exchange: "mx.example", priority: 10 }],
    resolveNs: async () => ["ns1.parkingcrew.net"],
  };
  const names = Array.from({ length: 120 }, (_, i) => (i % 3 ? "live" : "dead") + i + ".com");
  const out = await resolveCandidates(names, { resolver, concurrency: 10 });
  assert.equal(out.size, 80);
  assert.ok(peak <= 10, `peak in flight was ${peak}`);
  assert.deepEqual(out.get("live1.com"), {
    a: ["1.2.3.4"],
    mx: ["mx.example"],
    ns: ["ns1.parkingcrew.net"],
  });
});

test("MX and NS failures yield empty lists, not a dropped name", async () => {
  const resolver = {
    resolve4: async () => ["9.9.9.9"],
    resolveMx: async () => {
      throw new Error("ENODATA");
    },
    resolveNs: async () => {
      throw new Error("ETIMEOUT");
    },
  };
  const out = await resolveCandidates(["x.com"], { resolver });
  assert.deepEqual(out.get("x.com"), { a: ["9.9.9.9"], mx: [], ns: [] });
});

test("probeWildcardTlds flags a tld that resolves random labels", async () => {
  const seen = [];
  const resolver = {
    resolve4: async (n) => {
      seen.push(n);
      if (n.endsWith(".ws")) return ["1.1.1.1"];
      throw new Error("ENOTFOUND");
    },
  };
  const wild = await probeWildcardTlds(["com", "ws", "co.uk"], {
    resolver,
    random: () => Buffer.alloc(12, 0xab),
  });
  assert.deepEqual([...wild], ["ws"]);
  assert.ok(
    seen.every((n) => /^[0-9a-f]{24}\.(com|ws|co\.uk)$/.test(n)),
    seen.join(",")
  );
});

test("tldOf returns everything after the first label", () => {
  assert.equal(tldOf("acme-corp.com"), "com");
  assert.equal(tldOf("acme.co.uk"), "co.uk");
});
