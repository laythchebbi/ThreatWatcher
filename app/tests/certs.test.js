require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { fetchCertificates, certCandidates } = require("../src/services/watch/certs");
const { createBucket, createCache } = require("../src/services/watch/providers");
const spotter = require("./fixtures/certspotter-acme.json");
const crtsh = require("./fixtures/crtsh-acme.json");

const fastBuckets = () => ({
  crtsh: createBucket({ perMinute: 1000 }),
  certspotter: createBucket({ perMinute: 1000 }),
});
const ok = (body) => ({
  ok: true,
  status: 200,
  json: async () => body,
  text: async () => JSON.stringify(body),
});

test("short labels skip CT", async () => {
  let calls = 0;
  const out = await fetchCertificates("acme", {
    fetchImpl: async () => (calls++, ok([])),
    apiKey: "k",
    cache: createCache({ ttlMs: 1000 }),
    buckets: fastBuckets(),
  });
  assert.deepEqual(out, { certs: [], cursor: null, source: "skipped" });
  assert.equal(calls, 0);
});

test("certspotter parses, advances cursor and caches", async () => {
  const urls = [];
  const fetchImpl = async (url, init) => {
    urls.push(String(url));
    assert.equal(init.headers.Authorization, "Bearer k");
    return ok(/after=9000/.test(String(url)) ? spotter : []);
  };
  const cache = createCache({ ttlMs: 60_000 });
  const first = await fetchCertificates("acme-corp", {
    fetchImpl,
    apiKey: "k",
    cursor: "9000",
    cache,
    buckets: fastBuckets(),
  });
  assert.equal(first.source, "certspotter");
  assert.equal(first.cursor, "9004");
  assert.equal(first.certs.length, 4);
  assert.deepEqual(first.certs[0].names, [
    "acme-corp-login.example",
    "www.acme-corp-login.example",
  ]);
  assert.equal(first.certs[0].issuer, "Let's Encrypt");
  assert.equal(first.certs[0].tbs, "aaa111");
  assert.ok(first.certs[0].notBefore instanceof Date);
  assert.match(
    urls[0],
    /api\.certspotter\.com\/v1\/issuances\?domain=acme-corp&include_subdomains=true&expand=dns_names&expand=issuer&after=9000/
  );
  const second = await fetchCertificates("acme-corp", {
    fetchImpl,
    apiKey: "k",
    cursor: "9000",
    cache,
    buckets: fastBuckets(),
  });
  assert.equal(second.source, "cache", "same label and cursor within the TTL");
  assert.equal(urls.length, 2, "one data page plus the empty page, nothing on the cached call");
});

test("falls back to crt.sh and caps rows", async () => {
  const big = Array.from({ length: 6000 }, (_, i) => ({ ...crtsh[0], id: i }));
  const fetchImpl = async (url) =>
    /certspotter/.test(String(url)) ? { ok: false, status: 503 } : ok(big);
  const out = await fetchCertificates("acme-corp", {
    fetchImpl,
    apiKey: "k",
    cache: createCache({ ttlMs: 1000 }),
    buckets: fastBuckets(),
  });
  assert.equal(out.source, "crtsh");
  assert.equal(out.certs.length, 5000);
  assert.deepEqual(out.certs[0].names, ["acme-corp-secure.net", "www.acme-corp-secure.net"]);
});

test("both providers down returns the cached value or an empty list with error", async () => {
  const fetchImpl = async () => ({ ok: false, status: 502 });
  const out = await fetchCertificates("acme-corp", {
    fetchImpl,
    apiKey: undefined,
    cache: createCache({ ttlMs: 1000 }),
    buckets: fastBuckets(),
  });
  assert.equal(out.certs.length, 0);
  assert.ok(out.error);
});

test("certCandidates filters by similarity and merges per name", () => {
  const certs = spotter.map((c) => ({
    names: c.dns_names,
    notBefore: new Date(c.not_before),
    issuer: c.issuer.friendly_name,
    tbs: c.tbs_sha256,
  }));
  const out = certCandidates("acme-corp.com", certs);
  assert.ok(out.has("acme-corp-login.example"), "substring match kept");
  assert.ok(out.has("acme-c0rp.com"), "similar kept");
  assert.ok(!out.has("*.acme-c0rp.com"), "wildcard stripped");
  assert.ok(!out.has("unrelated.org"));
  assert.ok(!out.has("mail.acme-corp.com"), "own subdomain excluded");
  const merged = out.get("acme-c0rp.com");
  assert.equal(merged.firstIssuedAt.toISOString(), "2026-08-01T00:00:00.000Z");
  assert.equal(merged.notBefore.toISOString(), "2026-10-28T00:00:00.000Z");
  assert.equal(merged.tbs, "bbb222");
});

test("certspotter pages until an empty page and the cache is keyed by cursor", async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    const u = String(url);
    calls.push(u);
    if (/after=9000/.test(u)) return ok(spotter.slice(0, 2));
    if (/after=9002/.test(u)) return ok(spotter.slice(2, 4));
    if (/certspotter/.test(u)) return ok([]);
    return ok(crtsh);
  };
  const cache = createCache({ ttlMs: 60_000 });
  const out = await fetchCertificates("acme-corp", {
    fetchImpl,
    apiKey: "k",
    cursor: "9000",
    cache,
    buckets: fastBuckets(),
  });
  assert.equal(out.certs.length, 4);
  assert.equal(out.cursor, "9004");
  assert.equal(
    calls.filter((u) => /certspotter/.test(u)).length,
    3,
    "two pages plus the empty one"
  );
  const other = await fetchCertificates("acme-corp", {
    fetchImpl,
    apiKey: "k",
    cursor: null,
    cache,
    buckets: fastBuckets(),
  });
  assert.notEqual(other.source, "cache", "a different cursor is not the same cache entry");
});

test("with a key and no cursor yet, crt.sh backfills once and the results merge", async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    const u = String(url);
    calls.push(u);
    if (/certspotter/.test(u)) return ok(/after=/.test(u) ? [] : spotter.slice(0, 1));
    return ok(crtsh);
  };
  const out = await fetchCertificates("acme-corp", {
    fetchImpl,
    apiKey: "k",
    cursor: null,
    cache: createCache({ ttlMs: 1000 }),
    buckets: fastBuckets(),
  });
  assert.ok(
    calls.some((u) => /crt\.sh/.test(u)),
    "crt.sh called for backfill"
  );
  assert.ok(
    out.certs.some((c) => c.names.includes("acme-corp-secure.net")),
    "crt.sh rows merged"
  );
  assert.ok(
    out.certs.some((c) => c.tbs === "aaa111"),
    "certspotter rows merged"
  );
  assert.equal(out.source, "certspotter");
});
