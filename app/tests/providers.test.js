require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  createBucket,
  createCache,
  buckets,
  labelCache,
} = require("../src/services/watch/providers");

test("bucket allows perMinute calls then waits for refill", async () => {
  let t = 0;
  const b = createBucket({ perMinute: 2, now: () => t });
  await b.take();
  await b.take();
  let third = false;
  const p = b.take().then(() => (third = true));
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(third, false, "no token left");
  t += 30_000; // half a minute → one token refilled
  await p;
  assert.equal(third, true);
});

test("bucket capacity never exceeds perMinute", async () => {
  let t = 0;
  const b = createBucket({ perMinute: 3, now: () => t });
  t += 10 * 60_000; // idle for ten minutes
  for (let i = 0; i < 3; i++) await b.take();
  let fourth = false;
  const p = b.take().then(() => (fourth = true));
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(fourth, false);
  t += 20_000;
  await p;
});

test("cache forgets after ttl", () => {
  let t = 0;
  const c = createCache({ ttlMs: 1000, now: () => t });
  c.set("k", { v: 1 });
  assert.deepEqual(c.get("k"), { v: 1 });
  assert.equal(c.has("k"), true);
  t += 1001;
  assert.equal(c.get("k"), undefined);
  assert.equal(c.has("k"), false);
});

test("module singletons exist with the spec'd rates", () => {
  for (const name of ["crtsh", "certspotter", "dnstwister", "rdap", "hibp"]) {
    assert.equal(typeof buckets[name].take, "function", name);
  }
  assert.equal(typeof labelCache.get, "function");
});
