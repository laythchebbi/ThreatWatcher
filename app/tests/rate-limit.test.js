require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { rateLimit } = require("../src/middleware/rate-limit");

function res() {
  const r = { statusCode: 200, body: null };
  r.status = (s) => ((r.statusCode = s), r);
  r.json = (b) => ((r.body = b), r);
  return r;
}

test("6th request in window is 429 and window resets", () => {
  let t = 1_000_000;
  const mw = rateLimit({ windowMs: 60_000, max: 5, key: () => "k", now: () => t });
  const hits = [];
  for (let i = 0; i < 6; i++) {
    const r = res();
    mw({}, r, () => hits.push(i));
    if (i < 5) assert.equal(r.statusCode, 200);
    else {
      assert.equal(r.statusCode, 429);
      assert.deepEqual(r.body, { error: "rate_limited" });
    }
  }
  assert.equal(hits.length, 5);
  t += 60_001;
  const r = res();
  mw({}, r, () => hits.push("after"));
  assert.equal(hits.at(-1), "after");
});
