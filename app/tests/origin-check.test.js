require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { originCheck } = require("../src/middleware/origin-check");

function run(method, headers) {
  const r = { statusCode: 200, body: null };
  r.status = (s) => ((r.statusCode = s), r);
  r.json = (b) => ((r.body = b), r);
  let passed = false;
  originCheck("http://localhost:3000")({ method, headers }, r, () => (passed = true));
  return { passed, status: r.statusCode, body: r.body };
}

test("POST with foreign Origin is 403, same host passes, no headers passes, GET ignored", () => {
  assert.deepEqual(run("POST", { origin: "https://evil.example" }), {
    passed: false,
    status: 403,
    body: { error: "bad_origin" },
  });
  assert.equal(run("POST", { origin: "http://localhost:3000" }).passed, true);
  assert.equal(run("POST", { referer: "http://localhost:3000/login?x=1" }).passed, true);
  assert.equal(run("POST", { referer: "http://evil.example/login" }).passed, false);
  assert.equal(run("POST", {}).passed, true);
  assert.equal(run("GET", { origin: "https://evil.example" }).passed, true);
});
