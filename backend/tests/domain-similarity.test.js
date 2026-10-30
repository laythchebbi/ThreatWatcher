const { test } = require("node:test");
const assert = require("node:assert/strict");

process.env.MONGODB_URI ||= "mongodb://localhost:27017/threatwatcher-test";
process.env.INTERNAL_API_KEY ||= "x".repeat(16);
process.env.WORKOS_API_KEY ||= "sk_test_unit";
process.env.WORKOS_CLIENT_ID ||= "client_unit";
process.env.WORKOS_ORGANIZATION_ID ||= "org_unit";

const sim = require("../src/services/domain-similarity");

test("scoreDomains: returns 0 results for empty inputs", () => {
  assert.deepEqual(sim.scoreDomains("", []), []);
  assert.deepEqual(sim.scoreDomains("example.com", []), []);
  assert.deepEqual(sim.scoreDomains("", ["a.com"]), []);
});

test("scoreDomains: filters below threshold and sorts desc", () => {
  const out = sim.scoreDomains(
    "example.com",
    ["exemple.com", "totally-unrelated.io", "example.co"],
    0.7
  );
  assert.ok(out.length >= 1);
  for (let i = 1; i < out.length; i++) {
    assert.ok(out[i - 1].similarity >= out[i].similarity, "sort desc");
  }
});

test("isPunycode: detects xn-- and variants", () => {
  assert.equal(sim.isPunycode("xn--bcher-kva.com"), true);
  assert.equal(sim.isPunycode("XN--MGBH0FB.example"), true);
  assert.equal(sim.isPunycode("normal-domain.com"), false);
});

test("isSubstringMatch: matches by first label", () => {
  assert.equal(sim.isSubstringMatch("example.com", "myexample-login.io"), true);
  assert.equal(sim.isSubstringMatch("example.com", "completely.different"), false);
});

test("secureScore: bounded 0..1, higher is safer", () => {
  const clean = sim.secureScore({
    activeServer: false,
    substring: false,
    idn: false,
    visualSimilarity: 0,
  });
  const worst = sim.secureScore({
    activeServer: true,
    substring: true,
    idn: true,
    visualSimilarity: 1,
  });
  assert.equal(clean, 1);
  assert.ok(worst >= 0 && worst <= 1);
  assert.ok(worst < 0.4, "all signals → red zone (< 0.4)");
  assert.ok(clean >= 0.7, "no signals → green zone (>= 0.7)");
});
