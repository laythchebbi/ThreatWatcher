require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");

const sim = require("../src/services/similarity");

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
