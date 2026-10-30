const { test } = require("node:test");
const assert = require("node:assert/strict");

// Minimum env so config loader doesn't exit during require.
process.env.MONGODB_URI ||= "mongodb://localhost:27017/threatwatcher-test";
process.env.WORKOS_API_KEY ||= "sk_test_unit";
process.env.WORKOS_CLIENT_ID ||= "client_unit";
process.env.WORKOS_ORGANIZATION_ID ||= "org_unit";
process.env.NODE_ENV = "test";

test("config loads with required env present", () => {
  const { env } = require("../src/config");
  assert.equal(env.NODE_ENV, "test");
  assert.ok(env.MONGODB_URI);
  assert.ok(env.WORKOS_API_KEY.startsWith("sk_"));
  assert.ok(env.WORKOS_CLIENT_ID.startsWith("client_"));
});

test("domain-similarity scoring keeps high matches", () => {
  const {
    scoreDomains,
    isPunycode,
    isSubstringMatch,
    secureScore,
  } = require("../src/services/domain-similarity");
  const matches = scoreDomains(
    "example.com",
    ["example.com", "examp1e.com", "totally-different.org"],
    0.7
  );
  assert.ok(matches.length >= 1, "should keep at least one match");
  assert.equal(matches[0].domain, "example.com");
  assert.equal(isPunycode("xn--bcher-kva.com"), true);
  assert.equal(isPunycode("plain.com"), false);
  assert.equal(isSubstringMatch("example.com", "myexample-login.com"), true);
  const score = secureScore({
    activeServer: true,
    substring: true,
    idn: false,
    visualSimilarity: 0.9,
  });
  assert.ok(score > 0 && score <= 1);
});

test("zod schemas reject malformed input", () => {
  const { searchDomainParams } = require("../src/schemas/domain");
  assert.equal(searchDomainParams.safeParse({ domain: "example.com" }).success, true);
  assert.equal(searchDomainParams.safeParse({ domain: "'; DROP TABLE users; --" }).success, false);
  assert.equal(searchDomainParams.safeParse({ domain: "no-tld" }).success, false);
});
