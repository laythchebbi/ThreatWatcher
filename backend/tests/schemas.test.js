const { test } = require("node:test");
const assert = require("node:assert/strict");

process.env.MONGODB_URI ||= "mongodb://localhost:27017/threatwatcher-test";
process.env.INTERNAL_API_KEY ||= "x".repeat(16);
process.env.WORKOS_API_KEY ||= "sk_test_unit";
process.env.WORKOS_CLIENT_ID ||= "client_unit";
process.env.WORKOS_ORGANIZATION_ID ||= "org_unit";

const { searchDomainParams, dataleakQuery, domainName } = require("../src/schemas/domain");
const { invitationBody, profileUpdate } = require("../src/schemas/auth");

test("domain schema accepts well-formed domains", () => {
  for (const d of ["example.com", "sub.example.co.uk", "xn--bcher-kva.com", "a-b.io"]) {
    assert.equal(domainName.safeParse(d).success, true, `should accept ${d}`);
  }
});

test("domain schema rejects garbage", () => {
  for (const d of [
    "",
    "no-dot",
    "_bad.com",
    "exa..mple.com",
    "'; DROP TABLE x; --",
    "a".repeat(254) + ".com",
  ]) {
    assert.equal(domainName.safeParse(d).success, false, `should reject ${d}`);
  }
});

test("dataleak query enforces limit and source enum", () => {
  assert.equal(dataleakQuery.safeParse({ q: "hi", source: "all", limit: "10" }).success, true);
  assert.equal(dataleakQuery.safeParse({ q: "h" }).success, false, "too short");
  assert.equal(
    dataleakQuery.safeParse({ q: "hi", source: "imap" }).success,
    false,
    "invalid source"
  );
});

test("invitation schema validates email + role", () => {
  assert.equal(invitationBody.safeParse({ email: "a@b.com" }).success, true);
  assert.equal(invitationBody.safeParse({ email: "a@b.com", role: "admin" }).success, true);
  assert.equal(invitationBody.safeParse({ email: "nope", role: "admin" }).success, false);
  assert.equal(invitationBody.safeParse({ email: "a@b.com", role: "owner" }).success, false);
});

test("profile update accepts displayName only", () => {
  assert.equal(profileUpdate.safeParse({}).success, true);
  assert.equal(profileUpdate.safeParse({ displayName: "Bob" }).success, true);
  assert.equal(profileUpdate.safeParse({ displayName: "" }).success, false);
});

test("searchDomainParams composes domainName", () => {
  assert.equal(searchDomainParams.safeParse({ domain: "EXAMPLE.com" }).success, true);
  assert.equal(searchDomainParams.safeParse({ domain: "no-tld" }).success, false);
});
