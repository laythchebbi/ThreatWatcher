const { test } = require("node:test");
const assert = require("node:assert/strict");
const { z } = require("zod");

process.env.MONGODB_URI ||= "mongodb://localhost:27017/threatwatcher-test";
process.env.INTERNAL_API_KEY ||= "x".repeat(16);
process.env.WORKOS_API_KEY ||= "sk_test_unit";
process.env.WORKOS_CLIENT_ID ||= "client_unit";
process.env.WORKOS_ORGANIZATION_ID ||= "org_unit";

const validate = require("../src/middleware/validate");

const schema = z.object({
  domain: z.string().min(3),
  count: z.coerce.number().int(),
});

test("validate: passes through valid input and coerces", () => {
  const req = { body: { domain: "example.com", count: "5" } };
  let called = false;
  validate(schema)(req, {}, (err) => {
    assert.equal(err, undefined);
    called = true;
  });
  assert.equal(called, true);
  assert.equal(req.body.count, 5);
});

test("validate: surfaces zod issues on next(err) with 400 + issues array", () => {
  const req = { body: { domain: "ab", count: "not-a-number" } };
  let err;
  validate(schema)(req, {}, (e) => {
    err = e;
  });
  assert.ok(err);
  assert.equal(err.status, 400);
  assert.equal(err.code, "validation");
  assert.ok(Array.isArray(err.issues));
  assert.ok(err.issues.length >= 1);
});
