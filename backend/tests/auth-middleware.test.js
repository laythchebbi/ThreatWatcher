const { test } = require("node:test");
const assert = require("node:assert/strict");

process.env.MONGODB_URI ||= "mongodb://localhost:27017/threatwatcher-test";
process.env.INTERNAL_API_KEY ||= "y".repeat(16);
process.env.WORKOS_API_KEY ||= "sk_test_unit";
process.env.WORKOS_CLIENT_ID ||= "client_unit";
process.env.WORKOS_ORGANIZATION_ID ||= "org_unit";

const { requireServiceKey, requireRole } = require("../src/middleware/auth");

test("requireServiceKey 401s without header", () => {
  let status, body;
  const req = { headers: {} };
  const res = {
    status(s) {
      status = s;
      return this;
    },
    json(b) {
      body = b;
      return this;
    },
  };
  requireServiceKey(req, res, () => assert.fail("should not call next"));
  assert.equal(status, 401);
  assert.equal(body.error, "unauthorized");
});

test("requireServiceKey passes with matching header", () => {
  const req = { headers: { "x-internal-key": process.env.INTERNAL_API_KEY } };
  let nextCalled = false;
  requireServiceKey(req, {}, () => {
    nextCalled = true;
  });
  assert.equal(nextCalled, true);
});

test("requireRole 401 when unauthenticated", () => {
  let status;
  const req = {};
  const res = {
    status(s) {
      status = s;
      return this;
    },
    json() {
      return this;
    },
  };
  requireRole("admin")(req, res, () => assert.fail("should not call next"));
  assert.equal(status, 401);
});

test("requireRole 403 when role does not match", () => {
  let status;
  const req = { user: { role: "analyst" } };
  const res = {
    status(s) {
      status = s;
      return this;
    },
    json() {
      return this;
    },
  };
  requireRole("admin")(req, res, () => assert.fail("should not call next"));
  assert.equal(status, 403);
});

test("requireRole passes when role matches", () => {
  const req = { user: { role: "admin" } };
  let nextCalled = false;
  requireRole("admin")(req, {}, () => {
    nextCalled = true;
  });
  assert.equal(nextCalled, true);
});
