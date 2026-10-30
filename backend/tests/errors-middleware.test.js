const { test } = require("node:test");
const assert = require("node:assert/strict");

process.env.MONGODB_URI ||= "mongodb://localhost:27017/threatwatcher-test";
process.env.WORKOS_API_KEY ||= "sk_test_unit";
process.env.WORKOS_CLIENT_ID ||= "client_unit";
process.env.WORKOS_ORGANIZATION_ID ||= "org_unit";
process.env.NODE_ENV = "test";
process.env.LOG_LEVEL = "fatal";

const { handler } = require("../src/middleware/errors");
const HttpError = require("../src/lib/http-error");

function run(err) {
  let status, body;
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
  handler(err, { originalUrl: "/x", id: "r1" }, res, () => assert.fail("should not call next"));
  return { status, body };
}

test("validation errors → 400 with issues", () => {
  const out = run(new HttpError("validation", { status: 400, code: "validation", issues: [{}] }));
  assert.equal(out.status, 400);
  assert.equal(out.body.error, "validation");
});

test("mongoose CastError → 404", () => {
  const err = new Error("Cast to ObjectId failed");
  err.name = "CastError";
  assert.equal(run(err).status, 404);
});

test("unknown errors → 500 without leaking the message", () => {
  const out = run(new Error("db exploded"));
  assert.equal(out.status, 500);
  assert.equal(out.body.message, "Internal error");
});
