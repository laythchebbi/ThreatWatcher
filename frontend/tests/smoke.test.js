const { test } = require("node:test");
const assert = require("node:assert/strict");

process.env.BACKEND_URL ||= "http://localhost:3000";
process.env.FRONTEND_BASE_URL ||= "http://localhost:4000";
process.env.WORKOS_API_KEY ||= "sk_test_unit";
process.env.WORKOS_CLIENT_ID ||= "client_unit";
process.env.WORKOS_REDIRECT_URI ||= "http://localhost:4000/auth/callback";
process.env.SESSION_PASSWORD ||= "x".repeat(48);
process.env.NODE_ENV = "test";

test("frontend config loads with required env", () => {
  const { env } = require("../src/config");
  assert.equal(env.NODE_ENV, "test");
  assert.ok(env.BACKEND_URL);
  assert.ok(env.WORKOS_API_KEY.startsWith("sk_"));
  assert.ok(env.WORKOS_CLIENT_ID.startsWith("client_"));
  assert.ok(env.SESSION_PASSWORD.length >= 32);
  assert.equal(
    env.SESSION_COOKIE_SECURE,
    false,
    "unset SESSION_COOKIE_SECURE parses to boolean false"
  );
});

test("session middleware exposes requireAuth and requireRole guards", () => {
  const { requireAuth, requireRole } = require("../src/middleware/session");
  assert.equal(typeof requireAuth, "function");
  assert.equal(typeof requireRole, "function");

  // requireAuth on an unauthenticated JSON request → 401
  let status;
  requireAuth(
    { user: null, accepts: () => false },
    {
      status(s) {
        status = s;
        return this;
      },
      json() {
        return this;
      },
    },
    () => assert.fail("should not call next")
  );
  assert.equal(status, 401);

  // requireRole on wrong role → 403
  let status2;
  requireRole("admin")(
    { user: { role: "analyst" } },
    {
      status(s) {
        status2 = s;
        return this;
      },
      json() {
        return this;
      },
    },
    () => assert.fail("should not call next")
  );
  assert.equal(status2, 403);

  // requireRole on matching role → calls next
  let nextCalled = false;
  requireRole("admin")({ user: { role: "admin" } }, {}, () => {
    nextCalled = true;
  });
  assert.equal(nextCalled, true);
});

test("decodeClaims pulls payload from a JWT-shaped string without verification", () => {
  const { decodeClaims } = require("../src/middleware/session");

  // Hand-built JWT (header.payload.signature, signature unused since we never verify).
  const payload = { sub: "u_123", email: "a@b.c", role: "admin", org_id: "org_1" };
  const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
  const fake = `${b64({ alg: "RS256", typ: "JWT" })}.${b64(payload)}.sig`;

  const out = decodeClaims(fake);
  assert.equal(out.sub, "u_123");
  assert.equal(out.role, "admin");
  assert.equal(out.org_id, "org_1");

  // Garbage input never throws.
  assert.deepEqual(decodeClaims(""), {});
  assert.deepEqual(decodeClaims("not-a-jwt"), {});
  assert.deepEqual(decodeClaims(null), {});
});

test("safeNext only accepts same-site paths", () => {
  const { safeNext } = require("../src/middleware/session");
  assert.equal(safeNext("/settings#security"), "/settings#security");
  assert.equal(safeNext("/reports?limit=5"), "/reports?limit=5");
  assert.equal(safeNext("https://evil.example/"), "/dashboard");
  assert.equal(safeNext("//evil.example"), "/dashboard");
  assert.equal(safeNext("/\\evil.example"), "/dashboard");
  assert.equal(safeNext("/\\/evil.example"), "/dashboard");
  assert.equal(safeNext(undefined), "/dashboard");
  assert.equal(safeNext(["/a", "/b"]), "/dashboard");
});
