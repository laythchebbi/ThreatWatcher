const { test } = require("node:test");
const assert = require("node:assert/strict");

process.env.BACKEND_URL ||= "http://localhost:3000";
process.env.FRONTEND_BASE_URL ||= "http://localhost:4000";
process.env.WORKOS_API_KEY ||= "sk_test_unit";
process.env.WORKOS_CLIENT_ID ||= "client_unit";
process.env.WORKOS_REDIRECT_URI ||= "http://localhost:4000/auth/callback";
process.env.SESSION_PASSWORD ||= "x".repeat(48);

const backend = require("../src/services/backend-client");

test("client has expected baseURL", () => {
  assert.equal(backend.client.defaults.baseURL, "http://localhost:3000");
});

test("withAuth returns a new client with auth header", () => {
  const c = backend.withAuth("tok-123");
  assert.equal(c.defaults.headers.Authorization, "Bearer tok-123");
  assert.equal(c.defaults.baseURL, "http://localhost:3000");
});

test("withAuth returns the unauthenticated client when no token", () => {
  const c = backend.withAuth();
  assert.equal(c, backend.client);
});

test("backend module exports the expected typed methods", () => {
  for (const m of ["me", "scanDomain", "listReports"]) {
    assert.equal(typeof backend[m], "function", `missing method: ${m}`);
  }
});
