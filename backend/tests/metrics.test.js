const { test } = require("node:test");
const assert = require("node:assert/strict");

process.env.MONGODB_URI ||= "mongodb://localhost:27017/threatwatcher-test";
process.env.WORKOS_API_KEY ||= "sk_test_unit";
process.env.WORKOS_CLIENT_ID ||= "client_unit";
process.env.WORKOS_ORGANIZATION_ID ||= "org_unit";

const {
  registry,
  httpDuration,
  mlClassifications,
  httpMetricsMiddleware,
} = require("../src/services/metrics");

test("default metrics are registered with the expected prefix", async () => {
  const text = await registry.metrics();
  assert.match(text, /threatwatcher_backend_process_cpu_user_seconds_total/);
});

test("httpDuration observes do not throw", () => {
  httpDuration.observe({ method: "GET", route: "/x", status: "200" }, 0.05);
  mlClassifications.inc({ worker: "url", outcome: "ok" });
  assert.ok(true);
});

test("httpMetricsMiddleware finalizes on res.finish", () => {
  const handlers = {};
  const req = { method: "GET", path: "/y" };
  const res = {
    statusCode: 200,
    on(evt, fn) {
      handlers[evt] = fn;
    },
  };
  httpMetricsMiddleware(req, res, () => {});
  handlers.finish();
  assert.ok(true);
});
