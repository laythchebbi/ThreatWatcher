require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");

test("config loads with defaults", () => {
  const { env, isTest } = require("../src/config");
  assert.equal(isTest, true);
  assert.equal(env.PORT, 3000);
  assert.equal(env.PYTHON_BIN, "python3");
  assert.equal(env.WATCH_INTERVAL_HOURS, 6);
  assert.equal(env.WATCH_CONCURRENCY, 3);
  assert.equal(env.MAX_DOMAINS_PER_ACCOUNT, 5);
  assert.equal(env.SESSION_COOKIE_NAME, "tw_session");
});
