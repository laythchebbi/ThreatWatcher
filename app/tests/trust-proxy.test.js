// TRUST_PROXY=loopback must reach Express's "trust proxy" setting, else the per-IP
// rate limits behind nginx collapse into one bucket for everyone.
process.env.TRUST_PROXY = "loopback";
require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createApp } = require("../src/app");
const { env } = require("../src/config");

test("TRUST_PROXY is parsed and applied to the app", () => {
  assert.equal(env.TRUST_PROXY, "loopback");
  assert.equal(createApp().get("trust proxy"), "loopback");
});
