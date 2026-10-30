require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { hashPassword, verifyPassword, DUMMY_HASH } = require("../src/services/password");

test("hash round-trips and encodes params", async () => {
  const h = await hashPassword("correct horse");
  assert.match(h, /^scrypt\$16384\$8\$1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
  assert.equal(await verifyPassword("correct horse", h), true);
  assert.equal(await verifyPassword("wrong", h), false);
});

test("DUMMY_HASH is a valid hash that matches nothing", async () => {
  const d = await DUMMY_HASH;
  assert.match(d, /^scrypt\$/);
  assert.equal(await verifyPassword("", d), false);
});

test("malformed stored hash verifies false, never throws", async () => {
  assert.equal(await verifyPassword("x", "garbage"), false);
});
