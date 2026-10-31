// SMTP_URL set before Plan 3 must not break sign-up: the mailer stays log-only.
process.env.SMTP_URL = "smtp://user:pass@mail.example:587";
require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const mailer = require("../src/lib/mailer");

test("with SMTP_URL set the mailer still resolves and keeps the message", async () => {
  await mailer.send({ to: "a@example.com", subject: "s", text: "body" });
  assert.equal(mailer.outbox.length, 1);
});
