require("./helpers/env");
const { test, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const { withDb } = require("./helpers/db");
const { startApp } = require("./helpers/http");
const mailer = require("../src/lib/mailer");
const { rateLimit } = require("../src/middleware/rate-limit");

const PW = "correct horse battery";

beforeEach(() => {
  mailer._reset();
  rateLimit._reset();
});

test("signup normalises email, logs in, and sets a session cookie", async (t) => {
  const { User } = await withDb(t);
  const { post, fetchWithCookies } = await startApp(t);
  const res = await post("/signup", { email: "  A@Example.com ", password: PW });
  assert.equal(res.status, 302);
  assert.equal(res.headers.get("location"), "/domains");
  assert.ok(fetchWithCookies.jar.has("tw_session"));
  const u = await User.findOne({ email: "a@example.com" });
  assert.ok(u, "user stored lowercase");
  assert.equal(mailer.outbox[0].to, "a@example.com");
  assert.match(mailer.outbox[0].text, /\/verify\//);
});

test("login with unknown email and wrong password give the same response", async (t) => {
  await withDb(t);
  const { post, fetchWithCookies } = await startApp(t);
  await post("/signup", { email: "b@example.com", password: PW });
  fetchWithCookies.jar.clear();
  const unknown = await post("/login", { email: "nobody@example.com", password: PW });
  const wrong = await post("/login", { email: "b@example.com", password: "nope nope nope" });
  assert.equal(unknown.status, 200);
  assert.equal(wrong.status, 200);
  assert.equal(await unknown.text(), await wrong.text());
  assert.equal(fetchWithCookies.jar.has("tw_session"), false);
});

test("password reset is single use and invalidates old sessions", async (t) => {
  await withDb(t);
  const { post, fetchWithCookies } = await startApp(t);
  await post("/signup", { email: "c@example.com", password: PW });
  const before = await fetchWithCookies("/");
  assert.equal(before.status, 200, "signed in after signup");
  const forgot = await post("/forgot", { email: "c@example.com" });
  assert.equal(forgot.status, 200);
  const mail = mailer.outbox.find((m) => /\/reset\//.test(m.text));
  const token = mail.text.match(/\/reset\/([A-Za-z0-9_-]+)/)[1];
  const first = await post(`/reset/${token}`, { password: "new password here 1" });
  assert.equal(first.status, 302);
  assert.equal(first.headers.get("location"), "/login");
  const second = await post(`/reset/${token}`, { password: "new password here 2" });
  assert.equal(second.status, 400);
  const after = await fetchWithCookies("/");
  assert.equal(after.status, 302, "old session revoked");
  assert.match(after.headers.get("location"), /^\/login/);
});

test("forgot for an unknown address answers the same and sends nothing", async (t) => {
  await withDb(t);
  const { post } = await startApp(t);
  const res = await post("/forgot", { email: "ghost@example.com" });
  assert.equal(res.status, 200);
  assert.match(await res.text(), /If that address exists/);
  assert.equal(mailer.outbox.length, 0);
});

test("signup is rate limited per IP", async (t) => {
  await withDb(t);
  const { post } = await startApp(t);
  let last;
  for (let i = 0; i < 6; i++)
    last = await post("/signup", { email: `r${i}@example.com`, password: PW });
  assert.equal(last.status, 429);
});

test("verify link marks the account verified once", async (t) => {
  const { User } = await withDb(t);
  const { post, fetchWithCookies } = await startApp(t);
  await post("/signup", { email: "v@example.com", password: PW });
  const token = mailer.outbox[0].text.match(/\/verify\/([A-Za-z0-9_-]+)/)[1];
  const ok = await fetchWithCookies(`/verify/${token}`);
  assert.equal(ok.status, 302);
  assert.ok((await User.findOne({ email: "v@example.com" })).emailVerifiedAt);
  const again = await fetchWithCookies(`/verify/${token}`);
  assert.equal(again.status, 400);
});

test("signup with a taken email looks exactly like a fresh signup and warns the owner", async (t) => {
  await withDb(t);
  const { post, fetchWithCookies } = await startApp(t);
  const fresh = await post("/signup", { email: "taken@example.com", password: PW });
  fetchWithCookies.jar.clear();
  mailer._reset();
  const again = await post("/signup", {
    email: "taken@example.com",
    password: "another password here",
  });
  assert.equal(again.status, fresh.status);
  assert.equal(again.headers.get("location"), fresh.headers.get("location"));
  assert.equal(fetchWithCookies.jar.has("tw_session"), false, "no session for the impostor");
  assert.equal(mailer.outbox.length, 1);
  assert.equal(mailer.outbox[0].to, "taken@example.com");
  assert.match(mailer.outbox[0].text, /already has an account/i);
});
