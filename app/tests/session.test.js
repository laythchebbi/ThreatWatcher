require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { withDb } = require("./helpers/db");
const { getSession, readSession, safeNext } = require("../src/middleware/session");

// Minimal server: /mint seals a session for ?userId&sv ; /who runs readSession and reports req.user.
function serve() {
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://x");
    if (url.pathname === "/mint") {
      const session = await getSession(req, res);
      session.userId = url.searchParams.get("userId");
      session.sv = Number(url.searchParams.get("sv"));
      session.issuedAt = Date.now();
      await session.save();
      res.end("ok");
      return;
    }
    readSession(req, res, () => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ user: req.user ? req.user.email : null }));
    });
  });
  return new Promise((r) => server.listen(0, () => r(server)));
}

test("readSession loads the user and rejects a stale sessionVersion", async (t) => {
  const { User } = await withDb(t);
  const u = await User.create({ email: "s@example.com", passwordHash: "x" });
  const server = await serve();
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  const mint = await fetch(`${base}/mint?userId=${u._id}&sv=1`);
  const cookie = mint.headers.get("set-cookie").split(";")[0];
  const who = await fetch(`${base}/who`, { headers: { cookie } });
  assert.deepEqual(await who.json(), { user: "s@example.com" });
  await User.updateOne({ _id: u._id }, { $inc: { sessionVersion: 1 } });
  const stale = await fetch(`${base}/who`, { headers: { cookie } });
  assert.deepEqual(await stale.json(), { user: null });
  assert.match(stale.headers.get("set-cookie") || "", /tw_session=;|Max-Age=0/);
});

test("safeNext only accepts same-site paths", () => {
  assert.equal(safeNext("/domains"), "/domains");
  assert.equal(safeNext("/domains?x=1#a"), "/domains?x=1#a");
  assert.equal(safeNext("https://evil.example"), "/");
  assert.equal(safeNext("//evil.example"), "/");
  assert.equal(safeNext("/\\evil.example"), "/");
  assert.equal(safeNext(undefined), "/");
  assert.equal(safeNext(["/a"]), "/");
});
