require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createApp } = require("../src/app");

test("GET /health is 200 and unknown routes are 404 json", async () => {
  const server = createApp().listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const ok = await fetch(`${base}/health`);
    assert.equal(ok.status, 200);
    assert.deepEqual(await ok.json(), { ok: true });
    const nf = await fetch(`${base}/nope`, { headers: { accept: "application/json" } });
    assert.equal(nf.status, 404);
    assert.equal((await nf.json()).error, "not_found");
  } finally {
    server.close();
  }
});

// Under Referrer-Policy: no-referrer, browsers send `Origin: null` on same-origin form
// POSTs (Fetch spec), and the origin check rejects every form. Keep a policy that
// sends our own origin back to us.
test("Referrer-Policy lets browsers send our origin on form posts", async () => {
  const server = createApp().listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const res = await fetch(`${base}/health`);
    assert.equal(res.headers.get("referrer-policy"), "same-origin");
  } finally {
    server.close();
  }
});
