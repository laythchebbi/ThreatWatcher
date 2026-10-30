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
