// Boot the real app on a random port with a tiny cookie jar around fetch.
require("./env");
const { createApp } = require("../../src/app");

async function startApp(t) {
  const server = createApp().listen(0);
  await new Promise((r) => server.once("listening", r));
  t.after(() => new Promise((r) => server.close(r)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const jar = new Map();
  async function fetchWithCookies(path, init = {}) {
    const headers = { ...(init.headers || {}) };
    if (jar.size) headers.cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    const res = await fetch(base + path, { redirect: "manual", ...init, headers });
    for (const line of res.headers.getSetCookie?.() || []) {
      const [pair, ...attrs] = line.split(";");
      const [k, v] = pair.split("=");
      const expired = attrs.some((a) => /max-age=0/i.test(a.trim()));
      if (expired || v === "") jar.delete(k.trim());
      else jar.set(k.trim(), v);
    }
    return res;
  }
  fetchWithCookies.jar = jar;
  const form = (obj) =>
    Object.entries(obj)
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
      .join("&");
  const post = (path, body, extra = {}) =>
    fetchWithCookies(path, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", ...(extra.headers || {}) },
      body: form(body),
    });
  return { base, fetchWithCookies, post };
}

module.exports = { startApp };
