require("./helpers/env");
const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { fetchPage, fetchPages, isPrivateIp } = require("../src/services/watch/http");

const login = fs.readFileSync(path.join(__dirname, "fixtures/page-login.html"), "utf8");
const marketing = fs.readFileSync(path.join(__dirname, "fixtures/page-marketing.html"), "utf8");

let server;
let port;
before(async () => {
  server = http.createServer((req, res) => {
    if (req.url === "/redir-private") {
      res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" });
      return res.end();
    }
    if (req.url === "/redir-login") {
      res.writeHead(302, { location: `http://login.local:${port}/login` });
      return res.end();
    }
    if (req.url === "/big") {
      res.writeHead(200, { "content-type": "text/html" });
      res.write("<html><title>big</title><body>");
      for (let i = 0; i < 2000; i++) res.write("x".repeat(512) + "\n");
      return res.end("</body></html>");
    }
    res.writeHead(200, {
      "content-type": "text/html",
      server: "nginx",
      "set-cookie": "sid=1; Path=/",
    });
    res.end(req.url.startsWith("/login") ? login : marketing);
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
});
after(() => server.close());

// Every test host resolves to the local server; allowPrivate lets the guard pass for 127.0.0.1 only.
// localFetch sends any *.local URL to the local server, keeping the path.
const resolver = { resolve4: async () => ["127.0.0.1"], resolve6: async () => [] };
const localFetch = (url, init) =>
  fetch(String(url).replace(/^http:\/\/[a-z0-9.-]+\.local:\d+/, `http://127.0.0.1:${port}`), init);
const deps = (over = {}) => ({
  fetchImpl: localFetch,
  resolver,
  brandTerms: ["acme-corp", "acme corp"],
  allowPrivate: true,
  port,
  insecure: true,
  ...over,
});

test("isPrivateIp table", () => {
  for (const ip of [
    "127.0.0.1",
    "10.1.2.3",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "0.0.0.0",
    "::1",
    "fd00::1",
    "fe80::1",
    "ff02::1",
  ])
    assert.equal(isPrivateIp(ip), true, ip);
  for (const ip of ["8.8.8.8", "203.0.113.9", "2606:4700::1111"])
    assert.equal(isPrivateIp(ip), false, ip);
});

test("detects a password form with the brand term", async () => {
  const facts = await fetchPage("login.local", deps({ path: "/login" }));
  assert.equal(facts.status, 200);
  assert.equal(facts.title, "ACME Corp — Sign in");
  assert.equal(facts.hasPasswordForm, true);
  assert.equal(facts.brandTermFound, true);
  assert.equal(facts.headers.server, "nginx");
  assert.ok(!facts.visibleText.includes("hidden text"), "display:none dropped");
  assert.ok(!facts.visibleText.includes("not visible"), "scripts dropped");
  assert.equal(facts.finalHost, "login.local");
});

test("marketing page is not a login", async () => {
  const facts = await fetchPage("parked.local", deps());
  assert.equal(facts.hasPasswordForm, false);
  assert.equal(facts.brandTermFound, false);
});

test("refuses private targets after a redirect", async () => {
  const facts = await fetchPage(
    "parked.local",
    deps({
      path: "/redir-private",
      allowPrivate: false,
      resolver: {
        resolve4: async (h) => (h === "parked.local" ? ["8.8.8.8"] : ["169.254.169.254"]),
        resolve6: async () => [],
      },
    })
  );
  assert.equal(facts.error, "private_target");
  assert.deepEqual(facts.redirects, ["169.254.169.254"]);
});

test("follows a same-site redirect and records the hop", async () => {
  const facts = await fetchPage("parked.local", deps({ path: "/redir-login" }));
  assert.equal(facts.finalHost, "login.local");
  assert.deepEqual(facts.redirects, ["login.local"]);
  assert.equal(facts.hasPasswordForm, true);
});

test("stops reading after 256 KB", async () => {
  const facts = await fetchPage("parked.local", deps({ path: "/big" }));
  assert.equal(facts.status, 200);
  assert.ok(facts.visibleText.length <= 256 * 1024);
  assert.equal(facts.truncated, true);
});

test("similarity against reference text is stored", async () => {
  const facts = await fetchPage(
    "login.local",
    deps({ path: "/login", referenceText: "Welcome back to ACME Corp Sign in Help" })
  );
  assert.ok(facts.similarity > 0.5, String(facts.similarity));
});

test("fetchPages bounds concurrency and respects limit", async () => {
  const names = Array.from({ length: 12 }, (_, i) => `s${i}.local`);
  const out = await fetchPages(
    names.map((n) => ({ lookalike: n, similarity: 0.9 })),
    deps(),
    { concurrency: 3, limit: 5 }
  );
  assert.equal(out.size, 5);
});

test("fetchCertificate reads fingerprints from the peer certificate", async () => {
  const { fetchCertificate } = require("../src/services/watch/http");
  const EventEmitter = require("node:events");
  const connect = (opts, onSecure) => {
    const sock = new EventEmitter();
    sock.getPeerCertificate = () => ({
      fingerprint256: "AB:CD",
      pubkey: Buffer.from("key"),
      issuer: { O: "Let's Encrypt", CN: "R11" },
      valid_from: "Oct 20 00:00:00 2026 GMT",
    });
    sock.end = () => {};
    sock.setTimeout = () => {};
    setImmediate(onSecure);
    return sock;
  };
  const cert = await fetchCertificate("login.local", { connect });
  assert.equal(cert.fingerprint256, "AB:CD");
  assert.match(cert.spki, /^[0-9a-f]{64}$/);
  assert.equal(cert.issuer, "Let's Encrypt R11");
  assert.ok(cert.notBefore instanceof Date);
});
