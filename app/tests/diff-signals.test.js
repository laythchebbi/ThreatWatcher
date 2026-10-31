require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { diffDomain } = require("../src/services/watch/diff");
const { eventSeverity } = require("../src/services/watch/severity");

const now = new Date("2026-10-31T00:00:00Z");
const day = (n) => new Date(now.getTime() + n * 86400_000);
const emptyLists = { parkingNs: new Set(), cdnCidrs: [] };
const base = {
  domain: { name: "acme-corp.com" },
  lists: emptyLists,
  now,
  baseline: false,
  previous: [],
  candidates: [],
  observed: new Map(),
  certs: new Map(),
  pages: new Map(),
  rdap: new Map(),
  ownRdap: null,
};
const kinds = (events) => events.map((e) => e.kind);
const sev = (events, kind) => events.find((e) => e.kind === kind)?.severity;
const live = (a = ["1.1.1.1"]) => ({ a, mx: [], ns: ["ns1.example.net"] });
const cert = (over = {}) => ({
  firstIssuedAt: day(-1),
  notBefore: day(-1),
  issuer: "Let's Encrypt",
  tbs: "aaa",
  lastSeenAt: now,
  ...over,
});
const page = (over = {}) => ({
  status: 200,
  title: "Sign in",
  finalHost: "acme-corp-login.com",
  redirects: [],
  headers: {},
  hasPasswordForm: false,
  brandTermFound: false,
  visibleText: "should not be stored",
  similarity: 0.2,
  fetchedAt: now,
  ...over,
});

test("severity ladder for the new kinds", () => {
  const s = { punycode: false, substring: false, dns: { resolves: false, mx: [] } };
  assert.equal(eventSeverity("cert_issued", s), "medium");
  assert.equal(eventSeverity("cert_issued", { ...s, dns: { resolves: true, mx: [] } }), "high");
  assert.equal(eventSeverity("cert_issued", { ...s, substring: true }), "high");
  assert.equal(
    eventSeverity("cert_issued", { ...s, substring: true, dns: { resolves: true, mx: ["m"] } }),
    "high",
    "no mx bump on cert_issued"
  );
  assert.equal(eventSeverity("page_live", s), "high");
  assert.equal(eventSeverity("page_mimics_login", s), "critical");
  assert.equal(eventSeverity("posture_weak", s), "low");
  assert.equal(eventSeverity("leak_mention", s), "medium");
});

test("certificate before DNS creates a sighting with cert_issued", () => {
  const { upserts, events } = diffDomain({
    ...base,
    certs: new Map([["acme-corp-login.com", cert()]]),
  });
  assert.equal(upserts.length, 1);
  assert.equal(upserts[0].dns.resolves, false);
  assert.deepEqual(kinds(events), ["new_lookalike", "cert_issued"]);
  assert.equal(sev(events, "cert_issued"), "high", "substring bump");
  assert.equal(upserts[0].cert.firstIssuedAt.getTime(), cert().firstIssuedAt.getTime());
  assert.equal(upserts[0].cert.tbs, "aaa");
  assert.ok(!("visibleText" in upserts[0]));
});

test("cert renewal is silent", () => {
  const prev = {
    lookalike: "acme-corp-login.com",
    similarity: 0.73,
    punycode: false,
    substring: true,
    state: "open",
    severity: "high",
    baseline: false,
    inactive: false,
    dnsMisses: 0,
    dns: { resolves: false, a: [], mx: [], ns: [] },
    infra: { parked: false, cdn: false },
    firstSeenAt: day(-60),
    cert: {
      firstIssuedAt: day(-60),
      notBefore: day(-60),
      issuer: "Let's Encrypt",
      tbs: "old",
      lastSeenAt: day(-60),
    },
  };
  const renewed = cert({ firstIssuedAt: day(-60), notBefore: day(-1), tbs: "new" });
  const { upserts, events } = diffDomain({
    ...base,
    previous: [prev],
    certs: new Map([["acme-corp-login.com", renewed]]),
  });
  assert.deepEqual(kinds(events), []);
  assert.equal(upserts[0].cert.tbs, "new");
  assert.equal(upserts[0].cert.notBefore.getTime(), day(-1).getTime());
  assert.equal(upserts[0].cert.firstIssuedAt.getTime(), day(-60).getTime(), "first issuance kept");
});

test("old certificate on baseline records without event; fresh one still alerts", () => {
  const old = cert({ firstIssuedAt: day(-400), notBefore: day(-400) });
  const quiet = diffDomain({
    ...base,
    baseline: true,
    certs: new Map([["acme-corp-login.com", old]]),
  });
  assert.deepEqual(kinds(quiet.events), ["new_lookalike"]);
  assert.equal(quiet.upserts[0].cert.tbs, "aaa", "recorded");
  const fresh = diffDomain({
    ...base,
    baseline: true,
    certs: new Map([["acme-corp-login.com", cert()]]),
  });
  assert.deepEqual(kinds(fresh.events), ["new_lookalike", "cert_issued"]);
  assert.equal(fresh.events.find((e) => e.kind === "new_lookalike").payload.baseline, true);
  assert.equal(
    fresh.events.find((e) => e.kind === "cert_issued").payload.baseline,
    undefined,
    "post-baseline cert is not tagged"
  );
});

test("page_live then page_mimics_login across two cycles", () => {
  const first = diffDomain({
    ...base,
    candidates: ["acme-corp-login.com"],
    observed: new Map([["acme-corp-login.com", live()]]),
    pages: new Map([["acme-corp-login.com", page()]]),
  });
  assert.deepEqual(kinds(first.events), ["new_lookalike", "dns_live", "page_live"]);
  assert.equal(first.upserts[0].http.title, "Sign in");
  assert.ok(!first.upserts[0].http.visibleText);
  const second = diffDomain({
    ...base,
    previous: [first.upserts[0]],
    candidates: ["acme-corp-login.com"],
    observed: new Map([["acme-corp-login.com", live()]]),
    pages: new Map([
      ["acme-corp-login.com", page({ hasPasswordForm: true, brandTermFound: true })],
    ]),
  });
  assert.deepEqual(kinds(second.events), ["page_mimics_login"]);
  assert.equal(second.events[0].severity, "critical");
  const third = diffDomain({
    ...base,
    previous: [second.upserts[0]],
    candidates: ["acme-corp-login.com"],
    observed: new Map([["acme-corp-login.com", live()]]),
    pages: new Map([
      ["acme-corp-login.com", page({ hasPasswordForm: true, brandTermFound: true })],
    ]),
  });
  assert.deepEqual(kinds(third.events), [], "mimics_login fires once");
});

test("on a baseline cycle page_live is tagged but page_mimics_login is not", () => {
  const { events } = diffDomain({
    ...base,
    baseline: true,
    candidates: ["acme-corp-login.com"],
    observed: new Map([["acme-corp-login.com", live()]]),
    pages: new Map([
      ["acme-corp-login.com", page({ hasPasswordForm: true, brandTermFound: true })],
    ]),
  });
  assert.equal(events.find((e) => e.kind === "page_live").payload.baseline, true);
  assert.equal(events.find((e) => e.kind === "page_mimics_login").payload.baseline, undefined);
});

test("defensive registration is ignored, stale registration stays low", () => {
  const own = { registrar: "NameCheap, Inc.", ns: ["dns1.registrar-servers.com"] };
  const defensive = diffDomain({
    ...base,
    ownRdap: own,
    candidates: ["acme-corp-login.com"],
    observed: new Map([["acme-corp-login.com", live()]]),
    rdap: new Map([
      [
        "acme-corp-login.com",
        { registeredAt: day(-3), registrar: "NameCheap, Inc.", ns: ["dns1.registrar-servers.com"] },
      ],
    ]),
  });
  assert.deepEqual(kinds(defensive.events), []);
  assert.equal(defensive.upserts[0].state, "ignored");
  assert.equal(defensive.upserts[0].rdap.defensive, true);
  const stale = diffDomain({
    ...base,
    candidates: ["acme-corp-login.com"],
    observed: new Map([["acme-corp-login.com", live()]]),
    rdap: new Map([
      [
        "acme-corp-login.com",
        { registeredAt: day(-900), registrar: "GoDaddy", ns: ["ns1.other.net"] },
      ],
    ]),
  });
  assert.ok(
    stale.events.every((e) => e.severity === "low"),
    JSON.stringify(stale.events)
  );
  assert.equal(stale.events.find((e) => e.kind === "new_lookalike").payload.stale, true);
  assert.equal(stale.upserts[0].rdap.registrar, "GoDaddy");
});
