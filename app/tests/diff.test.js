require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { diffDomain } = require("../src/services/watch/diff");
const { bump, eventSeverity } = require("../src/services/watch/severity");

const now = new Date("2026-10-31T00:00:00Z");
const emptyLists = { parkingNs: new Set(), cdnCidrs: [] };
const base = { domain: { name: "acme-corp.com" }, lists: emptyLists, now, baseline: false };
const obs = (m) => new Map(Object.entries(m));
const live = (a = ["1.1.1.1"], extra = {}) => ({ a, mx: [], ns: ["ns1.example.net"], ...extra });
const prevSighting = (over = {}) => ({
  lookalike: "acme-c0rp.com",
  similarity: 0.86,
  punycode: false,
  substring: true,
  state: "open",
  severity: "medium",
  baseline: false,
  inactive: false,
  dnsMisses: 0,
  dns: { resolves: true, a: ["1.1.1.1"], mx: [], ns: ["ns1.example.net"] },
  infra: { parked: false, cdn: false },
  ...over,
});
const kinds = (events) => events.map((e) => e.kind);

test("bump clamps and eventSeverity applies substring and mx bumps", () => {
  assert.equal(bump("low"), "medium");
  assert.equal(bump("critical"), "critical");
  assert.equal(bump("low", 2), "high");
  const plain = { punycode: false, substring: false, dns: { mx: [] } };
  assert.equal(eventSeverity("dns_live", plain), "medium");
  assert.equal(eventSeverity("dns_live", { ...plain, substring: true }), "high");
  assert.equal(eventSeverity("new_lookalike", { ...plain, dns: { mx: ["mx.x"] } }), "medium");
  assert.equal(eventSeverity("mx_live", { ...plain, dns: { mx: ["mx.x"] } }), "medium");
});

test("new resolving lookalike raises new_lookalike and dns_live; non-resolving low-similarity names are dropped", () => {
  const { upserts, events } = diffDomain({
    ...base,
    previous: [],
    candidates: ["acme-corp-login.com", "totally-different.org"],
    observed: obs({ "acme-corp-login.com": live() }),
  });
  assert.deepEqual(kinds(events), ["new_lookalike", "dns_live"]);
  assert.equal(upserts.length, 1);
  assert.equal(upserts[0].lookalike, "acme-corp-login.com");
  assert.equal(upserts[0].substring, true);
  assert.equal(upserts[0].dns.resolves, true);
  assert.equal(upserts[0].severity, "high", "substring bump: dns_live medium → high");
  assert.equal(upserts[0].firstSeenAt, now);
});

test("a resolving candidate below the similarity threshold is still kept", () => {
  const { upserts } = diffDomain({
    ...base,
    previous: [],
    candidates: ["totally-different.org"],
    observed: obs({ "totally-different.org": live() }),
  });
  assert.equal(upserts.length, 1);
});

test("gone needs two misses", () => {
  const first = diffDomain({
    ...base,
    previous: [prevSighting()],
    candidates: ["acme-c0rp.com"],
    observed: obs({}),
  });
  assert.deepEqual(kinds(first.events), []);
  assert.equal(first.upserts[0].dnsMisses, 1);
  assert.equal(first.upserts[0].inactive, false);
  const second = diffDomain({
    ...base,
    previous: [prevSighting({ dnsMisses: 1 })],
    candidates: ["acme-c0rp.com"],
    observed: obs({}),
  });
  assert.deepEqual(kinds(second.events), ["gone"]);
  assert.equal(second.upserts[0].inactive, true);
  assert.equal(second.upserts[0].dns.resolves, false);
});

test("return re-fires dns_live only on changed A set", () => {
  const inactive = prevSighting({
    inactive: true,
    dnsMisses: 2,
    dns: { resolves: false, a: ["1.1.1.1"], mx: [], ns: [] },
  });
  const same = diffDomain({
    ...base,
    previous: [inactive],
    candidates: ["acme-c0rp.com"],
    observed: obs({ "acme-c0rp.com": live(["1.1.1.1"], { ns: [] }) }),
  });
  assert.deepEqual(kinds(same.events), []);
  assert.equal(same.upserts[0].inactive, false);
  assert.equal(same.upserts[0].dnsMisses, 0);
  const changed = diffDomain({
    ...base,
    previous: [inactive],
    candidates: ["acme-c0rp.com"],
    observed: obs({ "acme-c0rp.com": live(["2.2.2.2"], { ns: [] }) }),
  });
  assert.deepEqual(kinds(changed.events), ["dns_live"]);
});

test("mx present bumps later events and raises mx_live once", () => {
  const withMx = live(["1.1.1.1"], { mx: ["mx.acme-c0rp.com"] });
  const first = diffDomain({
    ...base,
    previous: [],
    candidates: ["acme-corp-login.com"],
    observed: obs({ "acme-corp-login.com": withMx }),
  });
  assert.deepEqual(kinds(first.events), ["new_lookalike", "dns_live", "mx_live"]);
  const sev = Object.fromEntries(first.events.map((e) => [e.kind, e.severity]));
  assert.equal(sev.new_lookalike, "high", "low + substring + mx");
  assert.equal(sev.dns_live, "critical", "medium + substring + mx");
  assert.equal(sev.mx_live, "high", "medium + substring, no mx self-bump");
  const again = diffDomain({
    ...base,
    previous: [{ ...first.upserts[0] }],
    candidates: ["acme-corp-login.com"],
    observed: obs({ "acme-corp-login.com": withMx }),
  });
  assert.deepEqual(kinds(again.events), []);
});

test("infra_changed names what changed", () => {
  const prev = prevSighting();
  const { events } = diffDomain({
    ...base,
    previous: [prev],
    candidates: ["acme-c0rp.com"],
    observed: obs({ "acme-c0rp.com": live(["1.1.1.1"], { ns: ["ns1.parkingcrew.net"] }) }),
  });
  assert.deepEqual(kinds(events), ["infra_changed"]);
  assert.deepEqual(events[0].payload.changed, ["ns"]);
});

test("dismissed sighting re-raises only above dismissedAtSeverity", () => {
  const dismissed = prevSighting({
    state: "dismissed",
    dismissedAtSeverity: "high",
    substring: false,
    severity: "medium",
  });
  const quiet = diffDomain({
    ...base,
    previous: [dismissed],
    candidates: ["acme-c0rp.com"],
    observed: obs({ "acme-c0rp.com": live(["3.3.3.3"]) }),
  });
  assert.deepEqual(kinds(quiet.events), [], "infra_changed medium ≤ high stays silent");
  assert.equal(quiet.upserts[0].state, "dismissed");
  const loud = diffDomain({
    ...base,
    previous: [{ ...dismissed, dns: { ...dismissed.dns, mx: ["mx.x"] } }],
    candidates: ["acme-c0rp.com"],
    observed: obs({ "acme-c0rp.com": live(["3.3.3.3"], { mx: ["mx.x"] }) }),
  });
  assert.deepEqual(kinds(loud.events), [], "medium + mx = high, still not above high");
  const critical = diffDomain({
    ...base,
    previous: [{ ...dismissed, substring: true, dns: { ...dismissed.dns, mx: ["mx.x"] } }],
    candidates: ["acme-c0rp.com"],
    observed: obs({ "acme-c0rp.com": live(["3.3.3.3"], { mx: ["mx.x"] }) }),
  });
  assert.deepEqual(kinds(critical.events), ["infra_changed"]);
  assert.equal(critical.events[0].severity, "critical");
  assert.equal(critical.upserts[0].state, "open", "re-opened");
});

test("ignored sighting never raises", () => {
  const ignored = prevSighting({ state: "ignored" });
  const { upserts, events } = diffDomain({
    ...base,
    previous: [ignored],
    candidates: ["acme-c0rp.com"],
    observed: obs({ "acme-c0rp.com": live(["9.9.9.9"], { mx: ["mx.x"] }) }),
  });
  assert.deepEqual(kinds(events), []);
  assert.equal(upserts[0].state, "ignored");
  assert.equal(upserts[0].lastSeenAt, now);
});

test("parked lookalike events are low", () => {
  const lists = { parkingNs: new Set(["parkingcrew.net"]), cdnCidrs: [] };
  const { upserts, events } = diffDomain({
    ...base,
    lists,
    previous: [],
    candidates: ["acme-c0rp.com"],
    observed: obs({ "acme-c0rp.com": live(["1.1.1.1"], { ns: ["ns1.parkingcrew.net"] }) }),
  });
  assert.equal(upserts[0].infra.parked, true);
  assert.ok(
    events.every((e) => e.severity === "low"),
    JSON.stringify(events)
  );
});

test("baseline cycle tags events and sightings", () => {
  const { upserts, events } = diffDomain({
    ...base,
    baseline: true,
    previous: [],
    candidates: ["acme-c0rp.com"],
    observed: obs({ "acme-c0rp.com": live() }),
  });
  assert.ok(events.length > 0);
  assert.ok(events.every((e) => e.payload.baseline === true));
  assert.equal(upserts[0].baseline, true);
});

test("gone needs two CONSECUTIVE misses: miss, hit, miss stays active", () => {
  const afterMiss = prevSighting({ dnsMisses: 1 });
  const hit = diffDomain({
    ...base,
    previous: [afterMiss],
    candidates: ["acme-c0rp.com"],
    observed: obs({ "acme-c0rp.com": live() }),
  });
  assert.equal(hit.upserts[0].dnsMisses, 0, "a hit resets the miss counter");
  const missAgain = diffDomain({
    ...base,
    previous: [hit.upserts[0]],
    candidates: ["acme-c0rp.com"],
    observed: obs({}),
  });
  assert.deepEqual(kinds(missAgain.events), []);
  assert.equal(missAgain.upserts[0].inactive, false);
});
