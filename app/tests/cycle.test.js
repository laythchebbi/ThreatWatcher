require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { withDb } = require("./helpers/db");
const { runCycle } = require("../src/services/watch/cycle");

const NOW = new Date("2026-10-31T00:00:00Z");
const emptyLists = { parkingNs: new Set(), cdnCidrs: [] };

function stubResolver(table) {
  return {
    resolve4: async (name) => {
      if (name in table) return table[name];
      throw new Error("ENOTFOUND");
    },
    resolveMx: async () => [],
    resolveNs: async () => [],
  };
}

const deps = (over = {}) => ({
  worker: { permute: async () => ["acme-c0rp.com", "acme-corp-login.com"] },
  resolver: stubResolver({ "acme-c0rp.com": ["1.1.1.1"] }),
  fetchImpl: async () => {
    throw new Error("no network in tests");
  },
  lists: emptyLists,
  now: NOW,
  random: () => Buffer.alloc(32, 1),
  ...over,
});

async function seed(t) {
  const models = await withDb(t);
  const user = await models.User.create({ email: "c@example.com", passwordHash: "x" });
  const domain = await models.Domain.create({ userId: user._id, name: "acme-corp.com" });
  return { ...models, user, domain };
}

test("first cycle is a baseline and schedules the next watch with jitter", async (t) => {
  const { Domain, Sighting, Event, domain } = await seed(t);
  const out = await runCycle(domain, deps());
  assert.equal(out.source, "worker");
  const d = await Domain.findById(domain._id);
  assert.ok(d.baselineDoneAt);
  assert.equal(d.lastWatchedAt.getTime(), NOW.getTime());
  assert.equal(d.watchingSince, null);
  const dt = (d.nextWatchAt - NOW) / 60000;
  assert.ok(dt >= 345 && dt <= 375, `next watch in ${dt} min`);
  assert.ok(d.lastPermutation.includes("acme-c0rp.com"));
  const events = await Event.find({ domainId: domain._id });
  assert.ok(events.length > 0);
  assert.ok(events.every((e) => e.payload.baseline === true));
  assert.ok(events.every((e) => String(e.userId) === String(domain.userId) && e.sightingId));
  assert.equal(await Sighting.countDocuments({ domainId: domain._id, "dns.resolves": true }), 1);
  assert.equal(
    await Sighting.countDocuments({ domainId: domain._id, baseline: true }),
    await Sighting.countDocuments({ domainId: domain._id })
  );
});

test("second cycle with the same observations raises no events", async (t) => {
  const { Event, Domain, domain } = await seed(t);
  await runCycle(domain, deps());
  const before = await Event.countDocuments({ domainId: domain._id });
  const d = await Domain.findById(domain._id);
  await runCycle(d, deps({ now: new Date(NOW.getTime() + 6 * 3600_000) }));
  assert.equal(await Event.countDocuments({ domainId: domain._id }), before);
  const events = await Event.find({ domainId: domain._id });
  assert.ok(
    events.every((e) => e.payload.baseline === true),
    "still only baseline events"
  );
});

test("a new resolving lookalike on a later cycle raises a non-baseline event", async (t) => {
  const { Event, Domain, domain } = await seed(t);
  await runCycle(domain, deps());
  const d = await Domain.findById(domain._id);
  await runCycle(
    d,
    deps({
      resolver: stubResolver({ "acme-c0rp.com": ["1.1.1.1"], "acme-corp-login.com": ["5.5.5.5"] }),
      now: new Date(NOW.getTime() + 6 * 3600_000),
    })
  );
  const fresh = await Event.find({
    domainId: domain._id,
    "payload.lookalike": "acme-corp-login.com",
  }).sort({ at: 1 });
  // Known since the baseline (similarity 0.73, not resolving); coming alive is one dns_live.
  assert.deepEqual(
    fresh.map((e) => e.kind),
    ["new_lookalike", "dns_live"]
  );
  assert.equal(fresh.find((e) => e.kind === "new_lookalike").payload.baseline, true);
  assert.equal(fresh.find((e) => e.kind === "dns_live").payload.baseline, undefined);
});

test("a resolver that throws still advances nextWatchAt and clears the claim", async (t) => {
  const { Domain, domain } = await seed(t);
  await Domain.updateOne({ _id: domain._id }, { watchingSince: NOW });
  const broken = {
    resolve4: async () => {
      throw new Error("resolver exploded");
    },
  };
  await runCycle(await Domain.findById(domain._id), deps({ resolver: broken }));
  const d = await Domain.findById(domain._id);
  assert.ok(d.nextWatchAt > NOW);
  assert.equal(d.watchingSince, null);
});

test("when permutations come from the stored list, lastPermutation is not overwritten", async (t) => {
  const { Domain, domain } = await seed(t);
  await Domain.updateOne({ _id: domain._id }, { lastPermutation: ["acme-c0rp.com"] });
  const failing = {
    permute: async () => {
      throw new Error("down");
    },
  };
  const out = await runCycle(await Domain.findById(domain._id), deps({ worker: failing }));
  assert.equal(out.source, "previous");
  assert.deepEqual((await Domain.findById(domain._id)).lastPermutation, ["acme-c0rp.com"]);
});
