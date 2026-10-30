require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { withDb } = require("./helpers/db");
const { claimDomain, createScheduler } = require("../src/services/watch/scheduler");

const NOW = new Date("2026-10-31T00:00:00Z");
const MIN = 60_000;

async function seedDomains(t, n) {
  const models = await withDb(t);
  const user = await models.User.create({ email: "s@example.com", passwordHash: "x" });
  const domains = [];
  for (let i = 0; i < n; i++) {
    domains.push(
      await models.Domain.create({
        userId: user._id,
        name: `d${i}.example`,
        nextWatchAt: new Date(NOW.getTime() - i * MIN),
      })
    );
  }
  return { ...models, domains };
}

test("claimDomain takes due domains once and re-takes after the 20-minute expiry", async (t) => {
  const { Domain, domains } = await seedDomains(t, 2);
  const first = await claimDomain(NOW);
  const second = await claimDomain(NOW);
  assert.ok(first && second);
  assert.notEqual(String(first._id), String(second._id));
  assert.equal(first.watchingSince.getTime(), NOW.getTime());
  assert.equal(await claimDomain(NOW), null, "both claimed");
  await Domain.updateOne(
    { _id: domains[0]._id },
    { watchingSince: new Date(NOW.getTime() - 21 * MIN) }
  );
  const retaken = await claimDomain(NOW);
  assert.equal(String(retaken._id), String(domains[0]._id));
  await Domain.updateOne(
    { _id: domains[1]._id },
    { watchingSince: new Date(NOW.getTime() - 19 * MIN) }
  );
  assert.equal(await claimDomain(NOW), null, "19 minutes is not expired");
});

test("claimDomain ignores domains that are not due yet", async (t) => {
  const { Domain, domains } = await seedDomains(t, 1);
  await Domain.updateOne({ _id: domains[0]._id }, { nextWatchAt: new Date(NOW.getTime() + MIN) });
  assert.equal(await claimDomain(NOW), null);
});

test("tick runs at most concurrency cycles at once and start/stop are clean", async (t) => {
  await seedDomains(t, 5);
  const running = new Set();
  const finish = new Map();
  const runCycle = (domain) =>
    new Promise((resolve) => {
      running.add(domain.name);
      finish.set(domain.name, () => {
        running.delete(domain.name);
        resolve({ events: 0, sightings: 0, source: "worker" });
      });
    });
  const sched = createScheduler({
    runCycle,
    deps: {},
    concurrency: 2,
    intervalMs: 60 * MIN,
    now: () => NOW,
  });
  assert.equal(await sched.tick(), 2);
  assert.equal(running.size, 2);
  assert.equal(await sched.tick(), 0, "no free slot");
  for (const done of [...finish.values()].slice(0, 2)) done();
  await new Promise((r) => setImmediate(r));
  assert.equal(await sched.tick(), 2);
  assert.equal(running.size, 2);
  for (const done of finish.values()) done();
  await sched.stop();
  assert.equal(running.size, 0);
});
