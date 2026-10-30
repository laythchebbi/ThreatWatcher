require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { withDb } = require("./helpers/db");

test("domain names are unique per user and sightings unique per domain", async (t) => {
  const { User, Domain, Sighting } = await withDb(t);
  const u = await User.create({ email: "A@Example.com", passwordHash: "x" });
  assert.equal(u.email, "a@example.com");
  assert.equal(u.sessionVersion, 1);
  const d = await Domain.create({ userId: u._id, name: "Acme-Corp.com" });
  assert.equal(d.name, "acme-corp.com");
  assert.ok(d.nextWatchAt instanceof Date);
  await assert.rejects(Domain.create({ userId: u._id, name: "acme-corp.com" }), /E11000/);
  await Sighting.create({ userId: u._id, domainId: d._id, lookalike: "acme-c0rp.com" });
  await assert.rejects(
    Sighting.create({ userId: u._id, domainId: d._id, lookalike: "acme-c0rp.com" }),
    /E11000/
  );
});

test("event and sighting defaults", async (t) => {
  const { User, Domain, Sighting, Event } = await withDb(t);
  const u = await User.create({ email: "b@example.com", passwordHash: "x" });
  const d = await Domain.create({ userId: u._id, name: "b.com" });
  const s = await Sighting.create({ userId: u._id, domainId: d._id, lookalike: "b.co" });
  assert.equal(s.state, "open");
  assert.equal(s.dnsMisses, 0);
  const e = await Event.create({
    userId: u._id,
    domainId: d._id,
    sightingId: s._id,
    kind: "new_lookalike",
    severity: "low",
    at: new Date(),
  });
  assert.equal(e.alertedAt, undefined);
});
