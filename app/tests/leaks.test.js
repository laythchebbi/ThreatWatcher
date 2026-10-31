require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { withDb } = require("./helpers/db");
const {
  termRegex,
  matchPage,
  mentionSeverity,
  diffMentions,
  runLeaks,
  leakSources,
} = require("../src/services/watch/leaks");

const now = new Date("2026-10-31T00:00:00Z");

test("term matching is whole-word and hyphen/space tolerant", () => {
  const re = termRegex("acme-corp");
  assert.equal(re.test("Fresh ACME Corp combolist"), true);
  assert.equal(re.test("acme-corp.com creds"), true);
  assert.equal(re.test("acmes corp"), false);
  assert.equal(re.test("acme-corporation leak"), false);
  assert.equal(termRegex("acme").test("acmes"), false);
});

test("matchPage returns an excerpt around the first hit with matched terms", () => {
  const body = "x".repeat(300) + " Selling ACME Corp VPN access, DM for price " + "y".repeat(300);
  const m = matchPage({ title: "Market", body }, ["acme-corp", "zebra"], "acme-corp.com");
  assert.deepEqual(m.matchedTerms, ["acme-corp"]);
  assert.ok(m.excerpt.length <= 420, String(m.excerpt.length));
  assert.ok(/ACME Corp VPN/.test(m.excerpt));
  assert.equal(
    matchPage({ title: "nothing", body: "nothing" }, ["acme-corp"], "acme-corp.com"),
    null
  );
});

test("severity: label-only medium, customer term high, email or domain critical, keyword bumps one level only", () => {
  const ctx = { domainName: "acme-corp.com", autoLabel: "acme-corp", customerTerms: ["acme bank"] };
  assert.equal(
    mentionSeverity({ matchedTerms: ["acme-corp"], excerpt: "acme corp mention", ...ctx }),
    "medium"
  );
  assert.equal(
    mentionSeverity({ matchedTerms: ["acme bank"], excerpt: "acme bank mention", ...ctx }),
    "high"
  );
  assert.equal(
    mentionSeverity({ matchedTerms: ["acme-corp"], excerpt: "login: bob@acme-corp.com", ...ctx }),
    "critical"
  );
  assert.equal(
    mentionSeverity({ matchedTerms: ["acme-corp"], excerpt: "see acme-corp.com dump", ...ctx }),
    "critical"
  );
  assert.equal(
    mentionSeverity({
      matchedTerms: ["acme-corp"],
      excerpt: "acme corp password combo dump",
      ...ctx,
    }),
    "high",
    "keywords bump medium to high, never critical"
  );
  assert.equal(
    mentionSeverity({ matchedTerms: ["acme bank"], excerpt: "acme bank password dump", ...ctx }),
    "critical",
    "high + keyword = critical"
  );
});

test("dismissed mention re-raises only on excerpt change", () => {
  const cand = (excerpt, severity = "medium") => ({
    source: "darkweb",
    sourceRef: "p1",
    excerpt,
    matchedTerms: ["acme-corp"],
    severity,
  });
  const fresh = diffMentions([], [cand("first text")], now);
  assert.equal(fresh.events.length, 1);
  assert.equal(fresh.events[0].kind, "leak_mention");
  const prev = { ...fresh.upserts[0], state: "dismissed", dismissedAtSeverity: "medium" };
  const same = diffMentions([prev], [cand("first text")], now);
  assert.deepEqual(same.events, []);
  assert.equal(same.upserts.length, 0, "nothing to write");
  const changed = diffMentions([prev], [cand("first text and more")], now);
  assert.equal(changed.events.length, 1);
  assert.equal(changed.upserts[0].state, "open");
  const quietOpen = diffMentions([fresh.upserts[0]], [cand("first text")], now);
  assert.deepEqual(quietOpen.events, [], "open and unchanged: silent");
});

test("runLeaks creates mentions and events from seeded darkweb_pages, once", async (t) => {
  const { User, Domain, DarkwebPage, Mention, Event } = await withDb(t);
  const user = await User.create({ email: "l@example.com", passwordHash: "x" });
  const domain = await Domain.create({
    userId: user._id,
    name: "acme-corp.com",
    terms: ["acme bank"],
    lastWatchedAt: null,
    baselineDoneAt: now,
  });
  await DarkwebPage.insertMany([
    {
      sourceUrl: "http://s.onion",
      pageUrl: "http://s.onion/a",
      title: "ACME Corp dump",
      body: "logins for acme-corp.com staff",
      crawledAt: new Date(now.getTime() - 3600_000),
    },
    {
      sourceUrl: "http://s.onion",
      pageUrl: "http://s.onion/b",
      title: "unrelated",
      body: "zebra bank",
      crawledAt: new Date(now.getTime() - 3600_000),
    },
    {
      sourceUrl: "http://s.onion",
      pageUrl: "http://s.onion/c",
      title: "old",
      body: "acme bank mention from long ago",
      crawledAt: new Date(now.getTime() - 10 * 86400_000),
    },
  ]);
  assert.ok(leakSources.some((s) => s.name === "darkweb"));
  const first = await runLeaks(domain, {
    models: { DarkwebPage, Mention, Event },
    now,
    since: new Date(now.getTime() - 86400_000),
  });
  assert.equal(first.mentions, 1, "only the page newer than since");
  const m = await Mention.findOne({ domainId: domain._id });
  assert.equal(m.source, "darkweb");
  assert.equal(m.severity, "critical", "full domain name in the excerpt");
  assert.equal(await Event.countDocuments({ domainId: domain._id, kind: "leak_mention" }), 1);
  const second = await runLeaks(domain, {
    models: { DarkwebPage, Mention, Event },
    now: new Date(now.getTime() + 60_000),
    since: new Date(now.getTime() - 86400_000),
  });
  assert.equal(second.events, 0, "same page, same excerpt: silent");
});
