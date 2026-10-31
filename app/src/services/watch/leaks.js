const crypto = require("node:crypto");
const { compare, bump } = require("./severity");
const { splitDomain } = require("./permute");

const EXCERPT_RADIUS = 200;
const KEYWORDS = /\b(password|passwords|credential|credentials|combo|combolist|dump)\b/i;

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Whole-word, case-insensitive, "-" and whitespace treated alike. */
function termRegex(term) {
  const pattern = escapeRegex(String(term).toLowerCase()).replace(/[-\s]+/g, "[-\\s]+");
  return new RegExp(`\\b${pattern}\\b`, "i");
}

/** Excerpt around the first matching term, or null. */
function matchPage(page, terms, domainName) {
  const haystack = `${page.title || ""} ${page.body || ""}`;
  const matchedTerms = [];
  let first = -1;
  for (const term of [...terms, domainName]) {
    const m = termRegex(term).exec(haystack);
    if (!m) continue;
    if (term !== domainName) matchedTerms.push(term);
    if (first < 0 || m.index < first) first = m.index;
  }
  if (first < 0) return null;
  const start = Math.max(0, first - EXCERPT_RADIUS);
  const excerpt = haystack
    .slice(start, first + EXCERPT_RADIUS)
    .replace(/\s+/g, " ")
    .trim();
  return { excerpt, matchedTerms };
}

/**
 * Spec 7.3: customer term = high, auto label = medium; critical only when the
 * excerpt holds an @domain address or the domain itself; leak keywords bump one
 * level at most.
 */
function mentionSeverity({ matchedTerms, excerpt, domainName, customerTerms = [] }) {
  const text = String(excerpt || "");
  const domainRe = new RegExp(
    `(^|[^a-z0-9-])@?${escapeRegex(domainName.toLowerCase())}(?![a-z0-9-])`,
    "i"
  );
  if (domainRe.test(text)) return "critical";
  const customer = new Set(customerTerms.map((t) => t.toLowerCase()));
  let level = matchedTerms.some((t) => customer.has(String(t).toLowerCase())) ? "high" : "medium";
  if (KEYWORDS.test(text)) level = bump(level);
  return level;
}

const hashExcerpt = (excerpt) => crypto.createHash("sha256").update(String(excerpt)).digest("hex");

/**
 * Pure diff of mention candidates against stored mentions. A changed excerpt
 * re-raises even a dismissed mention; an unchanged one is silent.
 * @returns {{ upserts: object[], events: object[] }}
 */
function diffMentions(previous, candidates, now) {
  const prevByRef = new Map(previous.map((m) => [m.sourceRef, m]));
  const upserts = [];
  const events = [];
  for (const c of candidates) {
    const excerptHash = hashExcerpt(c.excerpt);
    const prev = prevByRef.get(c.sourceRef);
    if (prev && prev.excerptHash === excerptHash) continue;
    const next = prev
      ? {
          ...prev,
          excerpt: c.excerpt,
          excerptHash,
          matchedTerms: c.matchedTerms,
          severity: compare(c.severity, prev.severity) > 0 ? c.severity : prev.severity,
          lastSeenAt: now,
          state: "open",
        }
      : {
          source: c.source,
          sourceRef: c.sourceRef,
          excerpt: c.excerpt,
          excerptHash,
          matchedTerms: c.matchedTerms,
          severity: c.severity,
          firstSeenAt: now,
          lastSeenAt: now,
          state: "open",
        };
    upserts.push(next);
    events.push({
      sourceRef: c.sourceRef,
      kind: "leak_mention",
      severity: c.severity,
      payload: {
        source: c.source,
        sourceRef: c.sourceRef,
        matchedTerms: c.matchedTerms,
        excerpt: c.excerpt.slice(0, 240),
      },
    });
  }
  return { upserts, events };
}

/**
 * @typedef {{ domain: any, terms: string[], since: Date | null, models: any, fetchImpl?: Function, buckets?: any, cache?: any }} SourceArgs
 * @typedef {{ name: string, find: (args: SourceArgs) => Promise<object[]> }} LeakSource
 */

/** Crawled dark-web pages newer than `since`, matched in Mongo first, excerpted in JS. */
/** @type {LeakSource} */
const darkwebPagesSource = {
  name: "darkweb",
  async find({ domain, terms, since, models }) {
    const alternation = [...terms, domain.name].map((t) => termRegex(t).source).join("|");
    const re = new RegExp(alternation, "i");
    const query = { $or: [{ title: re }, { body: re }] };
    if (since) query.crawledAt = { $gt: since };
    const pages = await models.DarkwebPage.find(query).sort({ crawledAt: -1 }).limit(500).lean();
    const out = [];
    for (const page of pages) {
      const m = matchPage(page, terms, domain.name);
      if (!m) continue;
      out.push({
        source: "darkweb",
        sourceRef: `darkweb:${page.pageUrl}`,
        excerpt: m.excerpt,
        matchedTerms: m.matchedTerms,
        severity: mentionSeverity({
          ...m,
          domainName: domain.name,
          customerTerms: domain.terms || [],
        }),
      });
    }
    return out;
  },
};

/** @type {LeakSource[]} */
const leakSources = [darkwebPagesSource];

/**
 * Run every leak source for a domain and persist mentions + events.
 * @param {any} domain
 * @param {{ models: any, now?: Date, since?: Date | null, baseline?: boolean, fetchImpl?: Function, buckets?: any, cache?: any }} opts
 * @returns {Promise<{ mentions: number, events: number }>}
 */
async function runLeaks(domain, opts) {
  const {
    models,
    now = new Date(),
    since = domain.lastWatchedAt || null,
    baseline = false,
    fetchImpl,
    buckets,
    cache,
  } = opts;
  const { Mention, Event } = models;
  const terms = [...new Set([splitDomain(domain.name).label, ...(domain.terms || [])])];
  const candidates = [];
  for (const source of leakSources) {
    candidates.push(
      ...(await source.find({ domain, terms, since, models, fetchImpl, buckets, cache }))
    );
  }
  const previous = await Mention.find({ domainId: domain._id }).lean();
  const { upserts, events } = diffMentions(previous, candidates, now);
  if (upserts.length) {
    await Mention.bulkWrite(
      upserts.map((m) => {
        const { _id, userId, domainId, createdAt, updatedAt, __v, ...fields } = m;
        return {
          updateOne: {
            filter: { domainId: domain._id, sourceRef: m.sourceRef },
            update: { $set: fields, $setOnInsert: { userId: domain.userId, domainId: domain._id } },
            upsert: true,
          },
        };
      }),
      { ordered: false }
    );
  }
  if (events.length) {
    const rows = await Mention.find(
      { domainId: domain._id, sourceRef: { $in: events.map((e) => e.sourceRef) } },
      { sourceRef: 1 }
    ).lean();
    const idByRef = new Map(rows.map((r) => [r.sourceRef, r._id]));
    await Event.insertMany(
      events.map((e) => ({
        userId: domain.userId,
        domainId: domain._id,
        mentionId: idByRef.get(e.sourceRef),
        kind: e.kind,
        severity: e.severity,
        at: now,
        payload: baseline ? { ...e.payload, baseline: true } : e.payload,
      }))
    );
  }
  return { mentions: upserts.length, events: events.length };
}

module.exports = {
  termRegex,
  matchPage,
  mentionSeverity,
  diffMentions,
  leakSources,
  runLeaks,
  hashExcerpt,
};
