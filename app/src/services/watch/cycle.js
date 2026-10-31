const crypto = require("node:crypto");
const { env } = require("../../config");
const logger = require("../../logger");
const { Sighting, Event, Domain } = require("../../models");
const { scoreDomains } = require("../similarity");
const { permutations, splitDomain } = require("./permute");
const { resolveCandidates, probeWildcardTlds, tldOf } = require("./dns");
const { fetchCertificates, certCandidates } = require("./certs");
const { fetchPage, fetchPages, fetchCertificate } = require("./http");
const { lookupRdap } = require("./rdap");
const { checkPosture, postureEvents } = require("./posture");
const { labelCache } = require("./providers");
const { diffDomain } = require("./diff");

const JITTER_MS = 15 * 60 * 1000;
const DAY_MS = 24 * 3600_000;
const OWN_RDAP_TTL = 30 * DAY_MS;
const POSTURE_TTL = 7 * DAY_MS;
const BASELINE_PAGE_LIMIT = 50;
const STRIP = new Set(["_id", "userId", "domainId", "createdAt", "updatedAt", "__v"]);

/** now + WATCH_INTERVAL_HOURS ± 15 min, so domains added together drift apart. */
function nextWatchAt(now, random) {
  const unit = random(2).readUInt16BE(0) / 65535; // 0..1
  const offset = (unit * 2 - 1) * JITTER_MS;
  return new Date(now.getTime() + env.WATCH_INTERVAL_HOURS * 3600_000 + offset);
}

/** Run one step; on failure log and return the fallback so the cycle goes on. */
async function step(name, domain, fn, fallback) {
  try {
    return await fn();
  } catch (err) {
    logger.warn(
      { err: { message: err.message }, domain: domain.name, step: name },
      "watch step failed"
    );
    return fallback;
  }
}

function brandTermsFor(domain) {
  const { label } = splitDomain(domain.name);
  return [...new Set([label, label.replace(/-/g, " "), ...(domain.terms || [])].filter(Boolean))];
}

/**
 * One watch cycle for one protected domain (spec 7.4): permute → certs →
 * wildcard filter → DNS → RDAP → pages → posture → diff → persist →
 * reschedule. Every step is fenced; a broken one never pins the domain.
 * @returns {Promise<{ events: number, sightings: number, source: string }>}
 */
async function runCycle(domain, deps) {
  const {
    worker,
    resolver,
    fetchImpl = fetch,
    apiKey = env.CERTSPOTTER_API_KEY,
    connect,
    lists,
    now = new Date(),
    random = crypto.randomBytes,
    cache = labelCache,
  } = deps;
  const result = { events: 0, sightings: 0, source: "previous" };
  const update = { lastWatchedAt: now, nextWatchAt: nextWatchAt(now, random), watchingSince: null };
  const baseline = !domain.baselineDoneAt;
  const { label } = splitDomain(domain.name);
  const brandTerms = brandTermsFor(domain);

  try {
    // 1. permutations
    const { candidates: permuted, source } = await permutations(domain.name, {
      worker,
      fetchImpl,
      previous: domain.lastPermutation || [],
    });
    result.source = source;
    if (source !== "previous") update.lastPermutation = permuted;

    // 2. certificates (names before DNS)
    const certResult = await step(
      "certs",
      domain,
      () => fetchCertificates(label, { fetchImpl, apiKey, cursor: domain.certCursor, cache }),
      {
        certs: [],
        cursor: domain.certCursor,
        source: "skipped",
      }
    );
    if (certResult.cursor && certResult.cursor !== domain.certCursor)
      update.certCursor = certResult.cursor;
    const certs = certCandidates(domain.name, certResult.certs);

    // 3. DNS
    const candidates = [...new Set([...permuted, ...certs.keys()])];
    const wild = await probeWildcardTlds([...new Set(candidates.map(tldOf))], { resolver, random });
    const kept = candidates.filter((c) => !wild.has(tldOf(c)));
    const observed = await resolveCandidates(kept, { resolver });
    const previous = await Sighting.find({ domainId: domain._id }).lean();
    const prevByName = new Map(previous.map((s) => [s.lookalike, s]));

    // 3b. RDAP: the customer's own domain monthly, lookalikes on their first resolve
    let ownRdap =
      domain.ownRdap?.fetchedAt &&
      now.getTime() - new Date(domain.ownRdap.fetchedAt).getTime() < OWN_RDAP_TTL
        ? domain.ownRdap
        : null;
    if (!ownRdap) {
      const fresh = await step(
        "rdap-own",
        domain,
        () => lookupRdap(domain.name, { fetchImpl }),
        null
      );
      if (fresh) {
        ownRdap = { registrar: fresh.registrar, ns: fresh.ns, fetchedAt: now };
        update.ownRdap = ownRdap;
      }
    }
    const rdap = new Map();
    const firstResolving = [...observed.keys()].filter((n) => !prevByName.get(n)?.dns?.resolves);
    for (const name of firstResolving) {
      const facts = await step("rdap", domain, () => lookupRdap(name, { fetchImpl }), null);
      if (facts) rdap.set(name, facts);
    }

    // 4. pages for resolving names, highest similarity first
    const similarity = new Map(
      scoreDomains(domain.name, [...observed.keys()], 0).map((s) => [s.domain, s.similarity])
    );
    const refKey = `ref:${domain.name}`;
    let referenceText = cache.get(refKey);
    if (referenceText === undefined) {
      const own = await step(
        "own-page",
        domain,
        () => fetchPage(domain.name, { fetchImpl, resolver, brandTerms: [] }),
        null
      );
      referenceText = own?.visibleText || "";
      cache.set(refKey, referenceText);
    }
    const targets = [...observed.keys()].map((lookalike) => ({
      lookalike,
      similarity: similarity.get(lookalike) || 0,
    }));
    const pages = await step(
      "pages",
      domain,
      () =>
        fetchPages(
          targets,
          { fetchImpl, resolver, brandTerms, referenceText, now: () => now },
          { concurrency: 8, limit: baseline ? BASELINE_PAGE_LIMIT : undefined }
        ),
      new Map()
    );
    for (const [name, facts] of pages) {
      if (facts.status) {
        const cert = await step(
          "tls",
          domain,
          () => fetchCertificate(name, connect ? { connect } : {}),
          null
        );
        if (cert) facts.cert = cert;
      }
    }

    // 5a. own-domain posture, weekly
    const postureDue =
      !domain.posture?.checkedAt ||
      now.getTime() - new Date(domain.posture.checkedAt).getTime() > POSTURE_TTL;
    let extraEvents = [];
    if (postureDue) {
      const posture = await step(
        "posture",
        domain,
        () =>
          checkPosture(domain.name, {
            resolver,
            dkimSelector: domain.dkimSelector,
            now: () => now,
          }),
        null
      );
      if (posture) {
        extraEvents = postureEvents(domain.posture?.grade ? domain.posture : null, posture).map(
          (e) => (baseline ? { ...e, payload: { ...e.payload, baseline: true } } : e)
        );
        update.posture = posture;
      }
    }

    // 6. diff + persist
    const { upserts, events } = diffDomain({
      domain,
      previous,
      observed,
      candidates: kept,
      lists,
      now,
      baseline,
      certs,
      pages,
      rdap,
      ownRdap,
    });
    if (upserts.length) {
      await Sighting.bulkWrite(
        upserts.map((u) => {
          const fields = Object.fromEntries(Object.entries(u).filter(([k]) => !STRIP.has(k)));
          return {
            updateOne: {
              filter: { domainId: domain._id, lookalike: u.lookalike },
              update: {
                $set: fields,
                $setOnInsert: { userId: domain.userId, domainId: domain._id },
              },
              upsert: true,
            },
          };
        }),
        { ordered: false }
      );
    }
    const all = [...events, ...extraEvents];
    if (all.length) {
      const rows = await Sighting.find(
        { domainId: domain._id, lookalike: { $in: events.map((e) => e.lookalike) } },
        { lookalike: 1 }
      ).lean();
      const idByName = new Map(rows.map((r) => [r.lookalike, r._id]));
      await Event.insertMany(
        all.map((e) => ({
          userId: domain.userId,
          domainId: domain._id,
          sightingId: e.lookalike ? idByName.get(e.lookalike) : undefined,
          kind: e.kind,
          severity: e.severity,
          at: now,
          payload: e.payload,
        }))
      );
    }
    result.events = all.length;
    result.sightings = upserts.length;
    const hadPermutations = source !== "previous" || (domain.lastPermutation || []).length > 0;
    if (baseline && hadPermutations) update.baselineDoneAt = now;
    logger.info(
      { domain: domain.name, ...result, baseline, certs: certs.size, pages: pages.size },
      "watch cycle done"
    );
  } catch (err) {
    logger.error({ err, domain: domain.name }, "watch cycle failed");
  } finally {
    await Domain.updateOne({ _id: domain._id }, { $set: update });
  }
  return result;
}

module.exports = { runCycle, nextWatchAt, brandTermsFor };
