const crypto = require("node:crypto");
const { env } = require("../../config");
const logger = require("../../logger");
const { Sighting, Event, Domain } = require("../../models");
const { permutations } = require("./permute");
const { resolveCandidates, probeWildcardTlds, tldOf } = require("./dns");
const { diffDomain } = require("./diff");

const JITTER_MS = 15 * 60 * 1000;
const STRIP = new Set(["_id", "userId", "domainId", "createdAt", "updatedAt", "__v"]);

/** now + WATCH_INTERVAL_HOURS ± 15 min, so domains added together drift apart. */
function nextWatchAt(now, random) {
  const unit = random(2).readUInt16BE(0) / 65535; // 0..1
  const offset = (unit * 2 - 1) * JITTER_MS;
  return new Date(now.getTime() + env.WATCH_INTERVAL_HOURS * 3600_000 + offset);
}

/**
 * One watch cycle for one protected domain (spec 7.4, Plan 1 steps):
 * permute → drop wildcard TLDs → resolve → diff → persist → reschedule.
 * A failing step is logged and the domain is still rescheduled, so a broken
 * cycle never pins a domain.
 * @returns {Promise<{ events: number, sightings: number, source: string }>}
 */
async function runCycle(
  domain,
  { worker, resolver, fetchImpl, lists, now = new Date(), random = crypto.randomBytes }
) {
  const result = { events: 0, sightings: 0, source: "previous" };
  const update = { lastWatchedAt: now, nextWatchAt: nextWatchAt(now, random), watchingSince: null };
  const baseline = !domain.baselineDoneAt;

  try {
    const { candidates, source } = await permutations(domain.name, {
      worker,
      fetchImpl,
      previous: domain.lastPermutation || [],
    });
    result.source = source;
    if (source !== "previous") update.lastPermutation = candidates;

    const wild = await probeWildcardTlds([...new Set(candidates.map(tldOf))], { resolver, random });
    const kept = candidates.filter((c) => !wild.has(tldOf(c)));
    const observed = await resolveCandidates(kept, { resolver });

    const previous = await Sighting.find({ domainId: domain._id }).lean();
    const { upserts, events } = diffDomain({
      domain,
      previous,
      observed,
      candidates: kept,
      lists,
      now,
      baseline,
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
    if (events.length) {
      const rows = await Sighting.find(
        { domainId: domain._id, lookalike: { $in: events.map((e) => e.lookalike) } },
        { lookalike: 1 }
      ).lean();
      const idByName = new Map(rows.map((r) => [r.lookalike, r._id]));
      await Event.insertMany(
        events.map((e) => ({
          userId: domain.userId,
          domainId: domain._id,
          sightingId: idByName.get(e.lookalike),
          kind: e.kind,
          severity: e.severity,
          at: now,
          payload: e.payload,
        }))
      );
    }
    result.events = events.length;
    result.sightings = upserts.length;
    // The baseline ends only when a cycle completed with a real permutation list;
    // combosquats alone (worker and API both down, nothing stored) are not one.
    const hadPermutations = source !== "previous" || (domain.lastPermutation || []).length > 0;
    if (baseline && hadPermutations) update.baselineDoneAt = now;
    logger.info({ domain: domain.name, ...result, baseline }, "watch cycle done");
  } catch (err) {
    logger.error({ err, domain: domain.name }, "watch cycle failed");
  } finally {
    await Domain.updateOne({ _id: domain._id }, { $set: update });
  }
  return result;
}

module.exports = { runCycle, nextWatchAt };
