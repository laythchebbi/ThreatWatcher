const logger = require("../../logger");
const { leakSources } = require("./leaks");
const { buckets: defaultBuckets, labelCache } = require("./providers");

const API = "https://haveibeenpwned.com/api/v3";
const UA = "ThreatWatcher/2 (brand monitoring; contact via the app)";

async function call(path, apiKey, { fetchImpl, buckets }) {
  await buckets.hibp.take();
  const res = await fetchImpl(`${API}${path}`, {
    headers: { "hibp-api-key": apiKey, "User-Agent": UA, Accept: "application/json" },
    signal: AbortSignal.timeout(15_000),
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`hibp ${res.status}`);
  return res.json();
}

function excerptFor(b) {
  const classes = (b.DataClasses || []).join(", ");
  return `${b.Title || b.Name}, ${b.BreachDate || "unknown date"}, ${b.PwnCount ?? "?"} addresses, data: ${classes}`;
}

/**
 * Have I Been Pwned domain search as a leak source (spec 7.4 step 5b). Uses
 * the customer's own key stored on the domain; polls /latestBreach each cycle
 * and reads /breacheddomain only when the latest breach changed.
 * @type {import("./leaks").LeakSource}
 */
const hibpSource = {
  name: "hibp",
  async find({ domain, models, fetchImpl = fetch, buckets = defaultBuckets, cache = labelCache }) {
    const apiKey = domain.hibp?.apiKey;
    if (!apiKey) return [];
    const { Domain } = models;
    try {
      const latest = await call("/latestBreach", apiKey, { fetchImpl, buckets });
      if (!latest?.Name || latest.Name === domain.hibp?.lastBreachSeen) return [];
      const byAlias =
        (await call(`/breacheddomain/${encodeURIComponent(domain.name)}`, apiKey, {
          fetchImpl,
          buckets,
        })) || {};
      const names = [...new Set(Object.values(byAlias).flat())];
      const out = [];
      for (const name of names) {
        const key = `hibp:breach:${name}`;
        let breach = cache.get(key);
        if (!breach) {
          breach = (await call(`/breach/${encodeURIComponent(name)}`, apiKey, {
            fetchImpl,
            buckets,
          })) || { Name: name };
          cache.set(key, breach);
        }
        out.push({
          source: "hibp",
          sourceRef: `hibp:${name}`,
          excerpt: excerptFor(breach),
          matchedTerms: [domain.name],
          severity: "high",
        });
      }
      await Domain.updateOne(
        { _id: domain._id },
        {
          $set: {
            "hibp.lastBreachSeen": latest.Name,
            "hibp.checkedAt": new Date(),
            "hibp.error": null,
          },
        }
      );
      return out;
    } catch (err) {
      logger.warn({ err: { message: err.message }, domain: domain.name }, "hibp source failed");
      await Domain.updateOne(
        { _id: domain._id },
        { $set: { "hibp.error": err.message, "hibp.checkedAt": new Date() } }
      ).catch(() => {});
      return [];
    }
  },
};

if (!leakSources.some((s) => s.name === "hibp")) leakSources.push(hibpSource);

module.exports = { hibpSource };
