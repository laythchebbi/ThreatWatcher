const dnsPromises = require("node:dns/promises");
const crypto = require("node:crypto");

/** "acme.co.uk" → "co.uk" */
function tldOf(name) {
  return String(name).split(".").slice(1).join(".");
}

/** Run `fn` over `items` with at most `limit` in flight; results in input order. */
async function mapBounded(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  async function lane() {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, lane));
  return out;
}

/**
 * A, MX and NS for every candidate. Only names whose A lookup succeeds are
 * returned; MX/NS failures become []. `dns.resolve*` (c-ares) is used on
 * purpose: unlike dns.lookup it does not queue on the libuv thread pool.
 * @param {string[]} candidates
 * @param {{ resolver?: typeof dnsPromises, concurrency?: number }} [opts]
 * @returns {Promise<Map<string, { a: string[], mx: string[], ns: string[] }>>}
 */
async function resolveCandidates(candidates, { resolver = dnsPromises, concurrency = 50 } = {}) {
  const results = await mapBounded(candidates, concurrency, async (name) => {
    let a;
    try {
      a = await resolver.resolve4(name);
    } catch {
      return null;
    }
    const [mx, ns] = await Promise.all([
      resolver
        .resolveMx(name)
        .then((rows) => rows.map((r) => r.exchange).sort())
        .catch(() => []),
      resolver
        .resolveNs(name)
        .then((rows) => [...rows].sort())
        .catch(() => []),
    ]);
    return [name, { a: [...a].sort(), mx, ns }];
  });
  return new Map(results.filter(Boolean));
}

/**
 * TLDs that answer for a random label resolve everything; candidates under
 * them tell us nothing. One probe per TLD per cycle.
 * @returns {Promise<Set<string>>}
 */
async function probeWildcardTlds(
  tlds,
  { resolver = dnsPromises, random = crypto.randomBytes } = {}
) {
  const wild = new Set();
  await mapBounded([...new Set(tlds)], 10, async (tld) => {
    const label = random(12).toString("hex");
    try {
      await resolver.resolve4(`${label}.${tld}`);
      wild.add(tld);
    } catch {
      /* normal: random labels do not resolve */
    }
  });
  return wild;
}

module.exports = { resolveCandidates, probeWildcardTlds, tldOf, mapBounded };
