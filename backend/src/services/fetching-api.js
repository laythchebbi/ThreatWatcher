const dns = require("node:dns/promises");
const logger = require("../logger");

/**
 * Generate fuzzy-similar domains via the dnstwister.report API.
 * Returns the raw `fuzzy_domains` list (each item has `.domain`).
 */
async function dnsTwistFuzz(domainName) {
  const hex = Buffer.from(domainName, "utf8").toString("hex");
  const url = `https://dnstwister.report/api/fuzz/${hex}`;
  const res = await fetch(url, { signal: AbortSignal.timeout(15_000) });
  if (!res.ok) throw new Error(`dnstwister ${url} -> ${res.status}`);
  const body = /** @type {{ fuzzy_domains?: { domain: string }[] }} */ (await res.json());
  return body.fuzzy_domains || [];
}

/**
 * Resolve which domains in a list have DNS records (i.e. registered/live).
 * Errors are swallowed per-domain — returns only those that resolved.
 *
 * shortcut: dns.resolve() checks A records only. Unlike dns.lookup() it does
 * not go through the 4-thread libuv pool, which thousands of parallel
 * candidates would exhaust. Upgrade to resolveAny() if AAAA-only lookalikes
 * ever matter.
 */
async function filterRegistered(domainList) {
  const out = [];
  await Promise.all(
    domainList.map(async (d) => {
      try {
        await dns.resolve(d);
        out.push(d);
      } catch {
        /* unresolved is fine — just means not registered */
      }
    })
  );
  if (domainList.length && !out.length) {
    logger.warn({ candidates: domainList.length }, "no candidate resolved; is DNS reachable?");
  }
  return out;
}

module.exports = { dnsTwistFuzz, filterRegistered };
