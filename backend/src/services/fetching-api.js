const dns = require("node:dns/promises");
const { env } = require("../config");
const logger = require("../logger");

/**
 * Generate fuzzy-similar domains via the dnstwister.report API.
 * Returns the raw `fuzzy_domains` list (each item has `.domain`).
 */
async function dnsTwistFuzz(domainName) {
  const hex = Buffer.from(domainName, "utf8").toString("hex");
  const url = `https://dnstwister.report/api/fuzz/${hex}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`dnstwister ${url} -> ${res.status}`);
  const body = /** @type {{ fuzzy_domains?: { domain: string }[] }} */ (await res.json());
  return body.fuzzy_domains || [];
}

/**
 * Resolve which domains in a list have DNS records (i.e. registered/live).
 * Errors are swallowed per-domain — returns only those that resolved.
 */
async function filterRegistered(domainList) {
  const out = [];
  await Promise.all(
    domainList.map(async (d) => {
      try {
        await dns.lookup(d);
        out.push(d);
      } catch {
        /* unresolved is fine — just means not registered */
      }
    })
  );
  return out;
}

/**
 * WhoisXML lookup for a single domain. Returns parsed JSON, or null on failure.
 */
async function whois(domainName) {
  if (!env.WHOISXML_API_KEY) {
    logger.warn("WHOISXML_API_KEY not set — whois() will return null");
    return null;
  }
  const url = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${env.WHOISXML_API_KEY}&domainName=${encodeURIComponent(domainName)}&outputFormat=json`;
  const res = await fetch(url);
  if (!res.ok) {
    logger.warn({ status: res.status, domainName }, "whois fetch failed");
    return null;
  }
  return res.json();
}

module.exports = { dnsTwistFuzz, filterRegistered, whois };
