const logger = require("../../logger");
const { buckets: defaultBuckets } = require("./providers");

const YEAR_MS = 365 * 24 * 3600_000;

/**
 * Registration facts via rdap.org (bootstrap redirector, free, no key).
 * @returns {Promise<{ registeredAt: Date | null, registrar: string | null, ns: string[] } | null>}
 */
async function lookupRdap(name, { fetchImpl = fetch, buckets = defaultBuckets } = {}) {
  await buckets.rdap.take();
  try {
    const res = await fetchImpl(`https://rdap.org/domain/${encodeURIComponent(name)}`, {
      redirect: "follow",
      headers: {
        Accept: "application/rdap+json, application/json",
        "User-Agent": "ThreatWatcher/2",
      },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return null;
    const body = /** @type {any} */ (await res.json());
    const reg = (body.events || []).find((e) => e.eventAction === "registration");
    const registrarEntity = (body.entities || []).find((e) =>
      (e.roles || []).includes("registrar")
    );
    let registrar = null;
    if (registrarEntity) {
      const fn = (registrarEntity.vcardArray?.[1] || []).find((row) => row[0] === "fn");
      registrar = fn
        ? String(fn[3])
        : registrarEntity.handle
          ? String(registrarEntity.handle)
          : null;
    }
    const ns = (body.nameservers || [])
      .map((n) => String(n.ldhName || "").toLowerCase())
      .filter(Boolean)
      .sort();
    return { registeredAt: reg?.eventDate ? new Date(reg.eventDate) : null, registrar, ns };
  } catch (err) {
    logger.warn({ err: { message: err.message }, name }, "rdap lookup failed");
    return null;
  }
}

/** Same registrar and at least one shared nameserver as the customer's own domain. */
function isDefensive(rdap, own) {
  if (!rdap || !own || !rdap.registrar || !own.registrar) return false;
  if (rdap.registrar.toLowerCase() !== own.registrar.toLowerCase()) return false;
  const ownNs = new Set((own.ns || []).map((n) => n.toLowerCase()));
  return (rdap.ns || []).some((n) => ownNs.has(n.toLowerCase()));
}

/** Registered more than a year ago: attackers' lookalikes are young. */
function isStale(rdap, now = new Date()) {
  const at = rdap?.registeredAt;
  if (!at) return false;
  return now.getTime() - new Date(at).getTime() > YEAR_MS;
}

module.exports = { lookupRdap, isDefensive, isStale };
