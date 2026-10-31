const { scoreDomains, isPunycode, isSubstringMatch } = require("../similarity");
const { buckets: defaultBuckets, labelCache } = require("./providers");

const MIN_LABEL = 5;
const CRTSH_MAX_ROWS = 5000;
const CRTSH_MAX_BYTES = 5 * 1024 * 1024;
const THRESHOLD = 0.7;

/** @typedef {{ names: string[], notBefore: Date, issuer: string, tbs: string }} CertRow */

async function fromCertSpotter(label, { fetchImpl, apiKey, cursor, buckets }) {
  await buckets.certspotter.take();
  const url =
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(label)}` +
    `&include_subdomains=true&expand=dns_names&expand=issuer` +
    (cursor ? `&after=${encodeURIComponent(cursor)}` : "");
  const res = await fetchImpl(url, {
    headers: { Authorization: `Bearer ${apiKey}`, "User-Agent": "ThreatWatcher/2" },
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`certspotter ${res.status}`);
  const rows = /** @type {any[]} */ (await res.json());
  const certs = rows.map((r) => ({
    names: (r.dns_names || []).map((n) => String(n).toLowerCase()),
    notBefore: new Date(r.not_before),
    issuer: r.issuer?.friendly_name || r.issuer?.name || "",
    tbs: String(r.tbs_sha256 || r.id),
  }));
  const last = rows.length ? String(rows[rows.length - 1].id) : cursor || null;
  return { certs, cursor: last };
}

async function fromCrtSh(label, { fetchImpl, buckets }) {
  await buckets.crtsh.take();
  const url = `https://crt.sh/?q=%25${encodeURIComponent(label)}%25&output=json`;
  const res = await fetchImpl(url, {
    headers: { "User-Agent": "ThreatWatcher/2" },
    signal: AbortSignal.timeout(20_000),
  });
  if (!res.ok) throw new Error(`crt.sh ${res.status}`);
  const text = await res.text();
  if (text.length > CRTSH_MAX_BYTES) throw new Error("crt.sh body too large");
  const rows = /** @type {any[]} */ (JSON.parse(text)).slice(0, CRTSH_MAX_ROWS);
  const certs = rows.map((r) => ({
    names: String(r.name_value || "")
      .split("\n")
      .map((n) => n.trim().toLowerCase())
      .filter(Boolean),
    notBefore: new Date(r.not_before),
    issuer: String(r.issuer_name || ""),
    tbs: String(r.id),
  }));
  return { certs };
}

/**
 * Certificates mentioning `label`, Cert Spotter first (cursor-based), crt.sh
 * as backfill and fallback, both cached per label for 6 h. Labels shorter
 * than 5 characters are skipped (the query returns the internet).
 * @returns {Promise<{ certs: CertRow[], cursor: string | null, source: "certspotter"|"crtsh"|"cache"|"skipped", error?: string }>}
 */
async function fetchCertificates(
  label,
  { fetchImpl = fetch, apiKey, cursor = null, cache = labelCache, buckets = defaultBuckets }
) {
  if (!label || label.length < MIN_LABEL)
    return { certs: [], cursor: cursor || null, source: "skipped" };
  const key = `certs:${label}`;
  const cached = cache.get(key);
  if (cached) return { ...cached, source: "cache" };

  const errors = [];
  if (apiKey) {
    try {
      const out = await fromCertSpotter(label, { fetchImpl, apiKey, cursor, buckets });
      const value = { certs: out.certs, cursor: out.cursor };
      cache.set(key, value);
      return { ...value, source: "certspotter" };
    } catch (err) {
      errors.push(err.message);
    }
  }
  try {
    const out = await fromCrtSh(label, { fetchImpl, buckets });
    const value = { certs: out.certs, cursor: cursor || null };
    cache.set(key, value);
    return { ...value, source: "crtsh" };
  } catch (err) {
    errors.push(err.message);
  }
  return { certs: [], cursor: cursor || null, source: "crtsh", error: errors.join("; ") };
}

/**
 * Names on certificates that look like `domainName`, merged per name.
 * @param {CertRow[]} certs
 * @returns {Map<string, { firstIssuedAt: Date, issuer: string, notBefore: Date, tbs: string, lastSeenAt: Date }>}
 */
function certCandidates(domainName, certs) {
  const self = String(domainName).toLowerCase();
  const out = new Map();
  const names = new Set();
  const byName = new Map();
  for (const cert of certs) {
    for (const raw of cert.names) {
      const name = raw.replace(/^\*\./, "");
      if (!name || name === self || name.endsWith(`.${self}`)) continue;
      names.add(name);
      (byName.get(name) || byName.set(name, []).get(name)).push(cert);
    }
  }
  const similar = new Set(scoreDomains(self, [...names], THRESHOLD).map((s) => s.domain));
  for (const name of names) {
    if (!similar.has(name) && !isPunycode(name) && !isSubstringMatch(self, name)) continue;
    const rows = byName.get(name).filter((c) => !Number.isNaN(c.notBefore.getTime()));
    if (!rows.length) continue;
    rows.sort((a, b) => a.notBefore - b.notBefore);
    const latest = rows[rows.length - 1];
    out.set(name, {
      firstIssuedAt: rows[0].notBefore,
      notBefore: latest.notBefore,
      issuer: latest.issuer,
      tbs: latest.tbs,
      lastSeenAt: new Date(),
    });
  }
  return out;
}

module.exports = { fetchCertificates, certCandidates, MIN_LABEL };
