const { scoreDomains, isPunycode, isSubstringMatch } = require("../similarity");
const { buckets: defaultBuckets, labelCache } = require("./providers");

const MIN_LABEL = 5;
const CRTSH_MAX_ROWS = 5000;
const CRTSH_MAX_BYTES = 5 * 1024 * 1024;
const MAX_PAGES = 20;
const THRESHOLD = 0.7;

/** @typedef {{ names: string[], notBefore: Date, issuer: string, tbs: string }} CertRow */

function spotterRow(r) {
  return {
    names: (r.dns_names || []).map((n) => String(n).toLowerCase()),
    notBefore: new Date(r.not_before),
    issuer: r.issuer?.friendly_name || r.issuer?.name || "",
    tbs: String(r.tbs_sha256 || r.id),
  };
}

/** Cert Spotter issuances after `cursor`, paged until an empty page (bounded). */
async function fromCertSpotter(label, { fetchImpl, apiKey, cursor, buckets }) {
  const certs = [];
  let after = cursor;
  for (let page = 0; page < MAX_PAGES; page++) {
    await buckets.certspotter.take();
    const url =
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(label)}` +
      `&include_subdomains=true&expand=dns_names&expand=issuer` +
      (after ? `&after=${encodeURIComponent(after)}` : "");
    const res = await fetchImpl(url, {
      headers: { Authorization: `Bearer ${apiKey}`, "User-Agent": "ThreatWatcher/2" },
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) throw new Error(`certspotter ${res.status}`);
    const rows = /** @type {any[]} */ (await res.json());
    if (!rows.length) break;
    certs.push(...rows.map(spotterRow));
    after = String(rows[rows.length - 1].id);
  }
  return { certs, cursor: after || null };
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
 * Certificates mentioning `label`: Cert Spotter (cursor-paged) when a key is
 * set, with one crt.sh backfill on the first call for a label; crt.sh alone
 * otherwise. Cached per label *and cursor* for 6 h. Labels shorter than 5
 * characters are skipped (the query returns the internet).
 * @returns {Promise<{ certs: CertRow[], cursor: string | null, source: "certspotter"|"crtsh"|"cache"|"skipped", error?: string }>}
 */
async function fetchCertificates(
  label,
  { fetchImpl = fetch, apiKey, cursor = null, cache = labelCache, buckets = defaultBuckets }
) {
  if (!label || label.length < MIN_LABEL)
    return { certs: [], cursor: cursor || null, source: "skipped" };
  const key = `certs:${label}:${cursor || "start"}`;
  const cached = cache.get(key);
  if (cached) return { ...cached, source: "cache" };

  const errors = [];
  if (apiKey) {
    try {
      const out = await fromCertSpotter(label, { fetchImpl, apiKey, cursor, buckets });
      let certs = out.certs;
      if (!cursor) {
        // First sight of this label: crt.sh history, because Cert Spotter starts "now".
        try {
          const back = await fromCrtSh(label, { fetchImpl, buckets });
          const seen = new Set(certs.map((c) => c.tbs));
          certs = [...certs, ...back.certs.filter((c) => !seen.has(c.tbs))];
        } catch (err) {
          errors.push(err.message);
        }
      }
      const value = { certs, cursor: out.cursor };
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
