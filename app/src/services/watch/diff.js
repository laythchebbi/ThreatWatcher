const { scoreDomains, isPunycode, isSubstringMatch } = require("../similarity");
const { classifyInfra } = require("./warninglists");
const { eventSeverity, compare } = require("./severity");
const { isDefensive, isStale } = require("./rdap");

const THRESHOLD = 0.7;
const EMPTY_DNS = { resolves: false, a: [], mx: [], ns: [] };
const FRESH_CERT_MS = 7 * 24 * 3600_000;
// Events that are never tagged as baseline and never downgraded for parked names.
const ALWAYS_LOUD = new Set(["cert_issued", "page_mimics_login"]);
const PARKED_LOW = new Set(["new_lookalike", "dns_live", "mx_live", "infra_changed"]);
const ok2xx3xx = (status) => typeof status === "number" && status >= 200 && status < 400;

const same = (x = [], y = []) => [...x].sort().join(",") === [...y].sort().join(",");

/**
 * Pure diff of one protected domain's watch cycle (spec 7.3 rules).
 * @param {{
 *   domain: { name: string },
 *   previous: object[],
 *   observed: Map<string, { a: string[], mx: string[], ns: string[] }>,
 *   candidates: string[],
 *   lists: { parkingNs: Set<string>, cdnCidrs: object[] },
 *   now: Date,
 *   baseline: boolean,
 *   certs?: Map<string, object>,
 *   pages?: Map<string, object>,
 *   rdap?: Map<string, object>,
 *   ownRdap?: object | null,
 * }} input
 * @returns {{ upserts: object[], events: { lookalike: string, kind: string, severity: string, payload: object }[] }}
 */
function diffDomain({
  domain,
  previous,
  observed,
  candidates,
  lists,
  now,
  baseline,
  certs = new Map(),
  pages = new Map(),
  rdap = new Map(),
  ownRdap = null,
}) {
  const prevByName = new Map(previous.map((s) => [s.lookalike, s]));
  const names = [
    ...new Set([...candidates, ...observed.keys(), ...certs.keys(), ...prevByName.keys()]),
  ];
  const similarity = new Map(
    scoreDomains(domain.name, names, 0).map((s) => [s.domain, s.similarity])
  );

  const upserts = [];
  const events = [];

  for (const name of names) {
    const prev = prevByName.get(name);
    const dns = observed.get(name) || null;
    const sim = similarity.get(name) ?? 0;
    const certFacts = certs.get(name) || null;
    const pageFacts = pages.get(name) || null;
    const rdapFacts = rdap.get(name) || null;
    if (!prev && !dns && !certFacts && sim < THRESHOLD) continue;

    const next = prev
      ? { ...prev, dns: { ...prev.dns }, infra: { ...prev.infra } }
      : {
          lookalike: name,
          firstSeenAt: now,
          lastSeenAt: now,
          baseline,
          inactive: false,
          dnsMisses: 0,
          dns: { ...EMPTY_DNS },
          infra: { parked: false, cdn: false },
          similarity: sim,
          punycode: isPunycode(name),
          substring: isSubstringMatch(domain.name, name),
          state: "open",
          severity: "low",
        };
    const kinds = [];
    /** @type {{ lookalike: string, baseline?: boolean, stale?: boolean, changed?: string[], before?: object, after?: object }} */
    const payload = { lookalike: name };

    if (dns) {
      next.lastSeenAt = now;
      next.dnsMisses = 0; // misses must be consecutive to count
      next.infra = classifyInfra(dns, lists);
      if (!prev) {
        kinds.push("new_lookalike", "dns_live");
        if (dns.mx.length) kinds.push("mx_live");
      } else if (prev.inactive || !prev.dns?.resolves) {
        next.inactive = false;
        next.dnsMisses = 0;
        if (!same(prev.dns?.a, dns.a)) kinds.push("dns_live");
        if (dns.mx.length && !prev.dns?.mx?.length) kinds.push("mx_live");
      } else {
        const changed = [];
        if (!same(prev.dns.a, dns.a)) changed.push("a");
        if (!same(prev.dns.ns, dns.ns)) changed.push("ns");
        if (dns.mx.length && !prev.dns.mx.length) kinds.push("mx_live");
        else if (!same(prev.dns.mx, dns.mx)) changed.push("mx");
        if (changed.length) {
          kinds.push("infra_changed");
          payload.changed = changed;
          payload.before = { a: prev.dns.a, mx: prev.dns.mx, ns: prev.dns.ns };
          payload.after = { a: dns.a, mx: dns.mx, ns: dns.ns };
        }
      }
      next.dns = { resolves: true, a: dns.a, mx: dns.mx, ns: dns.ns };
    } else if (prev) {
      if (!prev.inactive && prev.dns?.resolves) {
        next.dnsMisses = (prev.dnsMisses || 0) + 1;
        if (next.dnsMisses >= 2) {
          next.inactive = true;
          next.dns.resolves = false;
          kinds.push("gone");
        }
      }
    } else {
      kinds.push("new_lookalike");
    }

    // Certificates: first certificate fires once when it is fresh; renewals are silent.
    if (certFacts) {
      const hadCert = Boolean(prev?.cert?.firstIssuedAt);
      const sinceFirstSeen =
        (prev?.firstSeenAt ? new Date(prev.firstSeenAt) : now).getTime() - FRESH_CERT_MS;
      const fresh = certFacts.notBefore.getTime() >= sinceFirstSeen;
      next.cert = {
        firstIssuedAt:
          hadCert && prev.cert.firstIssuedAt < certFacts.firstIssuedAt
            ? prev.cert.firstIssuedAt
            : certFacts.firstIssuedAt,
        notBefore: certFacts.notBefore,
        issuer: certFacts.issuer,
        tbs: certFacts.tbs,
        lastSeenAt: now,
        fingerprint256: prev?.cert?.fingerprint256,
        spki: prev?.cert?.spki,
      };
      if (!hadCert && fresh) kinds.push("cert_issued");
    }

    // Pages: live once, mimics-login once.
    if (pageFacts) {
      const { visibleText: _text, ...stored } = pageFacts;
      next.http = stored;
      if (ok2xx3xx(pageFacts.status) && !ok2xx3xx(prev?.http?.status)) kinds.push("page_live");
      const mimics = pageFacts.hasPasswordForm && pageFacts.brandTermFound;
      const mimicked = prev?.http?.hasPasswordForm && prev?.http?.brandTermFound;
      if (mimics && !mimicked) kinds.push("page_mimics_login");
      if (pageFacts.cert) {
        next.cert = {
          ...(next.cert || {}),
          fingerprint256: pageFacts.cert.fingerprint256,
          spki: pageFacts.cert.spki,
        };
      }
    }

    // RDAP: defensive registrations are ignored; old registrations stay quiet.
    let stale = false;
    if (rdapFacts) {
      const defensive = isDefensive(rdapFacts, ownRdap);
      next.rdap = { ...rdapFacts, defensive, fetchedAt: now };
      if (defensive) next.state = "ignored";
      stale = isStale(rdapFacts, now);
    } else if (prev?.rdap) {
      stale = isStale(prev.rdap, now);
    }

    let produced = kinds.map((kind) => {
      let severity = eventSeverity(kind, next);
      if (next.infra.parked && PARKED_LOW.has(kind)) severity = "low";
      if (stale && !ALWAYS_LOUD.has(kind)) severity = "low";
      const p = { ...payload };
      if (baseline && !ALWAYS_LOUD.has(kind)) p.baseline = true;
      if (stale && kind === "new_lookalike") p.stale = true;
      return { lookalike: name, kind, severity, payload: p };
    });

    if (next.state === "ignored") {
      produced = [];
    } else if (next.state === "dismissed") {
      produced = produced.filter((e) => compare(e.severity, prev.dismissedAtSeverity || "low") > 0);
      if (produced.length) next.state = "open";
    }

    for (const e of produced) {
      if (compare(e.severity, next.severity) > 0) next.severity = e.severity;
    }
    upserts.push(next);
    events.push(...produced);
  }

  return { upserts, events };
}

module.exports = { diffDomain, THRESHOLD };
