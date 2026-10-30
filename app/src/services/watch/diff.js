const { scoreDomains, isPunycode, isSubstringMatch } = require("../similarity");
const { classifyInfra } = require("./warninglists");
const { eventSeverity, compare } = require("./severity");

const THRESHOLD = 0.7;
const EMPTY_DNS = { resolves: false, a: [], mx: [], ns: [] };

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
 * }} input
 * @returns {{ upserts: object[], events: { lookalike: string, kind: string, severity: string, payload: object }[] }}
 */
function diffDomain({ domain, previous, observed, candidates, lists, now, baseline }) {
  const prevByName = new Map(previous.map((s) => [s.lookalike, s]));
  const names = [...new Set([...candidates, ...observed.keys(), ...prevByName.keys()])];
  const similarity = new Map(
    scoreDomains(domain.name, names, 0).map((s) => [s.domain, s.similarity])
  );

  const upserts = [];
  const events = [];

  for (const name of names) {
    const prev = prevByName.get(name);
    const dns = observed.get(name) || null;
    const sim = similarity.get(name) ?? 0;
    if (!prev && !dns && sim < THRESHOLD) continue;

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
    const payload = { lookalike: name };

    if (dns) {
      next.lastSeenAt = now;
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

    let produced = kinds.map((kind) => ({
      lookalike: name,
      kind,
      severity: next.infra.parked ? "low" : eventSeverity(kind, next),
      payload: baseline ? { ...payload, baseline: true } : { ...payload },
    }));

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
