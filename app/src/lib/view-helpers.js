const { domainToUnicode } = require("node:url");
const { LEVELS } = require("../services/watch/severity");

/** Plain-language names for event kinds; the codes stay in the data. */
const EVENT_LABELS = {
  new_lookalike: "Lookalike registered",
  dns_live: "Now resolves in DNS",
  mx_live: "Can receive mail (MX)",
  infra_changed: "Infrastructure changed",
  gone: "Stopped resolving",
  cert_issued: "TLS certificate issued",
  page_live: "Web page went live",
  page_mimics_login: "Login page copy is live",
  posture_weak: "Your email posture is weak",
  leak_mention: "Mentioned in a leak",
};

const CHANGED_LABELS = { a: "A record", mx: "MX", ns: "name servers" };

/** "2026-10-31 17:27" in UTC; pages say "UTC" once in the header or column. */
function fmtTime(d) {
  return d ? new Date(d).toISOString().slice(0, 16).replace("T", " ") : "—";
}

function fmtDate(d) {
  return d ? new Date(d).toISOString().slice(0, 10) : "—";
}

/** Higher is worse: critical 3 … low 0, unknown -1. */
const sevRank = (s) => LEVELS.indexOf(s);

const byWorst = (a, b) => sevRank(b.severity) - sevRank(a.severity);

module.exports = {
  fmtTime,
  fmtDate,
  sevRank,
  byWorst,
  eventLabel: (kind) => EVENT_LABELS[kind] || kind,
  changedLabel: (keys) => (keys || []).map((k) => CHANGED_LABELS[k] || k).join(", "),
  sevLabel: (s) => (s ? s[0].toUpperCase() + s.slice(1) : ""),
  // An IDN lookalike shows its Unicode form next to the punycode.
  unicodeOf: (name) => {
    const u = domainToUnicode(name);
    return u && u !== name ? u : "";
  },
};
