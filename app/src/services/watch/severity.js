const LEVELS = ["low", "medium", "high", "critical"];

/** Base severity per event kind (spec 7.3, Plan 1 subset). */
const BASE = {
  new_lookalike: "low",
  dns_live: "medium",
  mx_live: "medium",
  infra_changed: "medium",
  gone: "low",
  cert_issued: "medium",
  page_live: "high",
  page_mimics_login: "critical",
  posture_weak: "low",
  leak_mention: "medium",
};

function bump(level, steps = 1) {
  const i = Math.max(0, LEVELS.indexOf(level));
  return LEVELS[Math.min(LEVELS.length - 1, i + steps)];
}

function compare(a, b) {
  return LEVELS.indexOf(a) - LEVELS.indexOf(b);
}

/**
 * Severity of an event on a sighting: base, +1 for punycode or substring
 * match, +1 when the lookalike has MX (it can send mail) except for mx_live
 * itself, which is the event that reports the MX.
 */
function eventSeverity(kind, sighting) {
  let level = BASE[kind] || "low";
  if (kind === "cert_issued") {
    // One bump when the name resolves or looks like the brand; auto-issued
    // certificates on parked names are not "high" (spec 7.3).
    if (sighting.dns?.resolves || sighting.punycode || sighting.substring) level = bump(level);
    return level;
  }
  if (sighting.punycode || sighting.substring) level = bump(level);
  if (kind !== "mx_live" && sighting.dns?.mx?.length) level = bump(level);
  return level;
}

module.exports = { LEVELS, BASE, bump, compare, eventSeverity };
