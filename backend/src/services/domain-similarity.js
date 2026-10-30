const stringSimilarity = require("string-similarity");
const logger = require("../logger");

/**
 * Score domains by Dice coefficient against a reference domain.
 * Returns matches whose similarity meets the threshold, sorted high-to-low.
 *
 * @param {string} reference   The protected (legitimate) domain.
 * @param {string[]} candidates Domains to compare against.
 * @param {number} threshold   Minimum similarity to keep (0..1).
 * @returns {{ domain: string, similarity: number }[]}
 */
function scoreDomains(reference, candidates, threshold = 0.7) {
  if (!reference || !candidates?.length) return [];
  const ref = reference.toLowerCase();
  const matches = [];
  for (const cand of candidates) {
    if (!cand) continue;
    const sim = stringSimilarity.compareTwoStrings(ref, String(cand).toLowerCase());
    if (sim >= threshold) {
      matches.push({ domain: String(cand).toLowerCase(), similarity: Number(sim.toFixed(4)) });
    }
  }
  matches.sort((a, b) => b.similarity - a.similarity);
  return matches;
}

/**
 * Returns true if any candidate is a substring of the reference's first label
 * (or vice-versa). Implements the legacy `DetectSubString` behavior.
 */
function isSubstringMatch(reference, candidate) {
  const refLabel = String(reference).toLowerCase().split(".")[0];
  const candLower = String(candidate).toLowerCase();
  return candLower.includes(refLabel);
}

/**
 * Detect punycode/IDN markers (`xn--` and common typo variants).
 */
function isPunycode(domain) {
  const d = String(domain).toLowerCase();
  return /(^|[.-])xn--/.test(d) || /(--xn|xn-|-xn)/.test(d);
}

/**
 * Compare the visible HTML text content of two URLs.
 * Returns a 0..1 similarity, or null if either fetch fails.
 */
async function compareTwoPages(urlA, urlB) {
  const cheerio = require("cheerio");
  async function bodyText(url) {
    const res = await fetch(url, { redirect: "follow" });
    if (!res.ok) throw new Error(`fetch ${url} -> ${res.status}`);
    const html = await res.text();
    return cheerio.load(html)("html").text();
  }
  try {
    const [a, b] = await Promise.all([bodyText(urlA), bodyText(urlB)]);
    return Number(stringSimilarity.compareTwoStrings(a, b).toFixed(4));
  } catch (err) {
    logger.warn({ err: { message: err.message }, urlA, urlB }, "compareTwoPages failed");
    return null;
  }
}

/**
 * SecureScore composite: 0..1 where HIGHER means SAFER (1 = no threat
 * signals). The UI colours >= 0.7 green and < 0.4 red. Threat points use
 * the legacy weighting (active server, substring, IDN, visual sim).
 */
function secureScore({ activeServer, substring, idn, visualSimilarity }) {
  let pts = 0;
  const max = 4;
  if (activeServer) pts += 1;
  if (substring) pts += 0.7;
  if (idn) pts += 0.7;
  if (typeof visualSimilarity === "number") pts += Math.min(1, visualSimilarity) * 0.7;
  return Number((1 - pts / max).toFixed(4));
}

module.exports = { scoreDomains, isSubstringMatch, isPunycode, compareTwoPages, secureScore };
