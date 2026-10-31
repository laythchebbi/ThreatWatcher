const { z } = require("zod");

const MAX_TERMS = 5;
const COMMON_RATIO = 0.05;

/** A brand term: 4–40 chars, lowercased. */
const termSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(4, "term too short")
  .max(40, "term too long");

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** True when the term matches more than 5 % of crawled pages (too generic to alert on). */
async function tooCommon(term, { DarkwebPage }) {
  const total = await DarkwebPage.countDocuments();
  if (!total) return false;
  const pattern = escapeRegex(term).replace(/(?:\\-|\s)+/g, "[-\\s]+");
  const re = new RegExp(`\\b${pattern}\\b`, "i");
  const hits = await DarkwebPage.countDocuments({ $or: [{ title: re }, { body: re }] });
  return hits / total > COMMON_RATIO;
}

module.exports = { termSchema, tooCommon, MAX_TERMS };
