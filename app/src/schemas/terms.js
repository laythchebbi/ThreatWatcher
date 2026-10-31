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

const { termRegex } = require("../services/watch/leaks");

/** True when the term matches more than 5 % of crawled pages (too generic to alert on). */
async function tooCommon(term, { DarkwebPage }) {
  const total = await DarkwebPage.countDocuments();
  if (!total) return false;
  const re = termRegex(term);
  const hits = await DarkwebPage.countDocuments({ $or: [{ title: re }, { body: re }] });
  return hits / total > COMMON_RATIO;
}

module.exports = { termSchema, tooCommon, MAX_TERMS };
