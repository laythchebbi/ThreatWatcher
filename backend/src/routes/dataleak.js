const { Router } = require("express");

const validate = require("../middleware/validate");
const { requireUser } = require("../middleware/auth");
const { dataleakQuery } = require("../schemas/domain");

const LeakTelegram = require("../models/leakTelegram");
const LeakTwitter = require("../models/leakTwitter");
const LeakForum = require("../models/leakForum");
const DarkwebPage = require("../models/darkwebPage");

const router = Router();

router.use(requireUser);

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

router.get("/search", validate(dataleakQuery, "query"), async (req, res, next) => {
  try {
    // `validate(dataleakQuery)` has already coerced/validated these; coerce
    // again at the boundary so the types are honest without an unsafe cast.
    const q = String(req.query.q);
    const source = String(req.query.source);
    const limit = Number(req.query.limit);
    const re = new RegExp(escapeRegex(q), "i");

    const queries = {
      telegram: () => LeakTelegram.find({ text: re }).sort({ postedAt: -1 }).limit(limit).lean(),
      twitter: () => LeakTwitter.find({ text: re }).sort({ postedAt: -1 }).limit(limit).lean(),
      forum: () =>
        LeakForum.find({ $or: [{ title: re }, { body: re }] })
          .sort({ postedAt: -1 })
          .limit(limit)
          .lean(),
      darkweb: () =>
        DarkwebPage.find({ $or: [{ title: re }, { body: re }] })
          .sort({ crawledAt: -1 })
          .limit(limit)
          .lean(),
    };

    const sources = source === "all" ? Object.keys(queries) : [source];
    const results = {};
    for (const s of sources) {
      results[s] = await queries[s]();
    }

    const totalCount = Object.values(results).reduce((sum, arr) => sum + arr.length, 0);
    return res.json({ q, source, totalCount, results });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
