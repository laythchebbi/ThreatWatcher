const { Router } = require("express");
const { requireAuth } = require("../middleware/session");
const { Mention, Domain, DarkwebPage, DarkwebSource } = require("../models");

const router = Router();

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Open leak mentions across the user's domains, plus a literal keyword search over crawled pages. */
router.get("/", requireAuth, async (req, res, next) => {
  try {
    const userId = req.user._id;
    const q = String(req.query.q || "").trim();
    const [mentions, domains, sourceCount, lastSource] = await Promise.all([
      Mention.find({ userId, state: "open" }).sort({ firstSeenAt: -1 }).limit(100).lean(),
      Domain.find({ userId }, { name: 1 }).lean(),
      DarkwebSource.countDocuments({ enabled: true }),
      DarkwebSource.findOne({ lastCrawledAt: { $ne: null } })
        .sort({ lastCrawledAt: -1 })
        .lean(),
    ]);
    const domainNames = new Map(domains.map((d) => [String(d._id), d.name]));
    let results = null;
    if (q.length >= 2 && q.length <= 200) {
      const re = new RegExp(escapeRegex(q), "i");
      const pages = await DarkwebPage.find({ $or: [{ title: re }, { body: re }] })
        .sort({ crawledAt: -1 })
        .limit(50)
        .lean();
      results = pages.map((p) => {
        const idx = p.body.search(re);
        const start = Math.max(0, idx - 120);
        return { ...p, excerpt: idx < 0 ? p.body.slice(0, 240) : p.body.slice(start, idx + 120) };
      });
    }
    res.render("dark-web", {
      title: "Dark web",
      active: "darkweb",
      crumbs: ["Watch", "Dark web"],
      mentions: mentions.map((m) => ({ ...m, domainName: domainNames.get(String(m.domainId)) })),
      q,
      results,
      sourceCount,
      lastCrawledAt: lastSource?.lastCrawledAt || null,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
