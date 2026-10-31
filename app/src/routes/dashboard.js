const { Router } = require("express");
const { requireAuth } = require("../middleware/session");
const { Domain, Sighting, Event, Mention } = require("../models");
const { byWorst } = require("../lib/view-helpers");

const router = Router();

router.get("/", requireAuth, async (req, res, next) => {
  try {
    const userId = req.user._id;
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const [domains, openBySev, openMentions, recentEvents, events, urgent] = await Promise.all([
      Domain.find({ userId }).sort({ name: 1 }).lean(),
      Sighting.aggregate([
        { $match: { userId, state: "open" } },
        { $group: { _id: "$severity", n: { $sum: 1 } } },
      ]),
      Mention.countDocuments({ userId, state: "open" }),
      Event.countDocuments({ userId, at: { $gte: since } }),
      Event.find({ userId }).sort({ at: -1 }).limit(100).lean(),
      Sighting.find({ userId, state: "open", severity: { $in: ["critical", "high"] } })
        .select("lookalike severity domainId lastSeenAt")
        .lean(),
    ]);
    const counts = Object.fromEntries(openBySev.map((g) => [g._id, g.n]));
    const worst = urgent.sort(byWorst)[0] || null;
    const worstEvent = worst
      ? await Event.findOne({ sightingId: worst._id }).sort({ at: -1 }).lean()
      : null;
    const domainNames = new Map(domains.map((d) => [String(d._id), d.name]));
    const watched = domains.map((d) => (d.lastWatchedAt ? +d.lastWatchedAt : 0));
    const lastWatchedAt = Math.max(0, ...watched) || null;
    res.render("dashboard", {
      title: "Dashboard",
      active: "dashboard",
      crumbs: ["Watch", "Dashboard"],
      domains,
      counts,
      worst,
      worstEvent,
      lastWatchedAt,
      stats: {
        domains: domains.length,
        openSightings: Object.values(counts).reduce((a, b) => a + b, 0),
        openMentions,
        recentEvents,
      },
      events: events.map((e) => ({ ...e, domainName: domainNames.get(String(e.domainId)) })),
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
