const { Router } = require("express");
const { requireAuth } = require("../middleware/session");
const { Domain, Sighting, Event } = require("../models");

const router = Router();

router.get("/", requireAuth, async (req, res, next) => {
  try {
    const userId = req.user._id;
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const [domains, openSightings, recentEvents, events] = await Promise.all([
      Domain.find({ userId }).sort({ name: 1 }).lean(),
      Sighting.countDocuments({ userId, state: "open" }),
      Event.countDocuments({ userId, at: { $gte: since } }),
      Event.find({ userId }).sort({ at: -1 }).limit(100).lean(),
    ]);
    const domainNames = new Map(domains.map((d) => [String(d._id), d.name]));
    res.render("dashboard", {
      title: "Dashboard",
      active: "dashboard",
      crumbs: ["Watch", "Dashboard"],
      domains,
      stats: { domains: domains.length, openSightings, recentEvents },
      events: events.map((e) => ({ ...e, domainName: domainNames.get(String(e.domainId)) })),
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
