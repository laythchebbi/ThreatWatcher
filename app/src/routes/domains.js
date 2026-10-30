const { Router } = require("express");
const { env } = require("../config");
const { requireAuth, requireVerified } = require("../middleware/session");
const validate = require("../middleware/validate");
const { domainBody } = require("../schemas/domain");
const { Domain, Sighting, Event } = require("../models");

const router = Router();
router.use(requireAuth);

const NOTICES = {
  verified: "Email verified.",
  verify: "Verify your email to add domains.",
  domain_limit: `You can watch up to ${env.MAX_DOMAINS_PER_ACCOUNT} domains for now.`,
  domain_exists: "That domain is already watched.",
};

router.get("/", async (req, res, next) => {
  try {
    const userId = req.user._id;
    const domains = await Domain.find({ userId }).sort({ name: 1 }).lean();
    const counts = await Sighting.aggregate([
      { $match: { userId, state: "open" } },
      { $group: { _id: "$domainId", n: { $sum: 1 } } },
    ]);
    const open = new Map(counts.map((c) => [String(c._id), c.n]));
    res.render("domains", {
      title: "Domains",
      active: "domains",
      crumbs: ["Watch", "Domains"],
      domains: domains.map((d) => ({ ...d, openSightings: open.get(String(d._id)) || 0 })),
      limit: env.MAX_DOMAINS_PER_ACCOUNT,
      verified: Boolean(req.user.emailVerifiedAt),
      notice:
        NOTICES[
          String(
            req.query.verified ? "verified" : req.query.verify ? "verify" : req.query.error || ""
          )
        ] || null,
    });
  } catch (err) {
    next(err);
  }
});

router.post("/", requireVerified, validate(domainBody), async (req, res, next) => {
  try {
    const userId = req.user._id;
    const count = await Domain.countDocuments({ userId });
    if (count >= env.MAX_DOMAINS_PER_ACCOUNT) return refuse(req, res, 422, "domain_limit");
    const existing = await Domain.findOne({ userId, name: req.body.name });
    if (existing) return refuse(req, res, 409, "domain_exists");
    await Domain.create({ userId, name: req.body.name, nextWatchAt: new Date() });
    return res.redirect("/domains");
  } catch (err) {
    return next(err);
  }
});

/** JSON for API callers, a redirect with a notice for browser forms. */
function refuse(req, res, status, code) {
  if (req.accepts(["json", "html"]) === "html") return res.redirect(`/domains?error=${code}`);
  return res.status(status).json({ error: code });
}

/** Resolve :id to the caller's domain or 404. Used by every per-domain route. */
async function loadDomain(req, res, next) {
  try {
    const domain = await Domain.findOne({ _id: req.params.id, userId: req.user._id });
    if (!domain) return res.status(404).json({ error: "not_found" });
    req.domain = domain;
    return next();
  } catch (err) {
    return next(err);
  }
}

router.post("/:id/delete", loadDomain, async (req, res, next) => {
  try {
    const domainId = req.domain._id;
    await Promise.all([
      Sighting.deleteMany({ domainId }),
      Event.deleteMany({ domainId }),
      Domain.deleteOne({ _id: domainId }),
    ]);
    return res.redirect("/domains");
  } catch (err) {
    return next(err);
  }
});

// Task 11 renders the real page; until then show the stub.
router.get("/:id", loadDomain, (req, res) =>
  res.render("placeholder", {
    title: req.domain.name,
    active: "domains",
    crumbs: ["Watch", "Domains", req.domain.name],
  })
);

module.exports = router;
module.exports.loadDomain = loadDomain;
