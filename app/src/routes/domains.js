const { Router } = require("express");
const { env } = require("../config");
const { requireAuth, requireVerified } = require("../middleware/session");
const validate = require("../middleware/validate");
const { domainBody } = require("../schemas/domain");
const { termSchema, tooCommon, MAX_TERMS } = require("../schemas/terms");
const { DarkwebPage, Mention } = require("../models");
const { Domain, Sighting, Event } = require("../models");
const { byWorst, sevRank } = require("../lib/view-helpers");

const router = Router();
router.use(requireAuth);

const NOTICES = {
  verified: "Email verified.",
  verify: "Verify your email to add domains.",
  domain_limit: `You can watch up to ${env.MAX_DOMAINS_PER_ACCOUNT} domains for now.`,
  domain_exists: "That domain is already watched.",
  term_invalid: "Brand terms are 4 to 40 characters.",
  term_limit: `Up to ${MAX_TERMS} brand terms per domain.`,
  term_common: "That term matches too many pages to be useful; pick something more specific.",
  hibp_key_invalid: "That does not look like a Have I Been Pwned API key.",
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
      Mention.deleteMany({ domainId }),
      Domain.deleteOne({ _id: domainId }),
    ]);
    return res.redirect("/domains");
  } catch (err) {
    return next(err);
  }
});

const WEEK_MS = 7 * 24 * 3600_000;
const TAB_ORDER = ["new", "changed", "watched", "inactive", "ignored"];

/** New / Watched / Changed / Inactive / Ignored, per spec 7.6. */
function tabOf(sighting, changedIds, now) {
  if (sighting.state === "ignored") return "ignored";
  if (sighting.inactive) return "inactive";
  if (changedIds.has(String(sighting._id))) return "changed";
  if (now - new Date(sighting.firstSeenAt).getTime() < WEEK_MS) return "new";
  return "watched";
}

router.get("/:id", loadDomain, async (req, res, next) => {
  try {
    const domainId = req.domain._id;
    const now = Date.now();
    const [events, sightings, changed, mentions] = await Promise.all([
      Event.find({ domainId }).sort({ at: -1 }).limit(100).lean(),
      // severity is a string enum: sort by rank in JS, not by the string.
      Sighting.find({ domainId }).sort({ lastSeenAt: -1 }).lean(),
      Event.distinct("sightingId", {
        domainId,
        kind: "infra_changed",
        at: { $gte: new Date(now - WEEK_MS) },
      }),
      Mention.find({ domainId }).sort({ firstSeenAt: -1 }).limit(50).lean(),
    ]);
    const changedIds = new Set(changed.map(String));
    const tabs = { new: [], watched: [], changed: [], inactive: [], ignored: [] };
    for (const s of sightings) tabs[tabOf(s, changedIds, now)].push(s);
    for (const list of Object.values(tabs)) list.sort(byWorst);
    // Open on the tab that holds the worst open sighting; Watched when nothing is open.
    const openTab = TAB_ORDER.filter((k) => k !== "ignored" && k !== "inactive").reduce(
      (best, k) => {
        const worst = Math.max(
          -1,
          ...tabs[k].filter((s) => s.state === "open").map((s) => sevRank(s.severity))
        );
        return worst > best.worst ? { tab: k, worst } : best;
      },
      { tab: "watched", worst: -1 }
    ).tab;
    res.render("domain", {
      title: req.domain.name,
      active: "domains",
      crumbs: ["Watch", "Domains", req.domain.name],
      domain: req.domain,
      events,
      tabs,
      tabOrder: TAB_ORDER,
      openTab,
      counts: Object.fromEntries(Object.entries(tabs).map(([k, v]) => [k, v.length])),
      mentions,
    });
  } catch (err) {
    next(err);
  }
});

router.post("/:id/terms", loadDomain, async (req, res, next) => {
  try {
    const parsed = termSchema.safeParse(req.body?.term);
    if (!parsed.success) return refuse(req, res, 400, "term_invalid");
    if (/** @type {string[]} */ (req.domain.terms || []).length >= MAX_TERMS)
      return refuse(req, res, 422, "term_limit");
    if (await tooCommon(parsed.data, { DarkwebPage })) return refuse(req, res, 422, "term_common");
    await Domain.updateOne({ _id: req.domain._id }, { $addToSet: { terms: parsed.data } });
    if (req.accepts(["json", "html"]) === "html") return res.redirect(`/domains/${req.domain._id}`);
    return res.json({ ok: true, term: parsed.data });
  } catch (err) {
    return next(err);
  }
});

router.post("/:id/terms/delete", loadDomain, async (req, res, next) => {
  try {
    await Domain.updateOne(
      { _id: req.domain._id },
      { $pull: { terms: String(req.body?.term || "").toLowerCase() } }
    );
    if (req.accepts(["json", "html"]) === "html") return res.redirect(`/domains/${req.domain._id}`);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
});

router.post("/:id/hibp", loadDomain, async (req, res, next) => {
  try {
    const apiKey = String(req.body?.apiKey || "").trim();
    if (!/^[A-Za-z0-9]{16,128}$/.test(apiKey)) return refuse(req, res, 400, "hibp_key_invalid");
    await Domain.updateOne(
      { _id: req.domain._id },
      { $set: { hibp: { apiKey, lastBreachSeen: null, error: null } } }
    );
    if (req.accepts(["json", "html"]) === "html") return res.redirect(`/domains/${req.domain._id}`);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
});

router.post("/:id/hibp/delete", loadDomain, async (req, res, next) => {
  try {
    await Domain.updateOne({ _id: req.domain._id }, { $unset: { hibp: 1 } });
    if (req.accepts(["json", "html"]) === "html") return res.redirect(`/domains/${req.domain._id}`);
    return res.json({ ok: true });
  } catch (err) {
    return next(err);
  }
});

const MENTION_TRANSITIONS = {
  dismiss: (m) => ({ state: "dismissed", dismissedAtSeverity: m.severity }),
  reopen: () => ({ state: "open" }),
};

router.post("/:id/mentions/:mid/:action(dismiss|reopen)", loadDomain, async (req, res, next) => {
  try {
    const mention = await Mention.findOne({ _id: req.params.mid, domainId: req.domain._id });
    if (!mention) return res.status(404).json({ error: "not_found" });
    const patch = MENTION_TRANSITIONS[req.params.action](mention);
    await Mention.updateOne({ _id: mention._id }, { $set: patch });
    if (req.accepts(["json", "html"]) === "html") return res.redirect(`/domains/${req.domain._id}`);
    return res.json({ ok: true, state: patch.state });
  } catch (err) {
    return next(err);
  }
});

router.post("/:id/scan", loadDomain, async (req, res, next) => {
  try {
    await Domain.updateOne(
      { _id: req.domain._id },
      { $set: { nextWatchAt: new Date(), watchingSince: null } }
    );
    return res.redirect(`/domains/${req.domain._id}`);
  } catch (err) {
    return next(err);
  }
});

const TRANSITIONS = {
  dismiss: (s) => ({ state: "dismissed", dismissedAtSeverity: s.severity }),
  ignore: () => ({ state: "ignored" }),
  reopen: () => ({ state: "open" }),
};

router.post(
  "/:id/sightings/:sid/:action(dismiss|ignore|reopen)",
  loadDomain,
  async (req, res, next) => {
    try {
      const sighting = await Sighting.findOne({ _id: req.params.sid, domainId: req.domain._id });
      if (!sighting) return res.status(404).json({ error: "not_found" });
      const patch = TRANSITIONS[req.params.action](sighting);
      await Sighting.updateOne({ _id: sighting._id }, { $set: patch });
      if (req.accepts(["json", "html"]) === "html")
        return res.redirect(`/domains/${req.domain._id}`);
      return res.json({ ok: true, state: patch.state });
    } catch (err) {
      return next(err);
    }
  }
);

module.exports = router;
module.exports.loadDomain = loadDomain;
