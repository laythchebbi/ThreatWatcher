const { Router } = require("express");

const validate = require("../middleware/validate");
const { requireUser } = require("../middleware/auth");
const { searchDomainParams } = require("../schemas/domain");

const Report = require("../models/report");

const similarity = require("../services/domain-similarity");
const fetching = require("../services/fetching-api");
const mlBridge = require("../services/ml-bridge");
const logger = require("../logger");

const router = Router();

router.use(requireUser);

router.get("/search/:domain", validate(searchDomainParams, "params"), async (req, res, next) => {
  try {
    const { domain } = req.params;
    const fuzzy = await fetching.dnsTwistFuzz(domain).catch((err) => {
      logger.warn({ err: { message: err.message }, domain }, "dnstwist failed");
      return [];
    });
    const candidates = fuzzy.map((f) => f.domain).filter(Boolean);
    const registered = await fetching.filterRegistered(candidates);
    const scored = similarity.scoreDomains(domain, registered, 0.7);

    const results = await Promise.all(
      scored.map(async (s) => {
        const ml = await mlBridge.classifyUrl(s.domain).catch(() => null);
        return {
          ...s,
          punycode: similarity.isPunycode(s.domain),
          substring: similarity.isSubstringMatch(domain, s.domain),
          mlLabel: ml?.label ?? null,
          mlScore: ml?.score ?? null,
        };
      })
    );

    return res.json({ domain, count: results.length, results });
  } catch (err) {
    return next(err);
  }
});

router.post("/scan/:domain", validate(searchDomainParams, "params"), async (req, res, next) => {
  try {
    const { domain } = req.params;
    const fuzzy = await fetching.dnsTwistFuzz(domain).catch(() => []);
    const candidates = fuzzy.map((f) => f.domain).filter(Boolean);
    const registered = await fetching.filterRegistered(candidates);
    const scored = similarity.scoreDomains(domain, registered, 0.7);

    const score = similarity.secureScore({
      activeServer: registered.length > 0,
      substring: scored.some((s) => similarity.isSubstringMatch(domain, s.domain)),
      idn: scored.some((s) => similarity.isPunycode(s.domain)),
      visualSimilarity: scored.length ? scored[0].similarity : 0,
    });

    const report = await Report.create({
      domain,
      secureScore: score,
      confidence: 0.85,
      findings: { lookalikes: scored.length },
      reportContent: { scored },
      createdBy: req.user._id,
    });

    return res.status(201).json({ report });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
