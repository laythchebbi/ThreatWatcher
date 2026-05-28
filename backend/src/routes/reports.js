const { Router } = require("express");
const Report = require("../models/report");
const { requireUser } = require("../middleware/auth");

const router = Router();

router.use(requireUser);

router.get("/", async (req, res, next) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 50, 200);
    const items = await Report.find({}).sort({ createdAt: -1 }).limit(limit);
    return res.json({ count: items.length, items });
  } catch (err) {
    return next(err);
  }
});

router.get("/:id", async (req, res, next) => {
  try {
    const report = await Report.findById(req.params.id);
    if (!report) return res.status(404).json({ error: "not_found" });
    return res.json({ report });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
