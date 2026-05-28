const { Router } = require("express");
const { z } = require("zod");

const User = require("../models/user");
const validate = require("../middleware/validate");
const { requireUser, requireRole } = require("../middleware/auth");
const { domainName } = require("../schemas/domain");
const { profileUpdate } = require("../schemas/auth");

const router = Router();
router.use(requireUser);

const monitoredUpdate = z.object({
  monitoredDomains: z.array(domainName).max(200),
});

const roleChange = z.object({
  role: z.enum(["analyst", "admin"]),
});

router.get("/me", (req, res) => {
  res.json({ user: req.user });
});

router.patch("/me", validate(profileUpdate), async (req, res, next) => {
  try {
    const user = await User.findByIdAndUpdate(req.user._id, req.body, { new: true });
    return res.json({ user });
  } catch (err) {
    return next(err);
  }
});

router.put("/me/monitored", validate(monitoredUpdate), async (req, res, next) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { monitoredDomains: req.body.monitoredDomains },
      { new: true }
    );
    return res.json({ monitoredDomains: user.monitoredDomains });
  } catch (err) {
    return next(err);
  }
});

// ── Admin-only user management ─────────────────────────────────────────────

router.get("/", requireRole("admin"), async (_req, res, next) => {
  try {
    const items = await User.find({}).sort({ createdAt: -1 }).limit(500);
    return res.json({ count: items.length, items });
  } catch (err) {
    return next(err);
  }
});

router.patch("/:id/role", requireRole("admin"), validate(roleChange), async (req, res, next) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { role: req.body.role },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: "not_found" });
    return res.json({ user });
  } catch (err) {
    return next(err);
  }
});

router.post("/:id/deactivate", requireRole("admin"), async (req, res, next) => {
  try {
    if (String(req.user._id) === req.params.id) {
      return res.status(400).json({ error: "cannot_deactivate_self" });
    }
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { deactivatedAt: new Date() },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: "not_found" });
    return res.json({ user });
  } catch (err) {
    return next(err);
  }
});

router.post("/:id/reactivate", requireRole("admin"), async (req, res, next) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { deactivatedAt: null },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: "not_found" });
    return res.json({ user });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
