const { Router } = require("express");

const validate = require("../middleware/validate");
const { requireUser, requireRole } = require("../middleware/auth");
const { invitationBody } = require("../schemas/auth");
const workosService = require("../services/workos");
const logger = require("../logger");

const router = Router();

/**
 * Return the local + WorkOS view of the current user.
 * This is the only "session" endpoint — login is handled by WorkOS AuthKit
 * via the frontend redirect flow.
 */
router.get("/me", requireUser, (req, res) => {
  res.json({
    user: req.user,
    workos: {
      sub: req.auth.sub,
      email: req.auth.email,
      // For org-scoped tokens (our single-tenant setup) WorkOS sets `org_id`
      // and `role` (a.k.a. `roleSlug`) on the access token directly.
      role: req.auth.role || req.auth.role_slug || req.auth.org_role || null,
      organizationId: req.auth.org_id || null,
      permissions: req.auth.permissions || [],
    },
  });
});

/**
 * Admin: send an invitation. The recipient gets a WorkOS-hosted AuthKit link
 * to enroll (password / OAuth / TOTP). The role baked into the invitation
 * carries through to the access-token claim on first sign-in, which the
 * backend middleware uses to set the local `users.role`. No local pre-seed
 * needed — the row is created on first sight.
 */
router.post(
  "/invitations",
  requireUser,
  requireRole("admin"),
  validate(invitationBody),
  async (req, res, next) => {
    try {
      const { email, role, expiresInDays } = req.body;
      const invitation = await workosService.sendInvitation({
        email,
        role,
        expiresInDays,
        invitedBy: req.auth.sub,
      });
      logger.info({ email, role, invitationId: invitation.id }, "invitation sent");
      return res.status(201).json({ invitation });
    } catch (err) {
      return next(err);
    }
  }
);

router.get("/invitations", requireUser, requireRole("admin"), async (_req, res, next) => {
  try {
    const list = await workosService.listInvitations();
    return res.json({ invitations: list.data || list });
  } catch (err) {
    return next(err);
  }
});

router.delete("/invitations/:id", requireUser, requireRole("admin"), async (req, res, next) => {
  try {
    await workosService.revokeInvitation(req.params.id);
    return res.status(204).end();
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
