const { z } = require("zod");

const invitationBody = z.object({
  email: z.string().trim().toLowerCase().email(),
  role: z.enum(["analyst", "admin"]).default("analyst"),
  expiresInDays: z.coerce.number().int().min(1).max(30).default(7),
});

const profileUpdate = z.object({
  displayName: z.string().trim().min(1).max(80).optional(),
});

module.exports = { invitationBody, profileUpdate };
