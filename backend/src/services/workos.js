const { WorkOS } = require("@workos-inc/node");
const { createRemoteJWKSet, jwtVerify } = require("jose");
const { env } = require("../config");
const logger = require("../logger");

const workos = new WorkOS(env.WORKOS_API_KEY);

const ISSUER = "https://api.workos.com";
const JWKS = createRemoteJWKSet(new URL(`${ISSUER}/sso/jwks/${env.WORKOS_CLIENT_ID}`));

/**
 * Verify a WorkOS-issued access token via the project's JWKS.
 * Returns the decoded payload on success, throws otherwise.
 *
 * Cache: `createRemoteJWKSet` caches keys in memory for 10 minutes by default.
 */
async function verifyAccessToken(token) {
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: ISSUER,
    // `aud` is set to the client ID for User Management access tokens.
    audience: env.WORKOS_CLIENT_ID,
  });
  return payload;
}

/**
 * Send an admin invitation for `email` into the configured organization.
 * `role` maps to a WorkOS roleSlug: analyst → member, admin → admin.
 */
async function sendInvitation({ email, role = "analyst", invitedBy, expiresInDays = 7 }) {
  const roleSlug = role === "admin" ? "admin" : "member";
  try {
    return await workos.userManagement.sendInvitation({
      email,
      organizationId: env.WORKOS_ORGANIZATION_ID,
      roleSlug,
      expiresInDays,
      inviterUserId: invitedBy || undefined,
    });
  } catch (err) {
    logger.warn({ err: { message: err.message }, email }, "workos sendInvitation failed");
    throw err;
  }
}

async function listInvitations() {
  return workos.userManagement.listInvitations({
    organizationId: env.WORKOS_ORGANIZATION_ID,
    limit: 100,
  });
}

async function revokeInvitation(invitationId) {
  return workos.userManagement.revokeInvitation(invitationId);
}

module.exports = { workos, verifyAccessToken, sendInvitation, listInvitations, revokeInvitation };
