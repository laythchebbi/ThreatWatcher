const { WorkOS } = require("@workos-inc/node");
const { env } = require("../config");

const workos = new WorkOS(env.WORKOS_API_KEY);

/**
 * Build the AuthKit authorize URL. By default uses the AuthKit-hosted
 * sign-in page (which routes to email/password OR OAuth providers
 * depending on what's enabled in the WorkOS dashboard).
 *
 * To force a specific provider, pass `provider: "GoogleOAuth"`.
 */
function authorizationUrl({ state, provider = "authkit" }) {
  return workos.userManagement.getAuthorizationUrl({
    provider,
    clientId: env.WORKOS_CLIENT_ID,
    redirectUri: env.WORKOS_REDIRECT_URI,
    state,
  });
}

async function authenticateWithCode(code) {
  return workos.userManagement.authenticateWithCode({
    clientId: env.WORKOS_CLIENT_ID,
    code,
  });
}

async function refreshAccessToken(refreshToken) {
  return workos.userManagement.authenticateWithRefreshToken({
    clientId: env.WORKOS_CLIENT_ID,
    refreshToken,
  });
}

module.exports = { workos, authorizationUrl, authenticateWithCode, refreshAccessToken };
