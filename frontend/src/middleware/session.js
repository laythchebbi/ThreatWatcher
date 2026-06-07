const { getIronSession } = require("iron-session");
const { env, isProd, isDemo } = require("../config");
const logger = require("../logger");
const workosService = require("../services/workos");

// Fixed mock identity used when DEMO_MODE is on.
const DEMO_USER = {
  id: "demo-user",
  email: "demo@threatwatcher.local",
  role: "admin",
  displayName: "Demo Analyst",
};

/**
 * Best-effort decode of a JWT *without* verification. We use this only to
 * extract org/role claims from a token we just received from WorkOS over
 * TLS (i.e. the source is already trusted) and want to inline on the
 * session. Real authentication happens on the backend with full JWKS
 * verification — this never gates access.
 */
function decodeClaims(jwt) {
  try {
    const [, payloadB64] = String(jwt || "").split(".");
    if (!payloadB64) return {};
    const json = Buffer.from(payloadB64, "base64url").toString("utf8");
    return JSON.parse(json);
  } catch {
    return {};
  }
}

/** @type {import("iron-session").SessionOptions} */
const SESSION_OPTS = {
  cookieName: env.SESSION_COOKIE_NAME,
  password: env.SESSION_PASSWORD,
  cookieOptions: {
    httpOnly: true,
    sameSite: "lax",
    secure: env.SESSION_COOKIE_SECURE || isProd,
    path: "/",
    maxAge: 60 * 60 * 24 * 7, // 7 days; refresh tokens re-extend
  },
};

/** @returns {Promise<import("iron-session").IronSession<any>>} */
async function getSession(req, res) {
  return getIronSession(req, res, SESSION_OPTS);
}

/**
 * Populate `req.user` and `req.session` from the sealed cookie. Always
 * resolves (never throws); missing/invalid → req.user = null.
 */
async function readSession(req, res, next) {
  if (isDemo) {
    req.user = DEMO_USER;
    req.token = "demo-token";
    req.session = null;
    return next();
  }
  try {
    const session = await getSession(req, res);
    req.session = session;
    req.user = session.workos?.user || null;
    req.token = session.workos?.accessToken || null;
    return next();
  } catch (err) {
    logger.warn({ err: { message: err.message } }, "session decode failed");
    req.session = null;
    req.user = null;
    req.token = null;
    return next();
  }
}

function requireAuth(req, res, next) {
  if (!req.user) {
    if (req.accepts("html"))
      return res.redirect(`/auth/sign-in?next=${encodeURIComponent(req.originalUrl)}`);
    return res.status(401).json({ error: "unauthorized" });
  }
  return next();
}

function requireRole(role) {
  return function roleGuard(req, res, next) {
    if (!req.user) return res.status(401).json({ error: "unauthorized" });
    if ((req.user.role || "") !== role) return res.status(403).json({ error: "forbidden" });
    return next();
  };
}

/**
 * Refresh the access token using the stored refresh token. Updates the
 * session in-place and returns the new access token, or `null` if refresh
 * fails (caller should redirect to sign-in).
 */
async function refreshSession(req, _res) {
  if (!req.session?.workos?.refreshToken) return null;
  try {
    const out = await workosService.refreshAccessToken(req.session.workos.refreshToken);
    const claims = decodeClaims(out.accessToken);
    const role = claims.role || claims.role_slug || claims.org_role || null;
    req.session.workos.accessToken = out.accessToken;
    req.session.workos.refreshToken = out.refreshToken;
    req.session.workos.user = { ...out.user, role };
    req.session.workos.organizationId = claims.org_id || req.session.workos.organizationId;
    await req.session.save();
    req.token = out.accessToken;
    req.user = req.session.workos.user;
    return out.accessToken;
  } catch (err) {
    logger.warn({ err: { message: err.message } }, "refresh failed; destroying session");
    req.session.destroy();
    return null;
  }
}

module.exports = {
  getSession,
  readSession,
  requireAuth,
  requireRole,
  refreshSession,
  decodeClaims,
};
