const { getIronSession } = require("iron-session");
const { env, isProd } = require("../config");
const logger = require("../logger");
const User = require("../models/user");

const ONE_DAY_MS = 24 * 60 * 60 * 1000;

/** @type {import("iron-session").SessionOptions} */
const SESSION_OPTS = {
  cookieName: env.SESSION_COOKIE_NAME,
  password: env.SESSION_PASSWORD,
  cookieOptions: {
    httpOnly: true,
    sameSite: "lax",
    secure: isProd,
    path: "/",
    maxAge: 60 * 60 * 24 * 30,
  },
};

/** @returns {Promise<import("iron-session").IronSession<any>>} */
function getSession(req, res) {
  return getIronSession(req, res, SESSION_OPTS);
}

/**
 * Populate req.user from the sealed cookie. A cookie whose `sv` no longer
 * matches users.sessionVersion is revoked (password change, reset, delete).
 * Re-seals a cookie older than a day so active users stay signed in.
 */
async function readSession(req, res, next) {
  req.user = null;
  try {
    const session = await getSession(req, res);
    req.session = session;
    if (!session.userId) return next();
    const user = await User.findById(session.userId);
    if (!user || session.sv !== user.sessionVersion) {
      session.destroy();
      return next();
    }
    req.user = user;
    if (!session.issuedAt || Date.now() - session.issuedAt > ONE_DAY_MS) {
      session.issuedAt = Date.now();
      await session.save();
    }
    return next();
  } catch (err) {
    logger.warn({ err: { message: err.message } }, "session read failed");
    req.session = null;
    return next();
  }
}

/** Same-site path or "/". Rejects absolute URLs, "//host" and "/\host" (browsers fold \ to /). */
function safeNext(value) {
  return typeof value === "string" && /^\/(?![/\\])/.test(value) ? value : "/";
}

function requireAuth(req, res, next) {
  if (req.user) return next();
  if (req.accepts("html")) {
    return res.redirect(`/login?next=${encodeURIComponent(req.originalUrl || "/")}`);
  }
  return res.status(401).json({ error: "unauthorized" });
}

/** Unverified accounts can look around but cannot add domains (abuse cap, spec 7.2). */
function requireVerified(req, res, next) {
  if (req.user && req.user.emailVerifiedAt) return next();
  if (req.accepts("html")) return res.redirect("/domains?verify=1");
  return res.status(403).json({ error: "email_unverified" });
}

module.exports = { getSession, readSession, requireAuth, requireVerified, safeNext };
