const { verifyAccessToken } = require("../services/workos");
const User = require("../models/user");
const { env } = require("../config");
const logger = require("../logger");

/**
 * Authenticate an incoming request using a WorkOS access token.
 * The token comes from the `Authorization: Bearer <token>` header attached
 * by the frontend's `/api/*` proxy (which reads it from the sealed session
 * cookie). For service-to-service we still accept `X-Internal-Key`.
 *
 * On success: `req.auth` is set to the decoded WorkOS payload; `req.user`
 * to the local Mongo User doc (upserted on first sight).
 */
async function requireUser(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : null;
  if (!token) return res.status(401).json({ error: "unauthorized" });

  let payload;
  try {
    payload = await verifyAccessToken(token);
  } catch (err) {
    logger.debug({ err: { message: err.message } }, "access token verification failed");
    return res.status(401).json({ error: "unauthorized" });
  }

  req.auth = payload;

  // Upsert the local User row. WorkOS access tokens include:
  //   sub        → workosUserId
  //   email
  //   org_id     when the token is org-scoped (our single-tenant setup)
  //   role       roleSlug within the org ("admin" | "member"); the SDK
  //              has shipped both `role` and `org_role` over time, so we
  //              tolerate either.
  const workosUserId = String(payload.sub);
  const email = String(payload.email || "").toLowerCase();
  const roleSlug = payload.role || payload.role_slug || payload.org_role;
  const role = roleSlug === "admin" ? "admin" : "analyst";

  try {
    const user = await User.findOneAndUpdate(
      { workosUserId },
      {
        $set: {
          email,
          role,
          lastLoginAt: new Date(),
        },
        $setOnInsert: { workosUserId },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    if (user.deactivatedAt) {
      return res.status(403).json({ error: "account_deactivated" });
    }

    req.user = user;
    return next();
  } catch (err) {
    logger.error({ err, workosUserId }, "user upsert failed");
    return next(err);
  }
}

function requireServiceKey(req, res, next) {
  const key = req.headers["x-internal-key"];
  if (!key || key !== env.INTERNAL_API_KEY) {
    return res.status(401).json({ error: "unauthorized" });
  }
  return next();
}

function requireRole(role) {
  return function roleGuard(req, res, next) {
    if (!req.user) return res.status(401).json({ error: "unauthorized" });
    if (req.user.role !== role) return res.status(403).json({ error: "forbidden" });
    return next();
  };
}

module.exports = { requireUser, requireServiceKey, requireRole };
