/**
 * CSRF second belt beside sameSite=lax: state-changing requests must come
 * from our own host when the browser says where they came from.
 * Requests with neither Origin nor Referer are allowed (non-browser clients).
 */
function originCheck(baseUrl) {
  const ownHost = new URL(baseUrl).host;
  return function check(req, res, next) {
    if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") return next();
    const source = req.headers.origin || req.headers.referer;
    if (!source) return next();
    let host;
    try {
      host = new URL(String(source)).host;
    } catch {
      return res.status(403).json({ error: "bad_origin" });
    }
    if (host !== ownHost) return res.status(403).json({ error: "bad_origin" });
    return next();
  };
}

module.exports = { originCheck };
