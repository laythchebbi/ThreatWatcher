// In-memory fixed-window limiter. One process, so a Map is enough (spec 7.2).
const buckets = new Map();

/**
 * @param {{ windowMs: number, max: number, key: (req: any) => string, now?: () => number }} opts
 */
function rateLimit({ windowMs, max, key, now = Date.now }) {
  return function limiter(req, res, next) {
    const k = key(req);
    const t = now();
    let b = buckets.get(k);
    if (!b || b.resetAt <= t) {
      b = { count: 0, resetAt: t + windowMs };
      buckets.set(k, b);
    }
    b.count += 1;
    if (b.count > max) return res.status(429).json({ error: "rate_limited" });
    return next();
  };
}

rateLimit._reset = () => buckets.clear();

module.exports = { rateLimit };
