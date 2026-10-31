/**
 * Shared plumbing for external providers: one token bucket per provider so
 * all cycles together stay under its rate, and one per-label cache so two
 * customers on the same brand cost one call (spec 7.4 step 2).
 */

/** Continuous-refill token bucket. `take()` resolves when a token is available. */
function createBucket({ perMinute, now = Date.now }) {
  const capacity = perMinute;
  const perMs = perMinute / 60_000;
  let tokens = capacity;
  let last = now();

  function refill() {
    const t = now();
    tokens = Math.min(capacity, tokens + (t - last) * perMs);
    last = t;
  }

  function take() {
    refill();
    if (tokens >= 1) {
      tokens -= 1;
      return Promise.resolve();
    }
    return new Promise((resolve) => {
      const poll = () => {
        refill();
        if (tokens >= 1) {
          tokens -= 1;
          resolve();
        } else {
          const waitMs = Math.min(1000, Math.max(5, Math.ceil((1 - tokens) / perMs)));
          setTimeout(poll, waitMs).unref?.();
        }
      };
      setTimeout(poll, 5).unref?.();
    });
  }

  return { take };
}

/** Map with a TTL; expired entries read as missing. */
function createCache({ ttlMs, now = Date.now }) {
  const store = new Map();
  const live = (key) => {
    const e = store.get(key);
    if (!e) return undefined;
    if (e.expiresAt <= now()) {
      store.delete(key);
      return undefined;
    }
    return e;
  };
  return {
    get: (key) => live(key)?.value,
    has: (key) => Boolean(live(key)),
    set: (key, value) => {
      store.set(key, { value, expiresAt: now() + ttlMs });
      if (store.size > 10_000) {
        for (const k of store.keys()) if (!live(k)) store.delete(k);
      }
    },
  };
}

const buckets = {
  crtsh: createBucket({ perMinute: 30 }),
  certspotter: createBucket({ perMinute: 60 }),
  dnstwister: createBucket({ perMinute: 30 }),
  rdap: createBucket({ perMinute: 60 }),
  hibp: createBucket({ perMinute: 10 }),
};

const labelCache = createCache({ ttlMs: 6 * 3600_000 });

module.exports = { createBucket, createCache, buckets, labelCache };
