const crypto = require("node:crypto");

// scrypt params per spec 7.2. maxmem is explicit: 128 * N * r = 16 MiB here,
// and Node throws if a later N bump crosses the default 32 MiB silently.
const N = 16384;
const R = 8;
const P = 1;
const KEYLEN = 64;
const MAXMEM = 64 * 1024 * 1024;

function scrypt(plain, salt, n, r, p) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(plain, salt, KEYLEN, { N: n, r, p, maxmem: MAXMEM }, (err, key) =>
      err ? reject(err) : resolve(key)
    );
  });
}

/** @returns {Promise<string>} `scrypt$N$r$p$<salt b64>$<hash b64>` */
async function hashPassword(plain) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(plain, salt, N, R, P);
  return `scrypt$${N}$${R}$${P}$${salt.toString("base64")}$${key.toString("base64")}`;
}

/** Constant-time compare against a stored hash. Malformed input → false, never throws. */
async function verifyPassword(plain, stored) {
  try {
    const [algo, n, r, p, saltB64, hashB64] = String(stored).split("$");
    if (algo !== "scrypt" || !saltB64 || !hashB64) return false;
    const expected = Buffer.from(hashB64, "base64");
    const key = await scrypt(
      plain,
      Buffer.from(saltB64, "base64"),
      Number(n),
      Number(r),
      Number(p)
    );
    return key.length === expected.length && crypto.timingSafeEqual(key, expected);
  } catch {
    return false;
  }
}

// Verified against when the email is unknown, so login timing does not reveal accounts.
const DUMMY_HASH = hashPassword(crypto.randomBytes(32).toString("hex"));

module.exports = { hashPassword, verifyPassword, DUMMY_HASH };
