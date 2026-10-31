const dnsPromises = require("node:dns/promises");
const tls = require("node:tls");
const crypto = require("node:crypto");
const cheerio = require("cheerio");
const stringSimilarity = require("string-similarity");
const { mapBounded } = require("./dns");

const USER_AGENT = "ThreatWatcher/2 (+https://github.com/threat-watcher)";
const TIMEOUT_MS = 8000;
const MAX_REDIRECTS = 3;
const BODY_CAP = 256 * 1024;

/** Loopback, RFC 1918, link-local, ULA, multicast, unspecified, cloud metadata. */
function isPrivateIp(ip) {
  const v4 = ip.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a >= 224) return true;
    return false;
  }
  const v6 = ip.toLowerCase();
  if (v6 === "::1" || v6 === "::") return true;
  if (/^f[cd]/.test(v6) || /^fe[89ab]/.test(v6) || /^ff/.test(v6)) return true;
  if (v6.startsWith("::ffff:")) return isPrivateIp(v6.slice(7));
  return false;
}

const isLoopback = (ip) => ip.startsWith("127.") || ip === "::1";

async function guardHost(host, { resolver, allowPrivate }) {
  const addrs = [];
  for (const fn of ["resolve4", "resolve6"]) {
    try {
      addrs.push(...(await resolver[fn](host)));
    } catch {
      /* one family missing is fine */
    }
  }
  if (!addrs.length) return "unresolved";
  const blocked = addrs.some((a) => isPrivateIp(a) && !(allowPrivate && isLoopback(a)));
  return blocked ? "private_target" : null;
}

const { termRegex } = require("./leaks");

async function readCapped(res) {
  const reader = res.body?.getReader?.();
  if (!reader) return { text: await res.text(), truncated: false };
  const chunks = [];
  let size = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    chunks.push(value);
    if (size >= BODY_CAP) {
      truncated = true;
      await reader.cancel().catch(() => {});
      break;
    }
  }
  return { text: Buffer.concat(chunks).subarray(0, BODY_CAP).toString("utf8"), truncated };
}

function analyse(html, { brandTerms, referenceText }) {
  const $ = cheerio.load(html);
  $("script, style, noscript, template, svg, iframe, [hidden]").remove();
  $(
    '[style*="display:none"], [style*="display: none"], [style*="visibility:hidden"], [style*="visibility: hidden"]'
  ).remove();
  const title = $("title").first().text().trim();
  const visibleText = $("body").text().replace(/\s+/g, " ").trim();
  const linkHosts = $("a[href]")
    .map((_, a) => {
      try {
        return new URL($(a).attr("href"), "http://x/").host;
      } catch {
        return "";
      }
    })
    .get()
    .join(" ");
  const haystack = `${title} ${visibleText} ${linkHosts}`;
  const brandTermFound = brandTerms.some((t) => termRegex(t).test(haystack));
  const hasPasswordForm = $('input[type="password"]').length > 0;
  const similarity = referenceText
    ? Number(stringSimilarity.compareTwoStrings(visibleText, referenceText).toFixed(4))
    : null;
  return { title, visibleText, brandTermFound, hasPasswordForm, similarity };
}

/**
 * Fetch one lookalike's page with the SSRF guard (spec 7.4 step 4).
 * @returns {Promise<object>} PageFacts
 */
async function fetchPage(name, opts) {
  const {
    fetchImpl = fetch,
    resolver = dnsPromises,
    brandTerms = [],
    referenceText,
    allowPrivate = false,
    port,
    insecure = false,
    path = "/",
    now = () => new Date(),
  } = opts;
  const facts = {
    status: null,
    title: "",
    finalHost: name,
    redirects: [],
    headers: {},
    hasPasswordForm: false,
    brandTermFound: false,
    visibleText: "",
    similarity: null,
    truncated: false,
    fetchedAt: now(),
  };
  const schemes = insecure ? ["http"] : ["https", "http"];
  for (const scheme of schemes) {
    let url = `${scheme}://${name}${port ? `:${port}` : ""}${path}`;
    facts.redirects = [];
    try {
      for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
        const host = new URL(url).hostname;
        const blocked = await guardHost(host, { resolver, allowPrivate });
        if (blocked) {
          facts.error = blocked;
          return facts;
        }
        const res = await fetchImpl(url, {
          redirect: "manual",
          headers: { "User-Agent": USER_AGENT, Accept: "text/html,*/*;q=0.5" },
          signal: AbortSignal.timeout(TIMEOUT_MS),
        });
        const location = res.headers.get("location");
        if (res.status >= 300 && res.status < 400 && location) {
          url = new URL(location, url).toString();
          facts.redirects.push(new URL(url).hostname);
          continue;
        }
        facts.status = res.status;
        facts.finalHost = host;
        facts.headers = {
          server: res.headers.get("server") || undefined,
          "content-type": res.headers.get("content-type") || undefined,
          "set-cookie": res.headers.getSetCookie?.() || undefined,
        };
        const { text, truncated } = await readCapped(res);
        facts.truncated = truncated;
        Object.assign(facts, analyse(text, { brandTerms, referenceText }));
        delete facts.error;
        return facts;
      }
      facts.error = "too_many_redirects";
      return facts;
    } catch (err) {
      facts.error = err.code || err.name || String(err.message);
    }
  }
  return facts;
}

/** Leaf-certificate fingerprints for a host (https only). */
function fetchCertificate(host, { connect = tls.connect } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };
    try {
      const sock = connect(
        { host, port: 443, servername: host, rejectUnauthorized: false, timeout: TIMEOUT_MS },
        () => {
          try {
            const cert = sock.getPeerCertificate(true);
            const spki = cert.pubkey
              ? crypto.createHash("sha256").update(cert.pubkey).digest("hex")
              : null;
            const issuer = [cert.issuer?.O, cert.issuer?.CN].filter(Boolean).join(" ");
            done({
              fingerprint256: cert.fingerprint256 || null,
              spki,
              issuer,
              notBefore: cert.valid_from ? new Date(cert.valid_from) : null,
            });
          } finally {
            sock.end();
          }
        }
      );
      sock.setTimeout?.(TIMEOUT_MS, () => {
        sock.end();
        done(null);
      });
      sock.on("error", () => done(null));
    } catch {
      done(null);
    }
  });
}

/**
 * Pages for resolving sightings, highest similarity first, at most `limit`,
 * `concurrency` in flight.
 * @param {{ concurrency?: number, limit?: number }} [opts]
 * @returns {Promise<Map<string, object>>}
 */
async function fetchPages(sightings, deps, opts = {}) {
  const { concurrency = 8, limit } = opts;
  const ordered = [...sightings].sort((a, b) => (b.similarity || 0) - (a.similarity || 0));
  const picked = limit ? ordered.slice(0, limit) : ordered;
  const results = await mapBounded(picked, concurrency, async (s) => [
    s.lookalike,
    await fetchPage(s.lookalike, deps),
  ]);
  return new Map(results);
}

module.exports = { fetchPage, fetchPages, fetchCertificate, isPrivateIp, termRegex };
