const WORDS = [
  "login",
  "secure",
  "support",
  "verify",
  "account",
  "portal",
  "my",
  "mail",
  "help",
  "id",
];
const JOINERS = ["-", ""];
const TLDS = ["com", "net", "org", "co", "io", "app"];

/** Split "acme.co.uk" into { label: "acme", tld: "co.uk" }. */
function splitDomain(domain) {
  const [label, ...rest] = String(domain).toLowerCase().split(".");
  return { label, tld: rest.join(".") };
}

/** brand-login.com style names: the most common 2026 phishing pattern (spec 7.4 step 1b). */
function combosquats(domain) {
  const { label, tld } = splitDomain(domain);
  const tlds = [...new Set([tld, ...TLDS])].filter(Boolean);
  const out = new Set();
  for (const word of WORDS) {
    for (const joiner of JOINERS) {
      for (const t of tlds) out.add(`${label}${joiner}${word}.${t}`);
    }
  }
  out.delete(String(domain).toLowerCase());
  return [...out];
}

function clean(domain, list) {
  const self = String(domain).toLowerCase();
  const out = new Set();
  for (const raw of list) {
    const name = String(raw || "")
      .trim()
      .toLowerCase();
    if (name && name !== self) out.add(name);
  }
  return [...out];
}

/**
 * Permutations for a protected domain: the worker (local dnstwist) first,
 * then dnstwister.report, then the list stored from the last cycle. The
 * result always includes combosquats and never the domain itself.
 * @returns {Promise<{ candidates: string[], source: "worker" | "dnstwister" | "previous" }>}
 */
async function permutations(domain, { worker, fetchImpl = fetch, previous = [] }) {
  let list;
  /** @type {"worker" | "dnstwister" | "previous"} */
  let source;
  try {
    list = await worker.permute(domain);
    source = "worker";
  } catch {
    try {
      const hex = Buffer.from(domain, "utf8").toString("hex");
      const res = await fetchImpl(`https://dnstwister.report/api/fuzz/${hex}`, {
        signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) throw new Error(`dnstwister ${res.status}`);
      const body = /** @type {{ fuzzy_domains?: { domain: string }[] }} */ (await res.json());
      list = (body.fuzzy_domains || []).map((f) => f.domain);
      source = "dnstwister";
    } catch {
      list = previous;
      source = "previous";
    }
  }
  return { candidates: clean(domain, [...list, ...combosquats(domain)]), source };
}

module.exports = { combosquats, permutations, splitDomain };
