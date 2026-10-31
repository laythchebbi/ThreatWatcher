const dnsPromises = require("node:dns/promises");

const COMMON_SELECTORS = [
  "default",
  "google",
  "selector1",
  "selector2",
  "k1",
  "s1",
  "mail",
  "dkim",
];

async function txt(resolver, name) {
  try {
    return (await resolver.resolveTxt(name)).map((parts) => parts.join(""));
  } catch {
    return [];
  }
}

function parseSpf(records) {
  const spf = records.find((r) => /^v=spf1\b/i.test(r));
  if (!spf) return { present: false, policy: "none", lookups: 0 };
  const terms = spf.split(/\s+/).slice(1);
  const all = terms.find((t) => /^[-~+?]?all$/i.test(t)) || "";
  const policy = all.startsWith("-") ? "strict" : all.startsWith("~") ? "soft" : "none";
  const lookups = terms.filter((t) =>
    /^(include:|a$|a:|mx$|mx:|redirect=|exists:)/i.test(t)
  ).length;
  return { present: true, policy, lookups };
}

function parseDmarc(records) {
  const rec = records.find((r) => /^v=DMARC1\b/i.test(r));
  if (!rec) return { present: false, policy: null, rua: null };
  const tags = Object.fromEntries(
    rec
      .split(";")
      .map((t) => t.trim().split("="))
      .filter((kv) => kv.length === 2)
      .map(([k, v]) => [k.trim().toLowerCase(), v.trim()])
  );
  return { present: true, policy: (tags.p || "none").toLowerCase(), rua: tags.rua || null };
}

/**
 * SPF / DMARC / DKIM posture of the customer's own domain (spec 7.4 step 5a).
 * @param {string} domainName
 * @param {{ resolver?: object, dkimSelector?: string, now?: () => Date }} [opts]
 * @returns {Promise<{ checkedAt: Date, spf: object, dmarc: object, dkim: { selectorsFound: string[] }, grade: string, findings: string[] }>}
 */
async function checkPosture(
  domainName,
  { resolver = dnsPromises, dkimSelector, now = () => new Date() } = {}
) {
  const spf = parseSpf(await txt(resolver, domainName));
  const dmarc = parseDmarc(await txt(resolver, `_dmarc.${domainName}`));
  const selectors = [...new Set([dkimSelector, ...COMMON_SELECTORS].filter(Boolean))];
  const found = [];
  for (const sel of selectors) {
    const rec = await txt(resolver, `${sel}._domainkey.${domainName}`);
    if (rec.some((r) => /v=DKIM1|p=/i.test(r))) found.push(sel);
  }
  const dkim = { selectorsFound: found };

  const findings = [];
  if (!spf.present) findings.push("Publish an SPF record ending in -all.");
  else if (spf.policy !== "strict") findings.push("Publish a strict SPF ending in -all.");
  if (spf.lookups > 10) findings.push("SPF exceeds 10 DNS lookups; flatten the includes.");
  if (!dmarc.present) findings.push("Publish a DMARC record (_dmarc) and move it to p=reject.");
  else if (dmarc.policy !== "reject")
    findings.push("Move DMARC to p=reject with a rua reporting address.");
  else if (!dmarc.rua) findings.push("Add a rua address to DMARC so you receive reports.");
  if (!found.length) {
    findings.push(
      "No DKIM key found under common selectors; confirm DKIM signing is enabled (set your selector on this page)."
    );
  }

  let grade = "A";
  if (!spf.present || !dmarc.present) grade = "F";
  else if (dmarc.policy === "none") grade = "D";
  else if (spf.policy !== "strict" || !found.length) grade = "C";
  else if (dmarc.policy === "quarantine") grade = "B";

  return { checkedAt: now(), spf, dmarc, dkim, grade, findings };
}

const RANK = { A: 0, B: 1, C: 2, D: 3, F: 4 };

/** One posture_weak (low) when the grade is D or F and it was better (or unknown) before. */
function postureEvents(previous, next) {
  if (!next || !["D", "F"].includes(next.grade)) return [];
  if (previous && RANK[previous.grade] >= RANK[next.grade]) return [];
  return [
    {
      lookalike: null,
      kind: "posture_weak",
      severity: "low",
      payload: { grade: next.grade, findings: next.findings },
    },
  ];
}

module.exports = { checkPosture, postureEvents, COMMON_SELECTORS };
