// Demo router — mounted ONLY when DEMO_MODE is on. Serves the in-memory demo
// dataset and bypasses WorkOS auth so the UI can be explored without external
// services. Live scans still run through the REAL domain-similarity engine.

const { Router } = require("express");
const crypto = require("node:crypto");
const sim = require("../services/domain-similarity");
const { demoUser, reports, leaks, invitations } = require("./data");
const logger = require("../logger");

const router = Router();

router.get("/health", (_req, res) => {
  res.json({ ok: true, demo: true, mongo: false, ml: { url: false, content: false } });
});

// ── Identity ────────────────────────────────────────────────────────────────
router.get("/auth/me", (_req, res) => {
  res.json({
    user: demoUser,
    workos: {
      sub: demoUser.workosUserId,
      email: demoUser.email,
      role: "admin",
      organizationId: "org_demo",
    },
  });
});
router.get("/api/users/me", (_req, res) => res.json({ user: demoUser }));
router.patch("/api/users/me", (req, res) => {
  if (typeof req.body?.displayName === "string") demoUser.displayName = req.body.displayName;
  res.json({ user: demoUser });
});
router.put("/api/users/me/monitored", (req, res) => {
  if (Array.isArray(req.body?.monitoredDomains))
    demoUser.monitoredDomains = req.body.monitoredDomains;
  res.json({ monitoredDomains: demoUser.monitoredDomains });
});
router.get("/api/users", (_req, res) => res.json({ count: 1, items: [demoUser] }));

// ── Reports ──────────────────────────────────────────────────────────────────
router.get("/api/reports", (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  const sorted = [...reports].sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );
  res.json({ count: reports.length, items: sorted.slice(0, limit) });
});
router.get("/api/reports/:id", (req, res) => {
  const report = reports.find((r) => r._id === req.params.id);
  if (!report) return res.status(404).json({ error: "not_found" });
  return res.json({ report });
});

// ── Live scan (real scoring on synthetic candidates) ─────────────────────────
function syntheticCandidates(domain) {
  const parts = domain.split(".");
  const label = parts[0];
  const tld = parts.slice(1).join(".") || "com";
  const out = new Set([
    label.replace(/o/g, "0") + "." + tld,
    label.replace(/l/g, "1") + "." + tld,
    label.replace(/i/g, "1") + "." + tld,
    label + "-login." + tld,
    label + "-secure." + tld,
    label + "-support." + tld,
    "xn--" + label + "-9bc." + tld,
    label + ".co",
    label + ".net",
    label + ".org",
  ]);
  out.delete(domain);
  return [...out];
}

router.post("/api/domains/scan/:domain", (req, res) => {
  const domain = String(req.params.domain).toLowerCase();
  const scored = sim.scoreDomains(domain, syntheticCandidates(domain), 0.45).map((s) => ({
    ...s,
    punycode: sim.isPunycode(s.domain),
    substring: sim.isSubstringMatch(domain, s.domain),
    mlLabel: s.similarity >= 0.8 ? 1 : 0,
    mlScore: Number(s.similarity.toFixed(2)),
  }));
  const secureScore = sim.secureScore({
    activeServer: true,
    substring: scored.some((s) => s.substring),
    idn: scored.some((s) => s.punycode),
    visualSimilarity: scored.length ? scored[0].similarity : 0,
  });
  const report = {
    _id: "rep_" + crypto.randomBytes(5).toString("hex"),
    domain,
    secureScore,
    confidence: 0.85,
    findings: {
      lookalikes: scored.length,
      maliciousUrls: scored.filter((s) => s.mlLabel === 1).length,
      contentMatches: 0,
      darkWebHits: 0,
      dataLeaks: 0,
    },
    reportContent: { scored },
    createdAt: new Date().toISOString(),
  };
  reports.push(report);
  logger.info({ domain, secureScore, lookalikes: scored.length }, "demo scan created");
  res.status(201).json({ report });
});

router.get("/api/domains/search/:domain", (req, res) => {
  const domain = String(req.params.domain).toLowerCase();
  const results = sim.scoreDomains(domain, syntheticCandidates(domain), 0.45).map((s) => ({
    ...s,
    punycode: sim.isPunycode(s.domain),
    substring: sim.isSubstringMatch(domain, s.domain),
  }));
  res.json({ domain, count: results.length, results });
});

// ── Data-leak search ─────────────────────────────────────────────────────────
router.get("/api/dataleak/search", (req, res) => {
  const q = String(req.query.q || "").toLowerCase();
  const source = String(req.query.source || "all");
  const match = (text) =>
    !q ||
    String(text || "")
      .toLowerCase()
      .includes(q);
  const pick = (arr, fields) => arr.filter((it) => fields.some((f) => match(it[f])));
  const all = {
    telegram: pick(leaks.telegram, ["text"]),
    twitter: pick(leaks.twitter, ["text"]),
    forum: pick(leaks.forum, ["title", "body"]),
    darkweb: pick(leaks.darkweb, ["title", "body"]),
  };
  const results = source === "all" ? all : { [source]: all[source] || [] };
  const totalCount = Object.values(results).reduce((n, a) => n + a.length, 0);
  res.json({ q, source, totalCount, results });
});

// ── Invitations (admin) ──────────────────────────────────────────────────────
router.get("/auth/invitations", (_req, res) => res.json({ invitations }));
router.post("/auth/invitations", (req, res) => {
  const inv = {
    id: "inv_" + crypto.randomBytes(4).toString("hex"),
    email: req.body?.email || "unknown@example.com",
    role: req.body?.role || "analyst",
    state: "pending",
  };
  invitations.push(inv);
  res.status(201).json({ invitation: inv });
});
router.delete("/auth/invitations/:id", (req, res) => {
  const i = invitations.findIndex((v) => v.id === req.params.id);
  if (i >= 0) invitations.splice(i, 1);
  res.status(204).end();
});

module.exports = router;
