const { Router } = require("express");
const { registry } = require("../services/metrics");

const router = Router();

// Open by default for the convenience of a local Prometheus scrape.
// In M7 this gets gated behind a service key or bound to loopback only.
router.get("/", async (_req, res) => {
  res.set("Content-Type", registry.contentType);
  res.end(await registry.metrics());
});

module.exports = router;
