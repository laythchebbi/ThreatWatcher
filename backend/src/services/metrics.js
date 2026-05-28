const client = require("prom-client");

const registry = new client.Registry();
client.collectDefaultMetrics({ register: registry, prefix: "threatwatcher_backend_" });

const httpDuration = new client.Histogram({
  name: "threatwatcher_backend_http_request_duration_seconds",
  help: "HTTP request duration in seconds",
  labelNames: ["method", "route", "status"],
  buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [registry],
});

const mlClassifications = new client.Counter({
  name: "threatwatcher_backend_ml_classifications_total",
  help: "Total ML classifications",
  labelNames: ["worker", "outcome"],
  registers: [registry],
});

const mongoOperations = new client.Counter({
  name: "threatwatcher_backend_mongo_ops_total",
  help: "Total mongoose operations",
  labelNames: ["model", "op"],
  registers: [registry],
});

function httpMetricsMiddleware(req, res, next) {
  const start = process.hrtime.bigint();
  res.on("finish", () => {
    const ms = Number(process.hrtime.bigint() - start) / 1e6;
    const route = req.route?.path || req.baseUrl || req.path || "unknown";
    httpDuration.observe({ method: req.method, route, status: String(res.statusCode) }, ms / 1000);
  });
  next();
}

module.exports = {
  registry,
  httpDuration,
  mlClassifications,
  mongoOperations,
  httpMetricsMiddleware,
};
