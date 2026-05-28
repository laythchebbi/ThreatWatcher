const client = require("prom-client");

const registry = new client.Registry();
client.collectDefaultMetrics({ register: registry, prefix: "threatwatcher_frontend_" });

const httpDuration = new client.Histogram({
  name: "threatwatcher_frontend_http_request_duration_seconds",
  help: "HTTP request duration in seconds",
  labelNames: ["method", "route", "status"],
  buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [registry],
});

const proxyCalls = new client.Counter({
  name: "threatwatcher_frontend_backend_proxy_total",
  help: "Counts of backend proxy calls by status",
  labelNames: ["method", "status"],
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

module.exports = { registry, httpDuration, proxyCalls, httpMetricsMiddleware };
