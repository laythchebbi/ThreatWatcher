const logger = require("../logger");

function notFound(req, res) {
  if (req.accepts("html")) {
    return res.status(404).render("error", {
      title: "Not found — Threat Watcher",
      active: null,
      crumbs: ["Error"],
      status: 404,
      message: `Page not found: ${req.originalUrl}`,
    });
  }
  return res.status(404).json({ error: "not_found", path: req.originalUrl });
}

function handler(err, req, res, _next) {
  logger.error({ err, path: req?.originalUrl }, "unhandled error");
  const status = err.status || 500;
  if (req.accepts("html")) {
    return res.status(status).render("error", {
      title: "Error — Threat Watcher",
      active: null,
      crumbs: ["Error"],
      status,
      message: status === 500 ? "Internal error" : err.message || "Error",
    });
  }
  return res.status(status).json({ error: status === 500 ? "internal_error" : "error" });
}

module.exports = { notFound, handler };
