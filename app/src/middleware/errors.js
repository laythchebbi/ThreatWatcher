const logger = require("../logger");

function notFound(req, res, _next) {
  if (req.accepts(["json", "html"]) === "html") {
    return res.status(404).render("error", {
      title: "Not found",
      status: 404,
      message: `No page at ${req.originalUrl}`,
    });
  }
  return res.status(404).json({ error: "not_found", path: req.originalUrl });
}

function handler(err, req, res, next) {
  if (res.headersSent) return next(err);
  if (err.issues) {
    return res.status(400).json({ error: "validation", issues: err.issues });
  }
  // Mongoose CastError = malformed ObjectId in a route param: not found, not a crash.
  if (err.name === "CastError") {
    return res.status(404).json({ error: "not_found" });
  }
  const status = err.status || 500;
  if (status >= 500) {
    logger.error({ err, reqId: req.id, path: req.originalUrl }, "unhandled error");
  }
  return res.status(status).json({
    error: status === 500 ? "internal_error" : err.code || "error",
    message: status === 500 ? "Internal error" : err.message || "Error",
  });
}

module.exports = { notFound, handler };
