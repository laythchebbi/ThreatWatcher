const logger = require("../logger");

function notFound(req, res, _next) {
  res.status(404).json({ error: "not_found", path: req.originalUrl });
}

function handler(err, req, _res, next) {
  if (err.status === 401 || err.name === "UnauthorizedError") {
    return next();
  }
  logger.error({ err, path: req?.originalUrl }, "unhandled error");
  return next(err);
}

handler.final = function (err, _req, res, _next) {
  if (err.status === 401 || err.name === "UnauthorizedError") {
    return res.status(401).json({ error: "unauthorized" });
  }
  if (err.issues) {
    return res.status(400).json({ error: "validation", issues: err.issues });
  }
  const status = err.status || 500;
  res.status(status).json({
    error: status === 500 ? "internal_error" : err.code || "error",
    message: status === 500 ? "Internal error" : err.message || "Error",
  });
};

module.exports = { notFound, handler: handler.final };
