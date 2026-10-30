const crypto = require("node:crypto");

function requestId(req, res, next) {
  const incoming = req.headers["x-request-id"];
  const id =
    typeof incoming === "string" && /^[\w-]{8,128}$/.test(incoming)
      ? incoming
      : crypto.randomUUID();
  req.id = id;
  res.setHeader("x-request-id", id);
  next();
}

module.exports = requestId;
