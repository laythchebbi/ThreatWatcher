const { Router } = require("express");
const mongoose = require("mongoose");
const mlBridge = require("../services/ml-bridge");

const router = Router();

router.get("/", (_req, res) => {
  res.json({
    ok: true,
    mongo: mongoose.connection.readyState === 1,
    ml: mlBridge.readiness(),
    uptime: Math.round(process.uptime()),
  });
});

module.exports = router;
