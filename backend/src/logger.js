const { pino } = require("pino");
const { env, isProd } = require("./config");

const redact = {
  paths: [
    "req.headers.authorization",
    "req.headers.cookie",
    "req.headers['x-internal-key']",
    "*.password",
    "*.token",
    "*.MONGODB_URI",
    "*.JWT_SECRET",
    "*.WHOISXML_API_KEY",
    "*.SLACK_BOT_TOKEN",
  ],
  remove: true,
};

let transport;
if (env.LOG_FILE) {
  /** @type {import("pino").TransportTargetOptions[]} */
  const targets = [
    {
      target: "pino/file",
      level: env.LOG_LEVEL,
      options: { destination: env.LOG_FILE, mkdir: true },
    },
  ];
  if (!isProd) {
    targets.push({
      target: "pino-pretty",
      level: env.LOG_LEVEL,
      options: { colorize: true, translateTime: "HH:MM:ss.l" },
    });
  }
  transport = pino.transport({ targets });
} else if (!isProd) {
  transport = pino.transport({
    target: "pino-pretty",
    options: { colorize: true, translateTime: "HH:MM:ss.l" },
  });
}

const logger = pino(
  {
    level: env.LOG_LEVEL,
    base: { service: "backend" },
    timestamp: pino.stdTimeFunctions.isoTime,
    redact,
  },
  transport
);

module.exports = logger;
