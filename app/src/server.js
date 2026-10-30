const { env } = require("./config");
const logger = require("./logger");
const db = require("./db");
const { createApp } = require("./app");

async function start() {
  await db.connect();
  const server = createApp().listen(env.PORT, () => {
    logger.info({ port: env.PORT, env: env.NODE_ENV }, "app listening");
  });

  const shutdown = (signal) => {
    logger.info({ signal }, "shutting down");
    server.close(async () => {
      await db.disconnect().catch(() => {});
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

start().catch((err) => {
  logger.fatal({ err }, "startup failed");
  process.exit(1);
});
