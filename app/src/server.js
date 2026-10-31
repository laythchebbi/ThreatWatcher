const { env } = require("./config");
const logger = require("./logger");
const db = require("./db");
const { createApp } = require("./app");
const mlBridge = require("./services/ml-bridge");
const { runCycle } = require("./services/watch/cycle");
const { createScheduler } = require("./services/watch/scheduler");
const warninglists = require("./services/watch/warninglists");

async function start() {
  await db.connect();
  await mlBridge.start();

  const scheduler = createScheduler({
    runCycle,
    deps: {
      worker: mlBridge,
      lists: warninglists.load(),
      fetchImpl: fetch,
      apiKey: env.CERTSPOTTER_API_KEY,
    },
  });
  scheduler.start();

  const server = createApp().listen(env.PORT, () => {
    logger.info({ port: env.PORT, env: env.NODE_ENV }, "app listening");
  });

  const shutdown = (signal) => {
    logger.info({ signal }, "shutting down");
    server.close(async () => {
      await scheduler.stop().catch(() => {});
      await mlBridge.stop().catch(() => {});
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
