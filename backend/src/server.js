const express = require("express");
const helmet = require("helmet").default;
const cors = require("cors");
const compression = require("compression");
const cookieParser = require("cookie-parser");
const { pinoHttp } = require("pino-http");

const { env, isDemo } = require("./config");
const logger = require("./logger");
const db = require("./db");

const errors = require("./middleware/errors");
const requestId = require("./middleware/requestId");
const healthRoute = require("./routes/health");
const authRoute = require("./routes/auth");
const domainsRoute = require("./routes/domains");
const reportsRoute = require("./routes/reports");
const dataleakRoute = require("./routes/dataleak");
const usersRoute = require("./routes/users");
const metricsRoute = require("./routes/metrics");
const mlBridge = require("./services/ml-bridge");
const { httpMetricsMiddleware } = require("./services/metrics");

async function start() {
  if (isDemo) {
    logger.warn(
      "⚠  DEMO MODE: WorkOS auth bypassed, no MongoDB, in-memory data. For local trials only — never production."
    );
  } else {
    await db.connect();
    await mlBridge.start();
  }

  const app = express();
  app.disable("x-powered-by");
  app.use(helmet());
  app.use(compression());
  app.use(cors({ origin: env.FRONTEND_ORIGIN, credentials: true }));
  app.use(express.json({ limit: "1mb" }));
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(requestId);
  app.use(
    pinoHttp({
      logger,
      customProps: (req) => ({ reqId: req.id }),
    })
  );
  app.use(httpMetricsMiddleware);
  app.use("/metrics", metricsRoute);

  if (isDemo) {
    app.use(require("./demo/router"));
  } else {
    app.use("/health", healthRoute);
    app.use("/auth", authRoute);
    app.use("/api/domains", domainsRoute);
    app.use("/api/reports", reportsRoute);
    app.use("/api/dataleak", dataleakRoute);
    app.use("/api/users", usersRoute);
  }

  app.use(errors.notFound);
  app.use(errors.handler);

  const server = app.listen(env.PORT, () => {
    logger.info({ port: env.PORT, env: env.NODE_ENV, demo: isDemo }, "backend listening");
  });

  const shutdown = async (signal) => {
    logger.info({ signal }, "shutting down");
    server.close(async () => {
      if (!isDemo) {
        await mlBridge.stop().catch(() => {});
        await db.disconnect().catch(() => {});
      }
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
