const path = require("path");
const express = require("express");
const helmet = require("helmet").default;
const compression = require("compression");
const { pinoHttp } = require("pino-http");
const expressLayouts = require("express-ejs-layouts");

const { env, isProd } = require("./config");
const logger = require("./logger");
const requestId = require("./middleware/request-id");
const errors = require("./middleware/errors");
const { readSession } = require("./middleware/session");
const { originCheck } = require("./middleware/origin-check");
const authRoutes = require("./routes/auth");
const dashboardRoutes = require("./routes/dashboard");
const domainRoutes = require("./routes/domains");
const darkwebRoutes = require("./routes/darkweb");
const { NAV } = require("./nav");

/** Build the Express app. Only server.js calls listen(); tests listen on port 0. */
function createApp() {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", env.TRUST_PROXY);
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          "default-src": ["'self'"],
          "script-src": ["'self'", "'unsafe-inline'"],
          "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
          "font-src": ["'self'", "https://fonts.gstatic.com", "data:"],
          "img-src": ["'self'", "data:"],
          "connect-src": ["'self'"],
        },
      },
      // no-referrer makes browsers send `Origin: null` on form POSTs, which originCheck rejects.
      referrerPolicy: { policy: "same-origin" },
    })
  );
  app.use(compression());
  app.use(express.json({ limit: "256kb" }));
  app.use(express.urlencoded({ extended: false }));
  app.use(requestId);
  app.use(pinoHttp({ logger, customProps: (req) => ({ reqId: req.id }) }));

  app.set("views", path.join(__dirname, "views"));
  app.set("view engine", "ejs");
  app.use(expressLayouts);
  app.set("layout", "layout");
  app.set("layout extractScripts", true);
  app.set("layout extractStyles", true);
  app.use(
    "/static",
    express.static(path.join(__dirname, "public"), { maxAge: isProd ? "7d" : "0" })
  );

  app.get("/health", (_req, res) => res.json({ ok: true }));

  app.locals.nav = NAV;
  Object.assign(app.locals, require("./lib/view-helpers"));
  app.use(readSession);
  app.use((req, res, next) => {
    res.locals.user = req.user;
    next();
  });
  app.use(originCheck(env.BASE_URL));
  app.use(authRoutes);
  app.use(dashboardRoutes);
  app.use("/domains", domainRoutes);
  app.use("/dark-web", darkwebRoutes);

  app.use(errors.notFound);
  app.use(errors.handler);
  return app;
}

module.exports = { createApp };
