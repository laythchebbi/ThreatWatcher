const path = require("path");
const crypto = require("node:crypto");
const express = require("express");
const cookieParser = require("cookie-parser");
const helmet = require("helmet").default;
const compression = require("compression");
const { pinoHttp } = require("pino-http");
const expressLayouts = require("express-ejs-layouts");

const { env, isProd, isDemo } = require("./config");
const logger = require("./logger");
const { NAV, ICONS } = require("./nav");
const {
  getSession,
  readSession,
  requireAuth,
  requireRole,
  refreshSession,
  decodeClaims,
  safeNext,
} = require("./middleware/session");
const errors = require("./middleware/errors");
const backend = require("./services/backend-client");
const workosService = require("./services/workos");
const { registry, httpMetricsMiddleware, proxyCalls } = require("./services/metrics");

const app = express();
app.disable("x-powered-by");
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'"],
        "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        "font-src": ["'self'", "https://fonts.gstatic.com", "data:"],
        "img-src": ["'self'", "data:", "https://www.gravatar.com"],
        "connect-src": ["'self'"],
      },
    },
  })
);

app.use(compression());
app.use((req, _res, next) => {
  req.id = req.headers["x-request-id"] || crypto.randomUUID();
  next();
});
app.use(pinoHttp({ logger, customProps: (req) => ({ reqId: req.id }) }));
app.use(httpMetricsMiddleware);
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(expressLayouts);
app.set("layout", "layout");
app.set("layout extractScripts", true);
app.set("layout extractStyles", true);

app.use("/static", express.static(path.join(__dirname, "public"), { maxAge: isProd ? "7d" : "0" }));

app.locals.nav = NAV;
app.locals.icons = ICONS;
app.locals.demoMode = isDemo;

app.use(readSession);
app.use((req, res, next) => {
  res.locals.user = req.user;
  next();
});

// ─── Public ────────────────────────────────────────────────────────────────
app.get("/health", (_req, res) => res.json({ ok: true }));
app.get("/metrics", async (_req, res) => {
  res.set("content-type", registry.contentType);
  res.end(await registry.metrics());
});

// ─── WorkOS AuthKit flow ───────────────────────────────────────────────────
// /auth/sign-in            → mint anti-CSRF state, redirect to AuthKit
// /auth/callback           → exchange code, seal session, redirect to next
// /auth/sign-out           → destroy session, redirect to /login
// /login                   → simplified "click to sign in" landing page

app.get("/login", (req, res) => {
  if (req.user) return res.redirect("/dashboard");
  res.render("login", {
    title: "Sign in — Threat Watcher",
    active: null,
    crumbs: ["Sign in"],
    layout: false,
    next: req.query.next || "/dashboard",
    error: req.query.error || null,
  });
});

app.get("/auth/sign-in", async (req, res, next) => {
  try {
    const session = await getSession(req, res);
    const state = crypto.randomBytes(16).toString("hex");
    session.oauth = { state, next: safeNext(req.query.next) };
    await session.save();
    const url = workosService.authorizationUrl({ state });
    res.redirect(url);
  } catch (err) {
    next(err);
  }
});

app.get("/auth/sign-in/google", async (req, res, next) => {
  try {
    const session = await getSession(req, res);
    const state = crypto.randomBytes(16).toString("hex");
    session.oauth = { state, next: "/dashboard" };
    await session.save();
    res.redirect(workosService.authorizationUrl({ state, provider: "GoogleOAuth" }));
  } catch (err) {
    next(err);
  }
});

app.get("/auth/sign-in/microsoft", async (req, res, next) => {
  try {
    const session = await getSession(req, res);
    const state = crypto.randomBytes(16).toString("hex");
    session.oauth = { state, next: "/dashboard" };
    await session.save();
    res.redirect(workosService.authorizationUrl({ state, provider: "MicrosoftOAuth" }));
  } catch (err) {
    next(err);
  }
});

app.get("/auth/callback", async (req, res) => {
  try {
    const session = await getSession(req, res);
    const { code, state, error: oauthError, error_description } = req.query;

    if (oauthError) {
      logger.warn({ oauthError, error_description }, "workos returned error to callback");
      return res.redirect(
        `/login?error=${encodeURIComponent(String(error_description || oauthError))}`
      );
    }

    if (!code || !state || state !== session.oauth?.state) {
      return res.redirect("/login?error=invalid_state");
    }

    const out = await workosService.authenticateWithCode(code);
    const nextUrl = safeNext(session.oauth.next);

    // Inline org + role claims so `req.user.role` works for guards on this
    // app without round-tripping the backend. Real authorization is still
    // verified server-side on every backend call.
    const claims = decodeClaims(out.accessToken);
    const role = claims.role || claims.role_slug || claims.org_role || null;

    session.workos = {
      user: { ...out.user, role },
      accessToken: out.accessToken,
      refreshToken: out.refreshToken,
      organizationId: out.organizationId || claims.org_id || null,
    };
    delete session.oauth;
    await session.save();

    logger.info({ workosUserId: out.user.id, email: out.user.email, role }, "user signed in");
    return res.redirect(nextUrl);
  } catch (err) {
    logger.error({ err: { message: err.message } }, "callback failed");
    return res.redirect(`/login?error=${encodeURIComponent("sign_in_failed")}`);
  }
});

app.post("/auth/sign-out", async (req, res, next) => {
  try {
    const session = await getSession(req, res);
    session.destroy();
    return res.redirect("/login");
  } catch (err) {
    next(err);
  }
});

// Keep the old /logout target as an alias for safety.
app.post("/logout", (req, res) => res.redirect(307, "/auth/sign-out"));

// ─── Authed pages ──────────────────────────────────────────────────────────
app.get("/", requireAuth, (_req, res) => res.redirect("/dashboard"));

app.get("/dashboard", requireAuth, async (req, res, next) => {
  try {
    let loadError = false;
    const me = await backend.me(req.token).catch(() => ({ user: null }));
    const reportData = await backend.listReports(req.token, 50).catch(() => {
      loadError = true;
      return { items: [] };
    });

    const reports = reportData.items || [];
    const scored = reports.filter((r) => typeof r.secureScore === "number");
    const avgScore = scored.length
      ? scored.reduce((sum, r) => sum + r.secureScore, 0) / scored.length
      : 0;

    res.render("dashboard", {
      title: "Dashboard — Threat Watcher",
      active: "dashboard",
      crumbs: ["Workspace", "Dashboard"],
      monitored: me?.user?.monitoredDomains || [],
      recent: reports.slice(0, 8),
      loadError,
      stats: {
        active: reports.length,
        lookalikes: reports.reduce((s, r) => s + ((r.findings && r.findings.lookalikes) || 0), 0),
        darkweb: reports.reduce((s, r) => s + ((r.findings && r.findings.darkWebHits) || 0), 0),
        avgScore: avgScore.toFixed(2),
      },
    });
  } catch (err) {
    next(err);
  }
});

app.get("/geolocation", requireAuth, (_req, res) => {
  res.render("geolocation", {
    title: "Geo activity — Threat Watcher",
    active: "geo",
    crumbs: ["Monitor", "Geo activity"],
  });
});

app.get("/new-scan", requireAuth, (req, res) => {
  res.render("new-scan", {
    title: "New scan — Threat Watcher",
    active: "scan",
    crumbs: ["Workspace", "New scan"],
    prefill: req.query.domain || "",
    error: null,
  });
});

app.post("/new-scan", requireAuth, async (req, res) => {
  try {
    const { domain } = req.body;
    const data = await backend.scanDomain(req.token, domain);
    const id = data?.report?._id;
    if (!id) {
      return res.status(400).render("new-scan", {
        title: "New scan — Threat Watcher",
        active: "scan",
        crumbs: ["Workspace", "New scan"],
        prefill: domain,
        error: "Scan failed — backend returned no report",
      });
    }
    return res.redirect(`/scan/${id}`);
  } catch (err) {
    return res.status(500).render("new-scan", {
      title: "New scan — Threat Watcher",
      active: "scan",
      crumbs: ["Workspace", "New scan"],
      prefill: req.body.domain || "",
      error: err.response?.data?.message || "Scan failed",
    });
  }
});

app.get("/scan/:id", requireAuth, async (req, res, next) => {
  try {
    const data = await backend.withAuth(req.token).get(`/api/reports/${req.params.id}`);
    if (!data?.data?.report) {
      return res.status(404).render("error", {
        title: "Not found — Threat Watcher",
        active: null,
        crumbs: ["Error"],
        status: 404,
        message: "Report not found",
      });
    }
    return res.render("scan-report", {
      title: `Scan report — ${data.data.report.domain}`,
      active: "reports",
      crumbs: ["Workspace", "Reports", data.data.report.domain],
      report: data.data.report,
    });
  } catch (err) {
    return next(err);
  }
});

app.get("/reports", requireAuth, async (req, res, next) => {
  try {
    let loadError = false;
    const data = await backend.listReports(req.token, 200).catch(() => {
      loadError = true;
      return { items: [] };
    });
    res.render("reports", {
      title: "Reports — Threat Watcher",
      active: "reports",
      crumbs: ["Workspace", "Reports"],
      reports: data.items || [],
      loadError,
    });
  } catch (err) {
    next(err);
  }
});

app.get("/dark-web", requireAuth, (_req, res) => {
  res.render("dark-web", {
    title: "Dark web — Threat Watcher",
    active: "darkweb",
    crumbs: ["Workspace", "Dark web"],
  });
});

app.get("/settings", requireAuth, async (req, res, next) => {
  try {
    const me = await backend.me(req.token).catch(() => ({ user: null, workos: null }));
    res.render("settings", {
      title: "Settings — Threat Watcher",
      active: "settings",
      crumbs: ["Account", "Settings"],
      profile: me?.user || {},
      workos: me?.workos || {},
      isAdmin: (me?.user?.role || "") === "admin",
    });
  } catch (err) {
    next(err);
  }
});

app.get("/design-system", requireAuth, (_req, res) => {
  res.render("design-system", {
    title: "Design system — Threat Watcher",
    active: "ds",
    crumbs: ["Account", "Design system"],
  });
});

// ─── API proxy ─────────────────────────────────────────────────────────────
// Pages call /api/* from the browser; we forward to the backend with the
// user's WorkOS access token attached server-side. On a 401, attempt one
// refresh-token round-trip and retry once before giving up.
async function proxy(req, res, { method, path: backendPath }) {
  if (!req.user) {
    proxyCalls.inc({ method, status: "401" });
    return res.status(401).json({ error: "unauthorized" });
  }

  const doRequest = async (token) => {
    const opts = { method, url: backendPath };
    if (req.method !== "GET" && req.method !== "HEAD") opts.data = req.body;
    return backend.withAuth(token).request(opts);
  };

  try {
    let out;
    try {
      out = await doRequest(req.token);
    } catch (err) {
      if (err.response?.status === 401) {
        const newToken = await refreshSession(req, res);
        if (!newToken) {
          proxyCalls.inc({ method, status: "401" });
          return res.status(401).json({ error: "unauthorized" });
        }
        out = await doRequest(newToken);
      } else {
        throw err;
      }
    }
    proxyCalls.inc({ method, status: String(out.status) });
    res
      .status(out.status)
      .set("content-type", out.headers["content-type"] || "application/json")
      .send(out.data);
  } catch (err) {
    const status = err.response?.status || 502;
    proxyCalls.inc({ method, status: String(status) });
    res.status(status).json({ error: "backend_error", status });
  }
}

/** Build a flat query string from Express's parsed query object. */
function toQueryString(query) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query || {})) {
    if (Array.isArray(value)) value.forEach((v) => params.append(key, String(v)));
    else if (value != null) params.append(key, String(value));
  }
  return params.toString();
}

app.get("/api/reports", (req, res) => {
  const qs = toQueryString(req.query);
  return proxy(req, res, { method: "GET", path: `/api/reports${qs ? "?" + qs : ""}` });
});
app.get("/api/reports/:id", (req, res) =>
  proxy(req, res, { method: "GET", path: `/api/reports/${encodeURIComponent(req.params.id)}` })
);
app.get("/api/dataleak", (req, res) => {
  const qs = toQueryString(req.query);
  return proxy(req, res, { method: "GET", path: `/api/dataleak/search${qs ? "?" + qs : ""}` });
});
app.get("/api/me", (req, res) => proxy(req, res, { method: "GET", path: "/api/users/me" }));
app.patch("/api/me", (req, res) => proxy(req, res, { method: "PATCH", path: "/api/users/me" }));
app.put("/api/me/monitored", (req, res) =>
  proxy(req, res, { method: "PUT", path: "/api/users/me/monitored" })
);

// Admin endpoints — frontend just forwards; backend enforces requireRole("admin").
app.get("/api/admin/users", requireRole("admin"), (req, res) =>
  proxy(req, res, { method: "GET", path: "/api/users" })
);
app.post("/api/admin/users/:id/deactivate", requireRole("admin"), (req, res) =>
  proxy(req, res, {
    method: "POST",
    path: `/api/users/${encodeURIComponent(req.params.id)}/deactivate`,
  })
);
app.get("/api/admin/invitations", requireRole("admin"), (req, res) =>
  proxy(req, res, { method: "GET", path: "/auth/invitations" })
);
app.post("/api/admin/invitations", requireRole("admin"), (req, res) =>
  proxy(req, res, { method: "POST", path: "/auth/invitations" })
);
app.delete("/api/admin/invitations/:id", requireRole("admin"), (req, res) =>
  proxy(req, res, {
    method: "DELETE",
    path: `/auth/invitations/${encodeURIComponent(req.params.id)}`,
  })
);

// ─── Errors ────────────────────────────────────────────────────────────────
app.use(errors.notFound);
app.use(errors.handler);

app.listen(env.PORT, () => {
  logger.info(
    { port: env.PORT, env: env.NODE_ENV, backend: env.BACKEND_URL },
    "frontend listening"
  );
});
