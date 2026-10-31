const { Router } = require("express");
const { z } = require("zod");
const validate = require("../middleware/validate");
const { rateLimit } = require("../middleware/rate-limit");
const { getSession, safeNext } = require("../middleware/session");
const auth = require("../services/auth");

const router = Router();

const GENERIC_LOGIN = "Check your email and password.";
const GENERIC_FORGOT = "If that address exists we sent a link.";

const credentials = z.object({
  email: z.string().trim().toLowerCase().email().max(254),
  password: z.string().min(10).max(128),
  next: z.string().optional(),
});
const emailOnly = z.object({ email: z.string().trim().toLowerCase().max(254) });
const newPassword = z.object({ password: z.string().min(10).max(128) });

const perIp = (max, windowMs) => rateLimit({ max, windowMs, key: (req) => `ip:${req.ip}` });
const perEmail = (max, windowMs) =>
  rateLimit({ max, windowMs, key: (req) => `email:${auth.normaliseEmail(req.body?.email)}` });

async function establish(req, res, user, next) {
  const session = await getSession(req, res);
  session.userId = String(user._id);
  session.sv = user.sessionVersion;
  session.issuedAt = Date.now();
  await session.save();
  res.redirect(next);
}

const page = (name, title) => (req, res) =>
  res.render(`auth/${name}`, {
    layout: false,
    title,
    error: null,
    message: null,
    next: req.query.next || "",
  });

router.get("/signup", page("signup", "Sign up"));
router.post("/signup", perIp(5, 60 * 60 * 1000), async (req, res, next) => {
  const parsed = credentials.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).render("auth/signup", {
      layout: false,
      title: "Sign up",
      error: "Enter a valid email and a password of 10 to 128 characters.",
      message: null,
      next: "",
    });
  }
  try {
    const user = await auth.signup(parsed.data);
    if (!user) return res.redirect("/domains"); // same shape as success; the owner got a mail
    return establish(req, res, user, "/domains");
  } catch (err) {
    return next(err);
  }
});

router.get("/login", page("login", "Sign in"));
router.post(
  "/login",
  perIp(10, 15 * 60 * 1000),
  perEmail(10, 15 * 60 * 1000),
  async (req, res, next) => {
    const parsed = credentials.safeParse(req.body);
    const fail = () =>
      res.status(200).render("auth/login", {
        layout: false,
        title: "Sign in",
        error: GENERIC_LOGIN,
        message: null,
        next: req.body?.next || "",
      });
    if (!parsed.success) return fail();
    try {
      const user = await auth.login(parsed.data);
      if (!user) return fail();
      return establish(req, res, user, safeNext(parsed.data.next));
    } catch (err) {
      return next(err);
    }
  }
);

router.post("/logout", async (req, res, next) => {
  try {
    const session = await getSession(req, res);
    session.destroy();
    return res.redirect("/login");
  } catch (err) {
    return next(err);
  }
});

router.get("/forgot", page("forgot", "Forgot password"));
router.post("/forgot", perIp(5, 60 * 60 * 1000), validate(emailOnly), async (req, res, next) => {
  try {
    await auth.startReset(req.body.email);
    return res.render("auth/forgot", {
      layout: false,
      title: "Forgot password",
      error: null,
      message: GENERIC_FORGOT,
      next: "",
    });
  } catch (err) {
    return next(err);
  }
});

router.get("/reset/:token", (req, res) =>
  res.render("auth/reset", {
    layout: false,
    title: "Choose a new password",
    error: null,
    message: null,
    token: req.params.token,
  })
);
router.post("/reset/:token", async (req, res, next) => {
  const parsed = newPassword.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).render("auth/reset", {
      layout: false,
      title: "Choose a new password",
      error: "Password must be 10 to 128 characters.",
      message: null,
      token: req.params.token,
    });
  }
  try {
    const ok = await auth.completeReset({
      token: req.params.token,
      password: parsed.data.password,
    });
    if (!ok) {
      return res.status(400).render("auth/reset", {
        layout: false,
        title: "Choose a new password",
        error: "This link is no longer valid. Request a new one.",
        message: null,
        token: "",
      });
    }
    return res.redirect("/login");
  } catch (err) {
    return next(err);
  }
});

router.get("/verify/:token", async (req, res, next) => {
  try {
    const ok = await auth.completeVerify(req.params.token);
    if (!ok) {
      return res.status(400).render("auth/verify", {
        layout: false,
        title: "Verify email",
        error: "This link is no longer valid.",
        message: null,
      });
    }
    return res.redirect("/domains?verified=1");
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
