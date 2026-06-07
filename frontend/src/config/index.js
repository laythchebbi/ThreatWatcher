const path = require("path");
const { z } = require("zod");
require("dotenv").config({ path: path.resolve(__dirname, "../../.env") });

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(4000),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace"]).default("info"),

  BACKEND_URL: z.string().url(),
  BACKEND_REQUEST_TIMEOUT_MS: z.coerce.number().int().positive().default(10_000),

  FRONTEND_BASE_URL: z.string().url(),

  WORKOS_API_KEY: z.string().regex(/^sk_/, "WORKOS_API_KEY must start with sk_"),
  WORKOS_CLIENT_ID: z.string().regex(/^client_/, "WORKOS_CLIENT_ID must start with client_"),
  WORKOS_REDIRECT_URI: z.string().url(),

  SESSION_COOKIE_NAME: z.string().min(1).default("tw_session"),
  SESSION_PASSWORD: z.string().min(32, "SESSION_PASSWORD must be at least 32 chars"),
  SESSION_COOKIE_SECURE: z
    .union([z.literal("true"), z.literal("false")])
    .transform((v) => v === "true")
    .default("false"),

  LOG_FILE: z.string().optional(),

  // Dev-only: explore the UI without WorkOS. Never in prod.
  DEMO_MODE: z
    .string()
    .optional()
    .transform((v) => /^(1|true|yes|on)$/i.test(v || "")),
});

// In demo mode, fill placeholders for the otherwise-required WorkOS/session
// secrets so validation passes. None are used (auth is bypassed in demo).
const raw = { ...process.env };
if (/^(1|true|yes|on)$/i.test(raw.DEMO_MODE || "")) {
  raw.WORKOS_API_KEY ||= "sk_demo_placeholder_unused";
  raw.WORKOS_CLIENT_ID ||= "client_demo_placeholder";
  raw.WORKOS_REDIRECT_URI ||= "http://localhost:4000/auth/callback";
  raw.SESSION_PASSWORD ||= "demo-session-password-unused-0123456789ab";
}

const parsed = schema.safeParse(raw);
if (!parsed.success) {
  console.error("Invalid environment configuration:");
  for (const issue of parsed.error.issues) {
    console.error(`  ${issue.path.join(".")}: ${issue.message}`);
  }
  process.exit(1);
}

const env = parsed.data;

if (env.DEMO_MODE && env.NODE_ENV === "production") {
  console.error("DEMO_MODE must never be enabled with NODE_ENV=production. Refusing to start.");
  process.exit(1);
}

module.exports = {
  env,
  isProd: env.NODE_ENV === "production",
  isDev: env.NODE_ENV === "development",
  isDemo: env.DEMO_MODE,
};
