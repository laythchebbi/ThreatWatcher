const path = require("path");
const { z } = require("zod");
require("dotenv").config({ path: path.resolve(__dirname, "../../.env") });

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace"]).default("info"),

  MONGODB_URI: z.string().min(1, "MONGODB_URI is required"),
  INTERNAL_API_KEY: z.string().min(16, "INTERNAL_API_KEY must be at least 16 chars"),

  WORKOS_API_KEY: z.string().regex(/^sk_/, "WORKOS_API_KEY must start with sk_"),
  WORKOS_CLIENT_ID: z.string().regex(/^client_/, "WORKOS_CLIENT_ID must start with client_"),
  WORKOS_ORGANIZATION_ID: z.string().regex(/^org_/, "WORKOS_ORGANIZATION_ID must start with org_"),

  FRONTEND_ORIGIN: z.string().url().default("http://localhost:4000"),

  WHOISXML_API_KEY: z.string().optional().default(""),
  SLACK_BOT_TOKEN: z.string().optional().default(""),

  PYTHON_BIN: z.string().default("python"),
  ML_URL_MODEL: z.string().default("ml/models/url_classifier.pkl"),
  ML_CONTENT_MODEL: z.string().default("ml/models/content_classifier.pkl"),

  LOG_FILE: z.string().optional(),

  // Dev-only: run without WorkOS/MongoDB for a local trial. Never in prod.
  DEMO_MODE: z
    .string()
    .optional()
    .transform((v) => /^(1|true|yes|on)$/i.test(v || "")),
});

// In demo mode, fill placeholder values for the otherwise-required secrets so
// validation passes. None of these are used for real auth/DB when demo is on.
const raw = { ...process.env };
if (/^(1|true|yes|on)$/i.test(raw.DEMO_MODE || "")) {
  raw.MONGODB_URI ||= "mongodb://demo-disabled:27017/threatwatcher-demo";
  raw.INTERNAL_API_KEY ||= "demo-internal-key-unused-000000";
  raw.WORKOS_API_KEY ||= "sk_demo_placeholder_unused";
  raw.WORKOS_CLIENT_ID ||= "client_demo_placeholder";
  raw.WORKOS_ORGANIZATION_ID ||= "org_demo_placeholder";
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
  isTest: env.NODE_ENV === "test",
  isDemo: env.DEMO_MODE,
};
