const path = require("path");
const { z } = require("zod");
require("dotenv").config({ path: path.resolve(__dirname, "../.env") });

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace"]).default("info"),

  MONGODB_URI: z.string().min(1, "MONGODB_URI is required"),
  BASE_URL: z.string().url(),
  SESSION_PASSWORD: z.string().min(32, "SESSION_PASSWORD must be at least 32 chars"),
  SESSION_COOKIE_NAME: z.string().min(1).default("tw_session"),

  PYTHON_BIN: z.string().default("python3"),
  ML_URL_MODEL: z.string().default("ml/models/url_classifier.pkl"),

  WATCH_INTERVAL_HOURS: z.coerce.number().positive().default(6),
  WATCH_CONCURRENCY: z.coerce.number().int().positive().default(3),
  MAX_DOMAINS_PER_ACCOUNT: z.coerce.number().int().positive().default(5),

  SMTP_URL: z.string().optional(),
  // Express "trust proxy": false (direct), "loopback" (nginx on the same host), a hop count, or a CIDR.
  TRUST_PROXY: z
    .string()
    .default("false")
    .transform((v) =>
      v === "true" ? true : v === "false" ? false : /^\d+$/.test(v) ? Number(v) : v
    ),
  LOG_FILE: z.string().optional(),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  console.error("Invalid environment configuration:");
  for (const issue of parsed.error.issues) {
    console.error(`  ${issue.path.join(".")}: ${issue.message}`);
  }
  process.exit(1);
}

const env = parsed.data;

module.exports = {
  env,
  isProd: env.NODE_ENV === "production",
  isTest: env.NODE_ENV === "test",
};
