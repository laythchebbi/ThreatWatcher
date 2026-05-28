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
  isDev: env.NODE_ENV === "development",
  isTest: env.NODE_ENV === "test",
};
