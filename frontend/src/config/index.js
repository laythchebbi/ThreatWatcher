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
};
