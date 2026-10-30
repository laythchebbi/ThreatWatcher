const { z } = require("zod");

const domainLabel = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;

const domainName = z
  .string()
  .trim()
  .toLowerCase()
  .min(3, "domain too short")
  .max(253, "domain too long")
  .refine((d) => {
    const labels = d.split(".");
    if (labels.length < 2) return false;
    return labels.every((label) => domainLabel.test(label));
  }, "invalid domain format");

const searchDomainParams = z.object({
  domain: domainName,
});

const dataleakQuery = z.object({
  q: z.string().trim().min(2, "query too short").max(200, "query too long"),
  source: z.enum(["telegram", "twitter", "forum", "darkweb", "all"]).default("all"),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});

module.exports = { domainName, searchDomainParams, dataleakQuery };
