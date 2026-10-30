const { z } = require("zod");

const domainLabel = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;

/** Registrable hostname: lowercase, trimmed, trailing dot removed, 3–253 chars, 2+ labels. */
const domainName = z
  .string()
  .trim()
  .toLowerCase()
  .transform((d) => d.replace(/\.$/, ""))
  .pipe(
    z
      .string()
      .min(3, "domain too short")
      .max(253, "domain too long")
      .refine((d) => {
        const labels = d.split(".");
        return labels.length >= 2 && labels.every((l) => domainLabel.test(l));
      }, "invalid domain format")
  );

const domainBody = z.object({ name: domainName });

module.exports = { domainName, domainBody };
