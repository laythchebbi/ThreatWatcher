const { Schema, model } = require("mongoose");

const SEVERITIES = ["low", "medium", "high", "critical"];
const STATES = ["open", "dismissed", "ignored"];

/** One lookalike domain as currently known for one protected domain. */
const sightingSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    domainId: { type: Schema.Types.ObjectId, ref: "Domain", required: true },
    lookalike: { type: String, required: true, lowercase: true, trim: true },
    firstSeenAt: { type: Date, default: Date.now },
    lastSeenAt: { type: Date, default: Date.now },
    baseline: { type: Boolean, default: false },
    inactive: { type: Boolean, default: false },
    dnsMisses: { type: Number, default: 0 },
    dns: {
      resolves: { type: Boolean, default: false },
      a: [{ type: String }],
      mx: [{ type: String }],
      ns: [{ type: String }],
    },
    infra: {
      parked: { type: Boolean, default: false },
      cdn: { type: Boolean, default: false },
    },
    rdap: {
      registeredAt: Date,
      registrar: String,
      ns: [{ type: String }],
      defensive: { type: Boolean, default: false },
      fetchedAt: Date,
    },
    cert: {
      firstIssuedAt: Date,
      issuer: String,
      notBefore: Date,
      lastSeenAt: Date,
      tbs: String,
      fingerprint256: String,
      spki: String,
    },
    http: {
      status: Number,
      title: String,
      finalHost: String,
      redirects: [{ type: String }],
      headers: { type: Schema.Types.Mixed },
      hasPasswordForm: { type: Boolean, default: false },
      brandTermFound: { type: Boolean, default: false },
      similarity: Number,
      truncated: Boolean,
      fetchedAt: Date,
      error: String,
    },
    ml: { label: { type: Number, default: null }, score: { type: Number, default: null } },
    similarity: { type: Number, min: 0, max: 1 },
    punycode: { type: Boolean, default: false },
    substring: { type: Boolean, default: false },
    severity: { type: String, enum: SEVERITIES, default: "low" },
    state: { type: String, enum: STATES, default: "open" },
    dismissedAtSeverity: { type: String, enum: SEVERITIES },
  },
  { timestamps: true, collection: "sightings" }
);

sightingSchema.index({ domainId: 1, lookalike: 1 }, { unique: true });
sightingSchema.index({ userId: 1, state: 1 });

module.exports = model("Sighting", sightingSchema);
module.exports.SEVERITIES = SEVERITIES;
module.exports.STATES = STATES;
