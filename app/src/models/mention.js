const { Schema, model } = require("mongoose");
const { SEVERITIES } = require("./sighting");

/** One leak source item that mentions a protected domain's terms (spec 7.3). */
const mentionSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    domainId: { type: Schema.Types.ObjectId, ref: "Domain", required: true },
    source: { type: String, enum: ["darkweb", "hibp"], required: true },
    sourceRef: { type: String, required: true },
    excerpt: { type: String, default: "" },
    excerptHash: { type: String, required: true },
    matchedTerms: [{ type: String }],
    severity: { type: String, enum: SEVERITIES, default: "medium" },
    firstSeenAt: { type: Date, default: Date.now },
    lastSeenAt: { type: Date, default: Date.now },
    state: { type: String, enum: ["open", "dismissed"], default: "open" },
    dismissedAtSeverity: { type: String, enum: SEVERITIES },
  },
  { timestamps: true, collection: "mentions" }
);

mentionSchema.index({ domainId: 1, sourceRef: 1 }, { unique: true });
mentionSchema.index({ userId: 1, firstSeenAt: -1 });

module.exports = model("Mention", mentionSchema);
