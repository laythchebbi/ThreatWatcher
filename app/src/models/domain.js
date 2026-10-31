const { Schema, model } = require("mongoose");

/** A protected domain. The scheduler claims rows by nextWatchAt / watchingSince. */
const domainSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    name: { type: String, required: true, lowercase: true, trim: true },
    terms: [{ type: String, trim: true }],
    lastWatchedAt: { type: Date },
    nextWatchAt: { type: Date, default: Date.now },
    watchingSince: { type: Date, default: null },
    lastPermutation: [{ type: String }],
    certCursor: { type: String, default: null },
    baselineDoneAt: { type: Date, default: null },
  },
  { timestamps: true, collection: "domains" }
);

domainSchema.index({ userId: 1, name: 1 }, { unique: true });
domainSchema.index({ nextWatchAt: 1 });

module.exports = model("Domain", domainSchema);
