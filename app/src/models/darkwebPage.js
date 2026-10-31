const { Schema, model } = require("mongoose");

/** A page the Tor crawler fetched. Pages expire after 90 days (unbounded growth otherwise). */
const darkwebPageSchema = new Schema(
  {
    sourceUrl: { type: String, required: true, index: true },
    pageUrl: { type: String, required: true },
    title: { type: String, default: "" },
    body: { type: String, default: "" },
    bodyHash: { type: String, index: true },
    crawledAt: { type: Date, default: Date.now },
  },
  { timestamps: true, collection: "darkweb_pages" }
);

darkwebPageSchema.index({ sourceUrl: 1, pageUrl: 1 }, { unique: true });
darkwebPageSchema.index({ crawledAt: 1 }, { expireAfterSeconds: 90 * 24 * 3600 });

module.exports = model("DarkwebPage", darkwebPageSchema);
