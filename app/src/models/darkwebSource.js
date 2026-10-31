const { Schema, model } = require("mongoose");

/** Operator-seeded crawl targets (`npm run seed:sources`). */
const darkwebSourceSchema = new Schema(
  {
    url: { type: String, required: true, unique: true, trim: true },
    kind: { type: String, enum: ["onion", "forum", "other"], default: "onion" },
    title: { type: String, default: "" },
    enabled: { type: Boolean, default: true },
    lastCrawledAt: { type: Date },
    lastStatus: { type: String, enum: ["ok", "error", "unreachable"], default: "ok" },
  },
  { timestamps: true, collection: "darkweb_sources" }
);

module.exports = model("DarkwebSource", darkwebSourceSchema);
