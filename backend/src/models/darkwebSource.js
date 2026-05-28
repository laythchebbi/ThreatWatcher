const { Schema, model } = require("mongoose");

const darkwebSourceSchema = new Schema(
  {
    url: { type: String, required: true, unique: true, trim: true },
    kind: {
      type: String,
      enum: ["onion", "forum", "telegram", "twitter", "other"],
      default: "onion",
    },
    title: { type: String, default: "" },
    enabled: { type: Boolean, default: true },
    lastCrawledAt: { type: Date },
    lastStatus: { type: String, enum: ["ok", "error", "unreachable"], default: "ok" },
  },
  { timestamps: true, collection: "darkweb_sources" }
);

module.exports = model("DarkwebSource", darkwebSourceSchema);
