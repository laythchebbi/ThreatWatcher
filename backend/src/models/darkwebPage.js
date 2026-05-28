const { Schema, model } = require("mongoose");

const darkwebPageSchema = new Schema(
  {
    sourceUrl: { type: String, required: true, index: true },
    pageUrl: { type: String, required: true, index: true },
    title: { type: String, default: "" },
    body: { type: String, default: "" },
    bodyHash: { type: String, index: true },
    keywords: [{ type: String, lowercase: true, trim: true }],
    crawledAt: { type: Date, default: Date.now, index: true },
  },
  { timestamps: true, collection: "darkweb_pages" }
);

darkwebPageSchema.index({ sourceUrl: 1, pageUrl: 1 }, { unique: true });
darkwebPageSchema.index({ keywords: 1 });

module.exports = model("DarkwebPage", darkwebPageSchema);
