const { Schema, model } = require("mongoose");

const leakTwitterSchema = new Schema(
  {
    handle: { type: String, required: true, index: true },
    // unique+sparse index declared explicitly below
    tweetId: { type: String },
    text: { type: String, default: "" },
    keywords: [{ type: String, lowercase: true, trim: true, index: true }],
    postedAt: { type: Date, index: true },
  },
  { timestamps: true, collection: "dataleak_twitter" }
);

leakTwitterSchema.index({ tweetId: 1 }, { unique: true, sparse: true });
leakTwitterSchema.index({ text: "text" });

module.exports = model("LeakTwitter", leakTwitterSchema);
