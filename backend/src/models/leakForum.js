const { Schema, model } = require("mongoose");

const leakForumSchema = new Schema(
  {
    forum: { type: String, required: true, index: true },
    // unique index declared explicitly below
    threadUrl: { type: String, required: true },
    author: { type: String, default: "" },
    title: { type: String, default: "" },
    body: { type: String, default: "" },
    keywords: [{ type: String, lowercase: true, trim: true, index: true }],
    postedAt: { type: Date, index: true },
  },
  { timestamps: true, collection: "dataleak_forums" }
);

leakForumSchema.index({ threadUrl: 1 }, { unique: true });
leakForumSchema.index({ title: "text", body: "text" });

module.exports = model("LeakForum", leakForumSchema);
