const { Schema, model } = require("mongoose");

const leakTelegramSchema = new Schema(
  {
    channel: { type: String, required: true, index: true },
    messageId: { type: Number, index: true },
    text: { type: String, default: "" },
    keywords: [{ type: String, lowercase: true, trim: true, index: true }],
    postedAt: { type: Date, index: true },
  },
  { timestamps: true, collection: "dataleak_telegrams" }
);

leakTelegramSchema.index({ channel: 1, messageId: 1 }, { unique: true, sparse: true });
leakTelegramSchema.index({ text: "text" });

module.exports = model("LeakTelegram", leakTelegramSchema);
