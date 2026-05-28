const { Schema, model } = require("mongoose");

const reportSchema = new Schema(
  {
    domain: { type: String, required: true, lowercase: true, trim: true, index: true },
    secureScore: { type: Number, min: 0, max: 1 },
    confidence: { type: Number, min: 0, max: 1, default: 0.9 },
    findings: {
      lookalikes: { type: Number, default: 0 },
      maliciousUrls: { type: Number, default: 0 },
      contentMatches: { type: Number, default: 0 },
      darkWebHits: { type: Number, default: 0 },
      dataLeaks: { type: Number, default: 0 },
    },
    reportContent: { type: Schema.Types.Mixed },
    createdBy: { type: Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true, collection: "reports" }
);

reportSchema.index({ domain: 1, createdAt: -1 });

module.exports = model("Report", reportSchema);
