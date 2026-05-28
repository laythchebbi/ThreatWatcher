const { Schema, model } = require("mongoose");

const registeredDomainSchema = new Schema(
  {
    domainName: { type: String, required: true, lowercase: true, trim: true, index: true },
    mainDomain: { type: String, required: true, lowercase: true, trim: true, index: true },
    similarity: { type: Number, min: 0, max: 1 },
    websimilarity: { type: Number, min: 0, max: 1 },
    webserver: { type: Boolean, default: false },
    substring: { type: Boolean, default: false },
    xn: { type: Boolean, default: false },
    links: { type: Number, default: 0 },
    dateOfScan: { type: Date, default: Date.now, index: true },
  },
  { timestamps: true, collection: "registered_domains" }
);

registeredDomainSchema.index({ mainDomain: 1, dateOfScan: -1 });

module.exports = model("RegisteredDomain", registeredDomainSchema);
