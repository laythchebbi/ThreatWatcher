const { Schema, model } = require("mongoose");

/**
 * Local user record. The canonical identity lives in WorkOS — this row is
 * upserted on every successful sign-in (see middleware/auth.js) and stores
 * app-specific fields that don't belong in WorkOS (monitored domains,
 * preferences, audit columns).
 */
const userSchema = new Schema(
  {
    workosUserId: { type: String, required: true, unique: true, index: true },
    email: { type: String, required: true, lowercase: true, trim: true, index: true },
    displayName: { type: String, default: "" },
    role: { type: String, enum: ["analyst", "admin"], default: "analyst", index: true },
    monitoredDomains: [{ type: String, lowercase: true, trim: true }],
    lastLoginAt: { type: Date },
    invitedBy: { type: Schema.Types.ObjectId, ref: "User" },
    deactivatedAt: { type: Date, default: null, index: true },
  },
  { timestamps: true, collection: "users" }
);

module.exports = model("User", userSchema);
