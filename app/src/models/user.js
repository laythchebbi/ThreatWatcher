const { Schema, model } = require("mongoose");

/**
 * Account. Password hash is scrypt (services/password.js). `sessionVersion`
 * is embedded in every session cookie; bumping it revokes them all.
 */
const userSchema = new Schema(
  {
    email: { type: String, required: true, lowercase: true, trim: true, unique: true },
    passwordHash: { type: String, required: true },
    emailVerifiedAt: { type: Date, default: null },
    sessionVersion: { type: Number, default: 1 },
    verifyTokenHash: { type: String },
    verifyTokenExpiresAt: { type: Date },
    resetTokenHash: { type: String },
    resetTokenExpiresAt: { type: Date },
    timezone: { type: String, default: "UTC" },
  },
  { timestamps: true, collection: "users" }
);

module.exports = model("User", userSchema);
