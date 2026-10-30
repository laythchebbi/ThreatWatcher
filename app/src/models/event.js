const { Schema, model } = require("mongoose");
const { SEVERITIES } = require("./sighting");

/** A change to a sighting or mention. Alerts are sent for events, never for sightings. */
const eventSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    domainId: { type: Schema.Types.ObjectId, ref: "Domain", required: true },
    sightingId: { type: Schema.Types.ObjectId, ref: "Sighting" },
    mentionId: { type: Schema.Types.ObjectId },
    kind: { type: String, required: true },
    severity: { type: String, enum: SEVERITIES, required: true },
    at: { type: Date, required: true, default: Date.now },
    payload: { type: Schema.Types.Mixed },
    alertedAt: { type: Date },
  },
  { collection: "events" }
);

eventSchema.index({ userId: 1, at: -1 });
eventSchema.index({ domainId: 1, at: -1 });
eventSchema.index({ alertedAt: 1 }, { sparse: true });

module.exports = model("Event", eventSchema);
