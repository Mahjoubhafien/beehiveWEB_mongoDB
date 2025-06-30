import mongoose from "mongoose";

const smsAlertSettingsSchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId, // MongoDB will link to the User collection
    required: true,
    ref: "User"
  },
  min_temp: { type: Number, required: true },
  max_temp: { type: Number, required: true },
  min_humidity: { type: Number, required: true },
  max_humidity: { type: Number, required: true },
  min_weight: { type: Number, required: true },
  max_weight: { type: Number, required: true },
  is_alerts_on: { type: Boolean, default: false },
  updated_at: { type: Date, default: Date.now },
  latitude: { type: Number },
  longitude: { type: Number }
});

export const SmsAlertSettings = mongoose.model(
  "SmsAlertSettings",
  smsAlertSettingsSchema
);
