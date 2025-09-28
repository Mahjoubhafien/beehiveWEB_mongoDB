import mongoose from "mongoose";

const alertsHistorySchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User", // link to User collection
  },
  alert_type: { type: String, required: true, maxlength: 50 },
  status: { type: String, required: true, maxlength: 255 },
  sensor_id: { type: String, maxlength: 50 },
  date: { type: Date, default: Date.now },
});

export const AlertsHistory = mongoose.model(
  "AlertsHistory",
  alertsHistorySchema
);
