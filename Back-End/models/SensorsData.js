import mongoose from 'mongoose';

const sensorsDataSchema = new mongoose.Schema({
  sensor_id: { type: String, maxlength: 50 },
  timestamp: { type: Date, default: Date.now },
  temperature: { type: Number },
  humidity: { type: Number },
  longitude: { type: Number },
  latitude: { type: Number },
  created_at: { type: Date, default: Date.now },
  hive_state: { type: String },
  battery_voltage: { type: Number },
  weight: { type: Number },
});

export const SensorsData = mongoose.model('SensorsData', sensorsDataSchema);
