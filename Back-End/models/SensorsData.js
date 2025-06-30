import mongoose from 'mongoose';

const sensorsDataSchema = new mongoose.Schema({
  sensor_id: { type: String, maxlength: 50 },
  timestamp: { type: Date, default: Date.now },
  temperature: { 
    type: mongoose.Decimal128,
    get: v => v != null ? parseFloat(v.toString()) : null,
  },
  humidity: { 
    type: mongoose.Decimal128,
    get: v => v != null ? parseFloat(v.toString()) : null,
  },
  longitude: { 
    type: mongoose.Decimal128,
    get: v => v != null ? parseFloat(v.toString()) : null,
  },
  latitude: { 
    type: mongoose.Decimal128,
    get: v => v != null ? parseFloat(v.toString()) : null,
  },
  created_at: { type: Date, default: Date.now },
  hive_state: { type: String },
  battery_voltage: { type: Number },
  weight: { type: Number },
},
{
  toJSON: { getters: true },     // <-- enable getters when calling toJSON()
  toObject: { getters: true },   // <-- enable getters when calling toObject()
});

export const SensorsData = mongoose.model('SensorsData', sensorsDataSchema);
