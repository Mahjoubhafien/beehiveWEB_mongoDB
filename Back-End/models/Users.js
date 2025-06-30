import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  full_name: { type: String },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  phone_number: { type: String },
  current_sensor_id: { type: String, default: "Select Sensor" },  // default added here
  created_at: { type: Date, default: Date.now },
});

export const User = mongoose.model('User', userSchema);
