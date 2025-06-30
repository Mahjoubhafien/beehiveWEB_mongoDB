import mongoose from 'mongoose';

const beehiveSchema = new mongoose.Schema({
  user_id: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',  // This links user_id to the User collection
    required: true
  },
  timestamp: { type: Date, default: Date.now },
  hive_name: { type: String, required: true, maxlength: 50 },
  hive_location: { type: String, maxlength: 100 },
  hive_type: { type: String, maxlength: 50 },
  sensor_id: { type: String, required: true, unique: true, maxlength: 50 }, 
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now },
  image_url: { type: String, default: 'assets/img/beehive/bee1.png', maxlength: 255 },
  health_status: { type: String, default: 'No Data', required: true, maxlength: 50 }
});

// Optional: auto-update the updated_at on save
beehiveSchema.pre('save', function(next) {
  this.updated_at = Date.now();
  next();
});

export const Beehive = mongoose.model('Beehive', beehiveSchema);
