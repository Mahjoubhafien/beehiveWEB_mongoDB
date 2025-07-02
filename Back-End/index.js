import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import cors from "cors";
import axios from "axios";
import multer from "multer";
import path from "path";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import bcrypt from "bcrypt";
import env from "dotenv";
import { SensorsData } from './models/SensorsData.js'; 
import { User } from './models/Users.js'; 
import { Beehive } from './models/Beehives.js'; 
import { SmsAlertSettings } from "./models/SmsAlertSettings.js";
import { AlertsHistory } from './models/AlertsHistory.js'; 

env.config();

const app = express();
const port = 5000;
//const saltRounds = 10;
//var currentSensorId = "Select Sensor";
//SMS Alerts Variables
var config = {
    MIN_TEMP: 32,
    MAX_TEMP: 36,
    MIN_HUMIDITY: 50,
    MAX_HUMIDITY: 70,
    MIN_WEIGHT: 10,
    MAX_WEIGHT: 100,
    isAlertsON: true
};


app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN, // Allow your React frontend
    credentials: true, // Allow cookies/session to work
  })
);

// db intialitation
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected");
  })
  .catch((err) => {
    console.error("MongoDB connection error", err);
  });
//session intialitation
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: false, // Set to true if using HTTPS
      httpOnly: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);
//Paspport intialisation
app.use(passport.initialize());
app.use(passport.session());

//Common Midalware init
app.use(express.json());
app.use(bodyParser.json());
app.use(express.static("public"));

///////////////////////////////// START Athentiction API /////////////////////////////////////////////////

// Passport Local Strategy
passport.use(
  new LocalStrategy(
    { usernameField: 'email' }, // tell passport that username is email
    async (username, password, done) => {
      console.log(username);
      console.log(password);
      try {
        const user = await User.findOne({ email: username });  // Mongoose query
        if (!user) {
          return done(null, false, {
            message: 'Incorrect username, Please Try Again',
          });
        }

        const isValid = await bcrypt.compare(password, user.password);
        console.log(isValid);

        if (!isValid) {
          return done(null, false, {
            message: 'Incorrect password, Please Try Again',
          });
        }

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);
// Passport Google Strategy
passport.use(
  'google',
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile);
        // Mongoose findOne by email
        let user = await User.findOne({ email: profile.email });

        if (!user) {
          // Create new user if not exists
          user = new User({
            full_name: profile.given_name + ' ' + profile.family_name,
            email: profile.email,
            password: 'google', // dummy password since Google OAuth
          });
          await user.save();
        }

        return cb(null, user);
      } catch (err) {
        return cb(err);
      }
    }
  )
);
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"], // this mean when the user logs in well tell them we try and grab hold of your public profile and your email.
  })
);
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: "/auth/sign-in",
  }),
  (req, res) => {
    // redirect to frontend home or dashboard after login
    res.redirect(process.env.FRONTEND_URL || "http://localhost:3000/admin/all-hives");
  }
);
// Serialization
passport.serializeUser((user, done) => {
  done(null, user._id); // use _id to store in session
});

passport.deserializeUser(async (id, done) => {
  try {
    // MongoDB _id field is usually a string or ObjectId
    const user = await User.findById(id).exec();
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Login
app.post("/api/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      return res.status(500).json({
        success: false,
        error: "Server error. Please try again later.",
      });
    }

    if (!user) {
      return res.status(401).json({
        success: false,
        error: info.message || "Authentication failed",
      });
    }

    req.logIn(user, (err) => {
      if (err) {
        return res.status(500).json({
          success: false,
          error: "Session error. Please try again.",
        });
      }

      console.log("Authenticated user ID:", user._id);

      return res.json({
        success: true,
        user: {
          user_id: user._id.toString(), // <-- change here to MongoDB _id as string
          email: user.email,
        },
      });
    });
  })(req, res, next);
});

app.post('/api/register', async (req, res) => {
  const { email, password, phone_number, full_name } = req.body;

  try {
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      full_name,
      email,
      password: hashedPassword,
      phone_number,
    });

    await newUser.save();

    req.login(newUser, (err) => {
      if (err) {
        return res.status(500).json({ message: 'Error logging in after registration' });
      }
      return res.json({
        success: true,
        user: {
          user_id: newUser._id.toString(),
          full_name: newUser.full_name,
          email: newUser.email,
          phone_number: newUser.phone_number,
        },
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Registration failed' });
  }
});

app.post("/api/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).json({
        success: false,
        error: "Logout failed",
      });
    }

    // Destroy the session completely
    req.session.destroy((err) => {
      if (err) {
        console.error("Session destruction error:", err);
        return res.status(500).json({
          success: false,
          error: "Could not destroy session",
        });
      }

      // Clear the cookie
      res.clearCookie("connect.sid"); // or whatever your session cookie name is
      return res.json({
        success: true,
        message: "Logged out successfully",
      });
    });
  });
});

///////////////////////////////// END Athentiction API /////////////////////////////////////////////////

// Configure storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/"); // Make sure this directory exists
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(
      null,
      file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname)
    );
  },
});
const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only image files are allowed!"), false);
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
});
// Upload endpoint
app.post("/admin/upload", upload.single("photo"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  // File uploaded successfully
  res.json({
    message: "File uploaded successfully",
    filePath: `/uploads/${req.file.filename}`,
    originalName: req.file.originalname,
  });
});
// Serve uploaded files statically
app.use("/uploads", express.static("uploads"));
/*
Getting sensor data
*/
app.post("/temphum", async (req, res) => {
  console.log("Received data from ESP32:", req.body);
  const { local_sensor, remote_sensor } = req.body;

  const sensors = [local_sensor, remote_sensor];

  try {
    // prepare documents to insert
    const documents = sensors.map(sensor => ({
      sensor_id: sensor.id,
      temperature: sensor.temperature,
      humidity: sensor.humidity,
      latitude: sensor.latitude,
      longitude: sensor.longitude,
      battery_voltage: sensor.battery_voltage || null,
      // other fields like hive_state and weight will remain undefined unless you fill them here
    }));

    // insert them all at once
    await SensorsData.insertMany(documents);

    res.status(200).send("Data received and stored successfully!");
  } catch (error) {
    console.error("Error inserting data into MongoDB:", error);
    res.status(500).send("Database insertion error");
  }
});
/*
Adding new hive to beehives table
*/
app.post('/admin/add-hive', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { hiveName, hiveLocation, sensorId, photoUrl } = req.body;

  if (!sensorId || sensorId.trim() === '') {
    return res.status(400).json({ error: 'Sensor ID cannot be empty' });
  }

  try {
    const userId = req.user._id; // MongoDB user id

    // Create new Beehive document
    const newHive = new Beehive({
      user_id: userId,
      hive_name: hiveName,
      hive_location: hiveLocation,
      hive_type: null, // as in your SQL
      sensor_id: sensorId,
      image_url: photoUrl,
    });

    await newHive.save();

    // Create a blank sensor data document linked to this sensor_id
    const blankSensorData = new SensorsData({
      sensor_id: sensorId,
      temperature: null,
      humidity: null,
      longitude: null,
      latitude: null,
      weight: null,
      // Add other fields if needed
    });

    await blankSensorData.save();

    res.status(201).json(newHive);
  } catch (err) {
    console.error('Error adding hive:', err);
    res.status(500).json({ error: 'Database error' });
  }
});
/*
getting hive list of specific user id
*/
app.get('/admin/getAllHives', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const userId = req.user._id; // MongoDB _id, NOT user_id from SQL
  console.log('user Authorized');
  console.log('user ID:', userId);

  try {
    const hives = await Beehive.aggregate([
  {
    $match: {
      user_id: req.user._id,
    }
  },
  {
    $lookup: {
      from: "sensorsdatas",  // your Mongo sensors collection
      localField: "sensor_id",
      foreignField: "sensor_id",
      as: "sensor_data"
    }
  },
  { $unwind: { path: "$sensor_data", preserveNullAndEmptyArrays: true } },
  { $sort: { "sensor_data.timestamp": -1 } },
  {
    $group: {
      _id: "$_id",  // group by hive
      hiveName: { $first: "$hive_name" },
      location: { $first: "$hive_location" },
      image_url: { $first: "$image_url" },
      sensor_id: { $first: "$sensor_id" },
      temperature: { $first: "$sensor_data.temperature" },
      humidity: { $first: "$sensor_data.humidity" },
      lastDataR: { $first: "$sensor_data.timestamp" },
      longitude: { $first: "$sensor_data.longitude" },
      latitude: { $first: "$sensor_data.latitude" },
      battery_voltage: { $first: "$sensor_data.battery_voltage" }
    }
  },
  {
  $sort: { sensor_id: 1 }  // 1 for ascending order, -1 for descending
},
  {
    $project: {
      _id: 0,
      id: "$sensor_id",
      hiveName: 1,
      location: 1,
      image_url: 1,
      temperature: 1,
      humidity: 1,
      lastDataR: 1,
      longitude: 1,
      latitude: 1,
      battery_voltage: 1
    }
  }
]);
    console.log('Complete hive data:', hives);
    res.status(200).json(hives);
  } catch (err) {
    console.error('Error fetching hive data:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});
/*
Get the triggered sensor id that press the more detail
*/
app.get("/admin/detailed-dashboard/:id", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  try {
    const userId = req.user._id;  // MongoDB user ID (_id)
    const currentSensorId = req.params.id;
    console.log("sensor Id: " + currentSensorId);

    // Update current_sensor_id in User collection
    await User.findByIdAndUpdate(userId, { current_sensor_id: currentSensorId });

    res.status(200).json({ message: "Current sensor ID updated successfully" });
  } catch (err) {
    console.error("Error updating current_sensor_id:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});
/*
Get all the daitailt of the cuurent sensor id
*/
app.get("/admin/getCurrentSensorData", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const currentSensorId = req.user.current_sensor_id;
  try {
    // Find all sensor data for currentSensorId sorted ascending by timestamp
    const data = await SensorsData.find({ sensor_id: currentSensorId })
                                  .sort({ timestamp: 1 }) // ascending
                                  .exec();

    console.log(currentSensorId + " data:", data);
    res.status(200).json(data);
  } catch (err) {
    console.error("Error fetching hive data:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});
app.get("/admin/sensor-ids", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  console.log("test get sensors ids");
  try {
    const userId = req.user._id; // MongoDB user ObjectId

    // Find all beehives for this user, return only sensor_id field
    const beehives = await Beehive.find({ user_id: userId }).select("sensor_id -_id").exec();

    // beehives is an array of objects like [{ sensor_id: "sensor-001" }, ...]
    res.json(beehives);
  } catch (err) {
    console.error("Error fetching sensor_ids:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});
//////////// Get All Hives location /////////
app.get("/admin/getHiveLocation", async (req, res) => {
  const { latitude, longitude } = req.query;

  if (!latitude || !longitude) {
    return res
      .status(400)
      .json({ error: "Latitude and longitude are required" });
  }

  try {
    const response = await axios.get(
      "https://nominatim.openstreetmap.org/reverse",
      {
        params: {
          lat: latitude,
          lon: longitude,
          format: "json",
          addressdetails: 1,
        },
        headers: {
          "User-Agent": "beehive/1.0 (mahjoubhafyen@gmail.com)", // Required by Nominatim
          "Accept-Language": "en", // Forces English response
        },
      }
    );

    const city =
      response.data.address?.city ||
      response.data.address?.town ||
      response.data.address?.village ||
      null;

      //console.log("city "+city);

    if (!city) {
      return res.status(404).json({ error: "City not found in location data" });
    }
    res.json({ city });
  } catch (error) {
    console.error("Error fetching location:", error.message);
    res.status(500).json({ error: "Failed to fetch location" });
  }
});
// api that update only sate in sensors_data table for the most recent one !!
app.post("/admin/insertState", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { healthStatus, id } = req.body;
  const userId = req.user._id; // using MongoDB _id

  try {
    const updatedBeehive = await Beehive.findOneAndUpdate(
      {
        user_id: userId,
        sensor_id: id
      },
      {
        health_status: healthStatus,
        updated_at: Date.now()
      },
      { new: true }
    );

    if (!updatedBeehive) {
      return res.status(404).json({
        error: "Beehive not found or not owned by user"
      });
    }

    res.status(200).json({
      success: true,
      message: "Beehive state updated",
      beehive: updatedBeehive
    });
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({
      error: "Database update failed",
      details:
        process.env.NODE_ENV === "development" ? err.message : undefined
    });
  }
});
app.get("/admin/current-sensor", (req, res) => {
    if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  const currentSensorId = req.user.current_sensor_id;
  res.json({ currentSensorId });
});
app.post("/admin/update-current-sensor", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const userId = req.user._id;  // MongoDB ObjectId from session
    const { id } = req.body;

    if (!id) {
      return res.status(400).json({ error: "Sensor ID is required" });
    }

    // Update current_sensor_id field in User document
    await User.findByIdAndUpdate(userId, { current_sensor_id: id });

    res.json({ message: "Current sensor ID updated", currentSensorId: id });
  } catch (error) {
    console.error("Failed to update current sensor ID:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
/////////// Edit Hive API ///////////
app.post("/admin/edit-hive", async (req, res) => {
  const { newHiveName, newSensorid, newHiveLocation, id: sensorId } = req.body;

  try {
    console.log("Received from frontend:");
    console.log("Name:", newHiveName);
    console.log("Sensor ID:", newSensorid);
    console.log("Location:", newHiveLocation);

    // Check if all fields are empty
    if (
      (!newSensorid || newSensorid.trim() === "") &&
      (!newHiveLocation || newHiveLocation.trim() === "") &&
      (!newHiveName || newHiveName.trim() === "")
    ) {
      return res.status(400).json({ message: "You changed nothing" });
    }

    // 1. Find the hive by current sensor_id
    const hive = await Beehive.findOne({ sensor_id: sensorId });
    if (!hive) {
      return res.status(404).json({ message: "Hive not found" });
    }

    console.log("Hive ID to update:", hive._id);

    // 2. Check if the new sensor_id already exists, ignoring the current hive
    if (newSensorid && newSensorid.trim() !== "") {
      const existingSensor = await Beehive.findOne({
        sensor_id: newSensorid.trim(),
        _id: { $ne: hive._id }  // exclude itself
      });
      if (existingSensor) {
        return res.status(400).json({ message: "Sensor ID already exists." });
      }
    }

    // 3. Prepare fields to update
    const updateFields = {};

    if (newHiveName && newHiveName.trim() !== "") {
      updateFields.hive_name = newHiveName.trim();
    }

    if (newHiveLocation && newHiveLocation.trim() !== "") {
      updateFields.hive_location = newHiveLocation.trim();
    }

    if (newSensorid && newSensorid.trim() !== "") {
      updateFields.sensor_id = newSensorid.trim();
    }

    updateFields.updated_at = new Date();  // keep your timestamp consistent

    // 4. Apply the update
    await Beehive.updateOne(
      { _id: hive._id },
      { $set: updateFields }
    );

    res.status(200).json({
      message: "Hive updated successfully",
      updatedFields: Object.keys(updateFields),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});
//SMS Alerts API 
// === POST API to update config from React frontend ===
app.post('/api/alert-config', (req, res) => {
    const { MIN_TEMP, MAX_TEMP, MIN_HUMIDITY, MAX_HUMIDITY, isAlertsON } = req.body;

    // Update if values are provided
    if (typeof MIN_TEMP === 'number') config.MIN_TEMP = MIN_TEMP;
    if (typeof MAX_TEMP === 'number') config.MAX_TEMP = MAX_TEMP;
    if (typeof MIN_HUMIDITY === 'number') config.MIN_HUMIDITY = MIN_HUMIDITY;
    if (typeof MAX_HUMIDITY === 'number') config.MAX_HUMIDITY = MAX_HUMIDITY;
    if (typeof isAlertsON === 'boolean') config.isAlertsON = isAlertsON;

    res.json({ message: 'Alert config updated successfully', config });
});

// === public api for sim800c ===
app.get("/api/public_alert-config", async (req, res) => {
  const { user_id } = req.query;

  if (!user_id) {
    return res.status(400).json({ error: "Missing user_id in query" });
  }

  // Validate and convert user_id to ObjectId
  let userObjectId;
  try {
    userObjectId = new mongoose.Types.ObjectId(user_id);
  } catch (err) {
    return res.status(400).json({ error: "Invalid user_id format" });
  }

  try {
    const settings = await SmsAlertSettings.findOne({ user_id: userObjectId });

    if (!settings) {
      return res.status(200).json({
        MIN_TEMP: 32,
        MAX_TEMP: 36,
        MIN_HUMIDITY: 50,
        MAX_HUMIDITY: 70,
        MIN_WEIGHT: 10,
        MAX_WEIGHT: 100,
        isAlertsON: false,
        REFERENCE_LATITUDE: null,
        REFERENCE_LONGITUDE: null
      });
    }

    return res.status(200).json({
      MIN_TEMP: settings.min_temp,
      MAX_TEMP: settings.max_temp,
      MIN_HUMIDITY: settings.min_humidity,
      MAX_HUMIDITY: settings.max_humidity,
      MIN_WEIGHT: settings.min_weight,
      MAX_WEIGHT: settings.max_weight,
      isAlertsON: settings.is_alerts_on,
      REFERENCE_LATITUDE: settings.latitude,
      REFERENCE_LONGITUDE: settings.longitude
    });
  } catch (error) {
    console.error("Error fetching alert config:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});
//get sensor data from sim800c 
app.get('/api/public_get_sensor_data', async (req, res) => {
  const { user_id, sensor_id } = req.query;

  if (!user_id || !sensor_id) {
    return res.status(400).json({ error: 'Missing user_id or sensor_id' });
  }

  let userObjectId;
  try {
    userObjectId = new mongoose.Types.ObjectId(user_id);
  } catch {
    return res.status(400).json({ error: 'Invalid user_id format' });
  }

  try {
    // Step 1: find the beehive that belongs to user and has the sensor_id
    const hive = await Beehive.findOne({ user_id: userObjectId, sensor_id: sensor_id });
    if (!hive) {
      return res.status(404).json({ error: 'Sensor not found for this user' });
    }

    // Step 2: find latest sensor data for this sensor_id
    const sensorData = await SensorsData.findOne({ sensor_id: sensor_id })
      .sort({ created_at: -1 })  // descending by created_at
      .lean();

    if (!sensorData) {
      return res.status(404).json({ error: 'No sensor data found' });
    }

    res.json(sensorData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Database error' });
  }
});
// === GET SMS Alerts Configuration From database ===
app.get("/api/sms-alert-settings", async (req, res) => {
  // Assuming you have a session/auth middleware setting req.user
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const userId = req.user._id;

    // Convert to ObjectId if needed
    let userObjectId;
    try {
      userObjectId = new mongoose.Types.ObjectId(userId);
    } catch {
      return res.status(400).json({ error: "Invalid user_id format" });
    }

    const settings = await SmsAlertSettings.findOne({ user_id: userObjectId });

    if (!settings) {
      // Return defaults if not found
      return res.status(200).json({
        MIN_TEMP: 32,
        MAX_TEMP: 36,
        MIN_HUMIDITY: 50,
        MAX_HUMIDITY: 70,
        MIN_WEIGHT: 10,
        MAX_WEIGHT: 100,
        isAlertsON: false,
        REFERENCE_LATITUDE: 35.5024,
        REFERENCE_LONGITUDE: 11.0457,
      });
    }

    return res.status(200).json({
      MIN_TEMP: settings.min_temp,
      MAX_TEMP: settings.max_temp,
      MIN_HUMIDITY: settings.min_humidity,
      MAX_HUMIDITY: settings.max_humidity,
      MIN_WEIGHT: settings.min_weight,
      MAX_WEIGHT: settings.max_weight,
      isAlertsON: settings.is_alerts_on,
      REFERENCE_LATITUDE: settings.latitude,
      REFERENCE_LONGITUDE: settings.longitude,
    });
  } catch (error) {
    console.error("Error fetching SMS alert settings:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
// udate the alers sms setting in the db 
app.post("/api/update_alert-config", async (req, res) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const userId = req.user._id;

    // Validate userId format
    let userObjectId;
    try {
      userObjectId = new mongoose.Types.ObjectId(userId);
    } catch {
      return res.status(400).json({ error: "Invalid user_id format" });
    }

    const {
      MIN_TEMP,
      MAX_TEMP,
      MIN_HUMIDITY,
      MAX_HUMIDITY,
      MIN_WEIGHT,
      MAX_WEIGHT,
      isAlertsON,
      REFERENCE_LATITUDE,
      REFERENCE_LONGITUDE,
    } = req.body;

    // Upsert (insert if not exists, else update)
    await SmsAlertSettings.findOneAndUpdate(
      { user_id: userObjectId },
      {
        min_temp: MIN_TEMP,
        max_temp: MAX_TEMP,
        min_humidity: MIN_HUMIDITY,
        max_humidity: MAX_HUMIDITY,
        min_weight: MIN_WEIGHT,
        max_weight: MAX_WEIGHT,
        is_alerts_on: isAlertsON,
        latitude: REFERENCE_LATITUDE,
        longitude: REFERENCE_LONGITUDE,
        updated_at: new Date(),
      },
      { upsert: true, new: true }
    );

    res.status(200).json({ message: "Alert settings saved successfully" });
  } catch (error) {
    console.error("Error saving alert settings:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
// Delete Hive API
app.delete("/api/delete-hive", async (req, res) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const sensorId = req.user.current_sensor_id;
  if (!sensorId) {
    return res.status(400).json({ error: "No current sensor selected" });
  }

  try {
    // Sequential deletes without transaction/session
    await SensorsData.deleteMany({ sensor_id: sensorId });
    await Beehive.deleteOne({ sensor_id: sensorId });
    await User.updateMany(
      { current_sensor_id: sensorId },
      { $unset: { current_sensor_id: "" } }
    );

    res.status(200).json({ message: `Hive and related data for sensor '${sensorId}' deleted.` });
  } catch (error) {
    console.error("Error deleting hive:", error);
    res.status(500).json({ error: "Failed to delete hive" });
  }
});
//////////////////////////////// Alerts History APIS ///////////////////////////
// Get Alerts history API 
app.get('/api/alerts-history', async (req, res) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const userId = req.user._id;
 // console.log("req.user:", req.user);
//console.log("req.user.user_id:", req.user.user_id);
//console.log("Is valid ObjectId?", mongoose.Types.ObjectId.isValid(req.user.user_id));

  // Validate userId ObjectId format
  let userObjectId;
  try {
    userObjectId = new mongoose.Types.ObjectId(userId);
  } catch {
    return res.status(400).json({ error: "Invalid user_id format" });
  }

  try {
    const alerts = await AlertsHistory.find({ user_id: userObjectId })
      .sort({ date: -1 })
      .exec();

    res.json(alerts);
  } catch (err) {
    console.error('Error fetching alerts_history:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/api/alerts-history', async (req, res) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const userId = req.user._id;
  const { alert_type, status, sensor_id } = req.body;

  if (!alert_type || !status || !sensor_id) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  // Validate userId ObjectId format
  let userObjectId;
  try {
    userObjectId = new mongoose.Types.ObjectId(userId);
  } catch {
    return res.status(400).json({ error: "Invalid user_id format" });
  }

  try {
    const newAlert = new AlertsHistory({
      user_id: userObjectId,
      alert_type,
      status,
      sensor_id,
      date: new Date(), // optional, defaults in schema
    });

    const savedAlert = await newAlert.save();

    res.status(201).json(savedAlert);
  } catch (err) {
    console.error('Error inserting alert:', err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
// heath status counts api 
app.get('/api/health-status-count', async (req, res) => {
  if (!req.isAuthenticated || !req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const userId = req.user._id;  // note: from the session with MongoDB auth

  try {
    const result = await Beehive.aggregate([
      {
        $match: {
          user_id: userId
        }
      },
      {
        $group: {
          _id: "$health_status",
          count: { $sum: 1 }
        }
      },
      {
        $project: {
          health_status: "$_id",
          count: 1,
          _id: 0
        }
      },
      {
        $sort: { health_status: 1 }
      }
    ]);

    res.json(result); // same format your frontend expects
  } catch (error) {
    console.error("Error fetching health status counts:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
app.get("/api/healthy-hives-week", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const userId = req.user._id;

  try {
    // aggregation
    const pipeline = [
      {
        $match: {
          user_id: userId,
          health_status: "Healthy",
          updated_at: {
            $gte: new Date(new Date().setDate(new Date().getDate() - 6))  // 6 days ago
          }
        }
      },
      {
        $group: {
          _id: {
            day: { $dateToString: { format: "%Y-%m-%d", date: "$updated_at" } }
          },
          healthy_count: { $sum: 1 }
        }
      },
      {
        $sort: { "_id.day": 1 }
      },
      {
        $project: {
          day: "$_id.day",
          healthy_count: 1,
          _id: 0
        }
      }
    ];

    const result = await Beehive.aggregate(pipeline);

    res.json(result);
  } catch (err) {
    console.error("Error fetching healthy hive counts", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${port}`);
});
