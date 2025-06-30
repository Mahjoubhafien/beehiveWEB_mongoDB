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
import { SensorsData } from './models/SensorsData.js'; // adjust the path accordingly
import { User } from './models/Users.js'; // adjust the path accordingly
import { Beehive } from './models/Beehives.js'; // adjust the path accordingly

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

  const insertQuery = `
    INSERT INTO sensors_data (sensor_id, temperature, humidity, latitude, longitude, battery_voltage)
    VALUES ($1, $2, $3, $4, $5, $6)
  `;

  try {
    for (const sensor of sensors) {
      const values = [
        sensor.id,
        sensor.temperature,
        sensor.humidity,
        sensor.latitude,
        sensor.longitude,
        sensor.battery_voltage || null  // fallback if voltage is missing
      ];

      await db.query(insertQuery, values);
    }

    res.status(200).send("Data received and stored successfully!");
  } catch (error) {
    console.error("Error inserting data into PostgreSQL:", error);
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

    // 1. First, get the hive_id from the sensor_id
    const getHiveIdQuery = "SELECT hive_id FROM beehives WHERE sensor_id = $1";
    const getHiveIdValues = [sensorId];
    const result = await db.query(getHiveIdQuery, getHiveIdValues);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Hive not found" });
    }

    const hiveId = result.rows[0].hive_id;
    console.log("Hive ID to update:", hiveId);

    // 2. If newSensorid is provided and not empty, check if it already exists
    if (newSensorid && newSensorid.trim() !== "") {
      const sensorIdResponse = await axios.get(
        `${process.env.REACT_APP_API_URL}/admin/sensor-ids`
      );
      const sensorIds = sensorIdResponse.data; // array of { sensor_id: value }

      const exists = sensorIds.some(
        (obj) => obj.sensor_id === newSensorid.trim()
      );
      if (exists) {
        return res.status(400).json({ message: "Sensor ID already exists." });
      }
      // If it doesn't exist, allow the update (continue)
    }

    // 3. Build the dynamic UPDATE query
    let updateParts = [];
    let updateValues = [];

    if (newHiveName && newHiveName.trim() !== "") {
      updateParts.push(`hive_name = $${updateValues.length + 1}`);
      updateValues.push(newHiveName.trim());
    }

    if (newHiveLocation && newHiveLocation.trim() !== "") {
      updateParts.push(`hive_location = $${updateValues.length + 1}`);
      updateValues.push(newHiveLocation.trim());
    }

    if (newSensorid && newSensorid.trim() !== "") {
      updateParts.push(`sensor_id = $${updateValues.length + 1}`);
      updateValues.push(newSensorid.trim());
    }

    // Add hive_id to the WHERE clause
    updateValues.push(hiveId);

    const updateQuery = `
      UPDATE beehives
      SET ${updateParts.join(", ")}
      WHERE hive_id = $${updateValues.length}
    `;

    await db.query(updateQuery, updateValues);

    res.status(200).json({
      message: "Hive updated successfully",
      updatedFields: updateParts.map((part) => part.split(" = ")[0]),
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

  try {
    const result = await db.query(
      'SELECT * FROM sms_alert_settings WHERE user_id = $1',
      [user_id]
    );

    if (result.rows.length === 0) {
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

    const row = result.rows[0];

    return res.status(200).json({
      MIN_TEMP: row.min_temp,
      MAX_TEMP: row.max_temp,
      MIN_HUMIDITY: row.min_humidity,
      MAX_HUMIDITY: row.max_humidity,
      MIN_WEIGHT: row.min_weight,
      MAX_WEIGHT: row.max_weight,
      isAlertsON: row.is_alerts_on,
      REFERENCE_LATITUDE: row.latitude,
      REFERENCE_LONGITUDE: row.longitude
    });
  } catch (error) {
    console.error("Error fetching alert config:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
//get sensor data from sim800c 
app.get('/api/public_get_sensor_data', async (req, res) => {
  const { user_id, sensor_id } = req.query;

  const query = `
SELECT sd.*
FROM beehives b
JOIN users u ON u.user_id = b.user_id
JOIN sensors_data sd ON sd.sensor_id = b.sensor_id
WHERE u.user_id = $1
  AND b.sensor_id = $2
ORDER BY sd.created_at DESC
LIMIT 1;
  `;

  try {
    const result = await db.query(query, [user_id, sensor_id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Sensor not found for this user' });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Database error' });
  }
});
// === GET SMS Alerts Configuration From database ===
app.get("/api/sms-alert-settings", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const userId = req.user.user_id;

    const result = await db.query(
      'SELECT * FROM sms_alert_settings WHERE user_id = $1',
      [userId]
    );

    if (result.rows.length === 0) {
      // No settings found — return defaults
      return res.status(200).json({
        MIN_TEMP: 32,
        MAX_TEMP: 36,
        MIN_HUMIDITY: 50,
        MAX_HUMIDITY: 70,
        MIN_WEIGHT: 10,
        MAX_WEIGHT: 100,
        isAlertsON: false,
        REFERENCE_LATITUDE: 35.5024,
        REFERENCE_LONGITUDE: 11.0457
      });
    }

    // Return first row of user-specific settings
    const row = result.rows[0];

    return res.status(200).json({
      MIN_TEMP: row.min_temp,
      MAX_TEMP: row.max_temp,
      MIN_HUMIDITY: row.min_humidity,
      MAX_HUMIDITY: row.max_humidity,
      MIN_WEIGHT: row.min_weight,
      MAX_WEIGHT: row.max_weight,
      isAlertsON: row.is_alerts_on,
      REFERENCE_LATITUDE: row.latitude,
      REFERENCE_LONGITUDE: row.longitude

    });
  } catch (error) {
    console.error("Error fetching SMS alert settings:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
// udate the alers sms setting in the db 
app.post("/api/update_alert-config", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const userId = req.user.user_id;

    const {
      MIN_TEMP,
  MAX_TEMP,
  MIN_HUMIDITY,
  MAX_HUMIDITY,
  MIN_WEIGHT,
  MAX_WEIGHT,
  isAlertsON,
  REFERENCE_LATITUDE,
  REFERENCE_LONGITUDE
    } = req.body;

    await db.query(
  `
  INSERT INTO sms_alert_settings 
    (user_id, min_temp, max_temp, min_humidity, max_humidity, min_weight, max_weight, is_alerts_on, latitude, longitude)
  VALUES 
    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
  ON CONFLICT (user_id) 
  DO UPDATE SET 
    min_temp = EXCLUDED.min_temp,
    max_temp = EXCLUDED.max_temp,
    min_humidity = EXCLUDED.min_humidity,
    max_humidity = EXCLUDED.max_humidity,
    min_weight = EXCLUDED.min_weight,
    max_weight = EXCLUDED.max_weight,
    is_alerts_on = EXCLUDED.is_alerts_on,
    latitude = EXCLUDED.latitude,
    longitude = EXCLUDED.longitude
  `,
  [
    userId,
    MIN_TEMP,
    MAX_TEMP,
    MIN_HUMIDITY,
    MAX_HUMIDITY,
    MIN_WEIGHT,
    MAX_WEIGHT,
    isAlertsON,
    REFERENCE_LATITUDE,
    REFERENCE_LONGITUDE
  ]
);

    res.status(200).json({ message: "Alert settings saved successfully" });
  } catch (error) {
    console.error("Error saving alert settings:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
// Delete Hive API
app.delete("/api/delete-hive", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const sensorId = req.user.current_sensor_id;

  if (!sensorId) {
    return res.status(400).json({ error: "No current sensor selected" });
  }

  try {
    // Begin transaction
    await db.query("BEGIN");

    // Delete all data related to the sensor in sensors_data
    await db.query("DELETE FROM sensors_data WHERE sensor_id = $1", [sensorId]);

    // Delete the hive from beehives table
    await db.query("DELETE FROM beehives WHERE sensor_id = $1", [sensorId]);

    // Optionally, also unset current_sensor_id from the user
    await db.query(
      "UPDATE users SET current_sensor_id = NULL WHERE current_sensor_id = $1",
      [sensorId]
    );

    // Commit transaction
    await db.query("COMMIT");

    res.status(200).json({ message: `Hive and related data for sensor '${sensorId}' deleted.` });
  } catch (error) {
    await db.query("ROLLBACK");
    console.error("Error deleting hive:", error);
    res.status(500).json({ error: "Failed to delete hive" });
  }
});

//////////////////////////////// Alerts History APIS ///////////////////////////
// Get Alerts history API 
app.get('/api/alerts-history', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const userId = req.user.user_id; // the logged-in user ID from the session

  try {
    const result = await db.query(
      'SELECT * FROM alerts_history WHERE user_id = $1 ORDER BY date DESC',
      [userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching alerts_history:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
// insert Alerts history API 
app.post('/api/alerts-history', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const { alert_type, status, sensor_id } = req.body;
    const userId = req.user.user_id; // from passport session
if (!alert_type || !status || !sensor_id) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const result = await db.query(
      `INSERT INTO alerts_history (user_id, alert_type, status, sensor_id)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [userId, alert_type, status, sensor_id]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error inserting alert:', err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
// heath status counts api 
app.get('/api/health-status-count', async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const userId = req.user.user_id;

  try {
    const result = await db.query(
      `
      SELECT health_status, COUNT(*) AS count
      FROM beehives
      WHERE user_id = $1
      GROUP BY health_status
      ORDER BY health_status;
      `,
      [userId]
    );

    // Return rows like [{ health_status: "Healthy", count: 5 }, ...]
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching health status counts:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});
app.get("/api/healthy-hives-week", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const userId = req.user.user_id;

  try {
    const result = await db.query(
      `
      SELECT
        to_char(updated_at::date, 'YYYY-MM-DD') as day,
        COUNT(*) as healthy_count
      FROM beehives
      WHERE user_id = $1
        AND health_status = 'Healthy'
        AND updated_at >= CURRENT_DATE - INTERVAL '6 days'
      GROUP BY day
      ORDER BY day ASC;
      `,
      [userId]
    );

    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching weekly healthy counts", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.listen(port, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${port}`);
});
